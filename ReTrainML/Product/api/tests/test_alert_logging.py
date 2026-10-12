"""Alert audit regressions; run with python -m unittest discover -s tests -v."""
import asyncio
import copy
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi import FastAPI

from app import config, main
from app.alert_logging import AlertLogMiddleware, AlertLogWriter
from app.errors import InvalidAlertError, UnknownModelVersionError, UnknownTenantError


class FakeClassifier:
    def predict_one(self, alert):
        if alert.get("outcome") == "invalid":
            raise InvalidAlertError("Không đủ trường quan trọng để dự đoán.")
        if alert.get("outcome") == "crash":
            raise RuntimeError("PRIVATE_MODEL_ERROR")
        return {"rate": alert.get("rate", 0.9821)}


class FakeRegistry:
    def get(self, tenant, version):
        if tenant != "vnd":
            raise UnknownTenantError(f"Tenant '{tenant}' không tồn tại.")
        if version != "v1.0":
            raise UnknownModelVersionError(f"Tenant '{tenant}' không có phiên bản model '{version}'.")
        return FakeClassifier()


def envelope(alert_id="A001", tenant="vnd", version="v1.0", **features):
    return {
        "id": alert_id,
        "raw_data": {"tenant": tenant, "model_version": version},
        "events": [{"Computer": "host", "EventID": "4624", **features}],
    }


OK_BODY = {"_id": "A001", "tenant": "vnd", "model_version": "v1.0", "rate": 0.9821}


def field(line, name):
    prefix = name + "="
    return next(part[len(prefix):] for part in line.split(" | ") if part.startswith(prefix))


class AlertLogTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.log_path = Path(self.temp.name) / "nested" / "alerts.log"
        self.app = FastAPI()
        self.app.include_router(main.app.router)
        self.app.exception_handlers.update(main.app.exception_handlers)
        self.app.add_middleware(AlertLogMiddleware, log_path=self.log_path)
        self.registry_patch = patch("app.main.get_registry", return_value=FakeRegistry())
        self.registry_patch.start()

    def tearDown(self):
        middleware = self.app.middleware_stack
        while middleware is not None:
            if isinstance(middleware, AlertLogMiddleware):
                middleware.writer.close()
            middleware = getattr(middleware, "app", None)
        self.registry_patch.stop()
        self.temp.cleanup()

    async def request(self, path="/predict", payload=None, *, raw=None, method="POST", on_receive=None):
        body = raw if raw is not None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        scope = {
            "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1", "method": method, "scheme": "http",
            "path": path, "raw_path": path.encode("ascii"), "query_string": b"",
            "root_path": "", "headers": [(b"content-type", b"application/json")],
            "client": ("127.0.0.1", 12345), "server": ("test", 80),
        }
        messages = []
        received = False

        async def receive():
            nonlocal received
            if received:
                return {"type": "http.disconnect"}
            received = True
            if on_receive is not None:
                on_receive()
            await asyncio.sleep(0)
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            messages.append(copy.deepcopy(message))

        error = None
        try:
            await self.app(scope, receive, send)
        except Exception as exc:
            # Starlette sends the 500 response and re-raises unexpected errors.
            error = exc
        starts = [m for m in messages if m["type"] == "http.response.start"]
        self.assertEqual(len(starts), 1, messages)
        response_body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
        status = starts[0]["status"]
        if error is not None and status != 500:
            raise error
        return status, response_body, error

    def lines(self):
        return self.log_path.read_text(encoding="utf-8").splitlines()

    async def test_success_keeps_response_and_uses_receipt_time_before_body(self):
        received_at = datetime(2026, 9, 10, 10, 0, 1, tzinfo=timezone(timedelta(hours=7)))
        finished_at = received_at + timedelta(minutes=5)
        with patch("app.alert_logging.now_vietnam", side_effect=[received_at, finished_at]) as clock:
            status, body, error = await self.request(payload=envelope(), on_receive=lambda: self.assertTrue(clock.called))
        self.assertIsNone(error)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), OK_BODY)
        line, = self.lines()
        self.assertTrue(line.startswith('"10:00:01 10/09/2026" | '), line)
        self.assertNotIn("received_at=", line)
        self.assertNotIn("10:05:01", line)
        self.assertRegex(field(line, "req"), r"^[0-9a-f]{32}$")
        self.assertIn(" | /predict | alert_id=A001 | tenant=vnd | model_version=v1.0 | http=200 | SUCCESS | rate=0.982100", line)

    async def test_structural_errors_include_id_and_exact_api_detail(self):
        cases = [
            {"id": "missing_raw"},
            {"id": "missing_tenant", "raw_data": {"other": "value"}},
            {"id": "empty_tenant", "raw_data": {"tenant": " "}},
            {"id": "missing_events", "raw_data": {"tenant": "vnd"}},
            {"id": "empty_events", "raw_data": {"tenant": "vnd"}, "events": []},
            {"id": "wrong_events", "raw_data": {"tenant": "vnd"}, "events": [42]},
            {"id": "missing_version", "raw_data": {"tenant": "vnd"}, "events": [{"Computer": "host"}]},
            {"id": "empty_version", "raw_data": {"tenant": "vnd", "model_version": " "}, "events": [{"Computer": "host"}]},
            {"id": "number_version", "raw_data": {"tenant": "vnd", "model_version": 1.0}, "events": [{"Computer": "host"}]},
            {"id": "path_version", "raw_data": {"tenant": "vnd", "model_version": "../v1.0"}, "events": [{"Computer": "host"}]},
            {"id": "dots_version", "raw_data": {"tenant": "vnd", "model_version": "v1..0"}, "events": [{"Computer": "host"}]},
        ]
        for payload in cases:
            with self.subTest(alert_id=payload["id"]):
                status, body, error = await self.request(payload=payload)
                self.assertIsNone(error)
                self.assertEqual(status, 422)
                response = json.loads(body)
                self.assertEqual(response["error_code"], "INVALID_STRUCTURE")
                line = self.lines()[-1]
                self.assertEqual(field(line, "alert_id"), payload["id"])
                self.assertIn(" | http=422 | INVALID_STRUCTURE | ", line)
                self.assertIn(response["detail"], line)
        self.assertEqual(len(self.lines()), len(cases))

    async def test_single_business_errors_log_actual_status(self):
        for payload, expected_status, code in [
            (envelope("unknown", "abc"), 404, "UNKNOWN_TENANT"),
            (envelope("old_version", version="v9.9"), 404, "UNKNOWN_MODEL_VERSION"),
            (envelope("invalid", outcome="invalid"), 422, "INVALID_ALERT"),
        ]:
            with self.subTest(code=code):
                status, body, error = await self.request(payload=payload)
                self.assertIsNone(error)
                self.assertEqual(status, expected_status)
                self.assertEqual(json.loads(body)["error_code"], code)
                self.assertIn(f" | http={expected_status} | {code} | ", self.lines()[-1])

    async def test_missing_id_and_tenant_use_placeholder(self):
        payload = envelope()
        payload.pop("id")
        status, body, _ = await self.request(payload=payload)
        self.assertEqual(status, 200)
        self.assertIsNone(json.loads(body)["_id"])
        self.assertIn(" | alert_id=- | tenant=vnd | ", self.lines()[-1])
        await self.request(payload={"id": "no_tenant"})
        self.assertIn(" | alert_id=no_tenant | tenant=- | ", self.lines()[-1])

    async def test_mixed_batch_keeps_order_one_time_and_request_id(self):
        payload = [envelope("success"), envelope("invalid", outcome="invalid"), envelope("unknown", "abc"),
                   envelope("old_version", version="v0.9"), {"id": "missing"}]
        status, body, error = await self.request("/predict/batch", payload)
        self.assertIsNone(error)
        self.assertEqual(status, 200)
        results = json.loads(body)
        self.assertEqual([r["_id"] for r in results], [p["id"] for p in payload])
        self.assertEqual(results[0], {"_id": "success", "tenant": "vnd", "model_version": "v1.0", "rate": 0.9821})
        codes = ["INVALID_ALERT", "UNKNOWN_TENANT", "UNKNOWN_MODEL_VERSION", "INVALID_STRUCTURE"]
        self.assertEqual([r["error_code"] for r in results[1:]], codes)
        lines = self.lines()
        self.assertEqual(len(lines), 5)
        self.assertEqual(len({line.split(" | ")[0] for line in lines}), 1)
        self.assertEqual(len({field(line, "req") for line in lines}), 1)
        self.assertEqual(field(lines[3], "model_version"), "v0.9")
        for index, code in enumerate(["SUCCESS"] + codes, 1):
            self.assertIn(f" | /predict/batch | item={index} | alert_id={payload[index - 1]['id']} | ", lines[index - 1])
            self.assertIn(f" | http=200 | {code} | ", lines[index - 1])

    async def test_malformed_json_and_missing_body_do_not_leak_payload(self):
        status, _, error = await self.request(raw=b'{"content": "PRIVATE_INPUT", "id":')
        self.assertIsNone(error)
        self.assertEqual(status, 422)
        self.assertIn(" | alert_id=- | tenant=- | model_version=- | http=422 | JSON_INVALID | ", self.lines()[-1])
        self.assertNotIn("PRIVATE_INPUT", self.lines()[-1])
        status, _, _ = await self.request(raw=b"")
        self.assertEqual(status, 422)
        self.assertIn(" | http=422 | REQUEST_VALIDATION_ERROR | ", self.lines()[-1])

    async def test_framework_rejection_marks_whole_batch_unprocessed(self):
        status, body, error = await self.request("/predict/batch", [envelope("never_run"), 42])
        self.assertIsNone(error)
        self.assertEqual(status, 422)
        self.assertIn("detail", json.loads(body))
        lines = self.lines()
        self.assertEqual(len(lines), 2)
        self.assertIn(" | item=1 | alert_id=never_run | ", lines[0])
        self.assertIn(" | item=2 | alert_id=- | ", lines[1])
        for line in lines:
            self.assertIn(" | http=422 | REQUEST_VALIDATION_ERROR | ", line)
            self.assertNotIn("SUCCESS", line)

    async def test_empty_and_wrong_batch_container(self):
        status, _, _ = await self.request("/predict/batch", [])
        self.assertEqual(status, 422)
        self.assertIn(" | http=422 | INVALID_STRUCTURE | ", self.lines()[-1])
        status, _, _ = await self.request("/predict/batch", {"id": "not_a_batch"})
        self.assertEqual(status, 422)
        self.assertIn(" | http=422 | REQUEST_VALIDATION_ERROR | ", self.lines()[-1])
        self.assertEqual(len(self.lines()), 2)

    async def test_unexpected_single_error_is_logged_without_exception_secrets(self):
        status, body, error = await self.request(payload=envelope("crashed", outcome="crash"))
        self.assertEqual(status, 500)
        self.assertIsInstance(error, RuntimeError)
        self.assertEqual(body, b"Internal Server Error")
        line, = self.lines()
        self.assertIn(" | alert_id=crashed | tenant=vnd | model_version=v1.0 | http=500 | INTERNAL_ERROR | ", line)
        self.assertNotIn("PRIVATE_MODEL_ERROR", line)

    async def test_unexpected_batch_error_never_logs_unreturned_success(self):
        payload = [envelope("first"), envelope("bad", outcome="invalid"), envelope("crashed", outcome="crash"), envelope("pending")]
        status, _, error = await self.request("/predict/batch", payload)
        self.assertEqual(status, 500)
        self.assertIsInstance(error, RuntimeError)
        lines = self.lines()
        self.assertEqual(len(lines), 4)
        for index, expected in enumerate(["REQUEST_FAILED", "REQUEST_FAILED", "INTERNAL_ERROR", "NOT_PROCESSED"]):
            self.assertEqual(field(lines[index], "alert_id"), payload[index]["id"])
            self.assertIn(f" | http=500 | {expected} | ", lines[index])
            self.assertNotIn("SUCCESS", lines[index])
            self.assertNotIn("PRIVATE_MODEL_ERROR", lines[index])

    async def test_configured_keys_and_case_insensitive_identity(self):
        with patch.object(config, "RAW_DATA_KEY", "metadata"), patch.object(config, "TENANT_KEY", "customer"), \
                patch.object(config, "EVENTS_KEY", "records"), patch.object(config, "MODEL_VERSION_KEY", "modelVersion"):
            payload = {" _ID ": "es-document-id", "metadata": {" CUSTOMER ": " vnd ", " MODELVERSION ": " v1.0 "},
                       "records": [{"Computer": "host"}]}
            status, body, error = await self.request(payload=payload)
        self.assertIsNone(error)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["_id"], "es-document-id")
        self.assertEqual(json.loads(body)["model_version"], "v1.0")
        self.assertIn(" | alert_id=es-document-id | tenant=vnd | model_version=v1.0 | http=200 | SUCCESS | ", self.lines()[-1])

    async def test_untrusted_strings_cannot_inject_records_or_fields(self):
        malicious_id = "es\\id\r\nFORGED | http=200\t\x1b\u2028tail"
        malicious_tenant = "bad\n | SUCCESS\r\t"
        payload = envelope(malicious_id, malicious_tenant)
        payload["content"] = "PRIVATE_CONTENT"
        payload["events"][0]["secret"] = "PRIVATE_EVENT"
        status, body, error = await self.request(payload=payload)
        self.assertIsNone(error)
        self.assertEqual(status, 404)
        self.assertIn(malicious_tenant.strip(), json.loads(body)["detail"])
        lines = self.lines()
        self.assertEqual(len(lines), 1, lines)
        self.assertEqual(len(lines[0].split(" | ")), 9)
        for secret in ["PRIVATE_CONTENT", "PRIVATE_EVENT"]:
            self.assertNotIn(secret, lines[0])
        for control in ["\r", "\n", "\t", "\x1b", "\u2028"]:
            self.assertNotIn(control, lines[0])
        self.assertIn(" | http=404 | UNKNOWN_TENANT | ", lines[0])

    async def test_compound_identity_values_never_leak_into_log_details(self):
        for path, tenant in [("/predict", {"secret": "PRIVATE_TENANT_OBJECT"}), ("/predict/batch", ["PRIVATE_TENANT_LIST"])]:
            with self.subTest(path=path):
                alert = envelope({"secret": "PRIVATE_ID_OBJECT"}, tenant)
                payload = [alert] if path.endswith("batch") else alert
                status, body, error = await self.request(path, payload)
                self.assertIsNone(error)
                self.assertEqual(status, 200 if path.endswith("batch") else 404)
                result = json.loads(body)
                result = result[0] if isinstance(result, list) else result
                self.assertEqual(result["error_code"], "UNKNOWN_TENANT")
                self.assertIn("PRIVATE_TENANT_", result["detail"])
                line = self.lines()[-1]
                self.assertIn(" | alert_id=- | tenant=- | ", line)
                self.assertNotIn("PRIVATE_TENANT_", line)
                self.assertNotIn("PRIVATE_ID_OBJECT", line)

    async def test_large_invalid_batch_has_bounded_validation_details(self):
        status, _, error = await self.request("/predict/batch", [42] * 30)
        self.assertIsNone(error)
        self.assertEqual(status, 422)
        lines = self.lines()
        self.assertEqual(len(lines), 30)
        for line in lines:
            self.assertLess(len(line), 1000)
            self.assertIn(" | http=422 | REQUEST_VALIDATION_ERROR | ", line)

    async def test_concurrent_requests_keep_ids_and_results_isolated(self):
        replies = await asyncio.gather(*(
            self.request(payload=envelope(f"parallel-{i}", rate=i / 10)) for i in range(8)
        ))
        self.assertTrue(all(status == 200 and error is None for status, _, error in replies))
        lines = self.lines()
        self.assertEqual(len(lines), 8)
        self.assertEqual(len({field(line, "req") for line in lines}), 8)
        by_id = {field(line, "alert_id"): line for line in lines}
        for i in range(8):
            self.assertIn(f" | SUCCESS | rate={i / 10:.6f}", by_id[f"parallel-{i}"])

    async def test_documentation_requests_do_not_create_alert_entries(self):
        status, _, error = await self.request("/openapi.json", method="GET", raw=b"")
        self.assertIsNone(error)
        self.assertEqual(status, 200)
        self.assertTrue(not self.log_path.exists() or self.log_path.read_text(encoding="utf-8") == "")

    async def test_writer_failure_does_not_change_api_response(self):
        with patch.object(AlertLogWriter, "write", side_effect=OSError("disk unavailable")):
            with self.assertLogs("uvicorn.error", level="ERROR"):
                status, body, error = await self.request(payload=envelope())
        self.assertIsNone(error)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), OK_BODY)


class AlertLogWriterTests(unittest.TestCase):
    def test_utf8_rotation_keeps_only_configured_backups(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "alerts.log"
            writer = AlertLogWriter(path, max_bytes=120, backup_count=2)
            try:
                self.assertFalse(writer.logger.propagate)
                for i in range(12):
                    writer.write(f"{i:02d} | Thiếu trường tenant. " + "x" * 60)
            finally:
                writer.close()
            self.assertEqual({p.name for p in path.parent.iterdir()}, {"alerts.log", "alerts.log.1", "alerts.log.2"})
            self.assertIn("11 | Thiếu trường tenant.", path.read_text(encoding="utf-8"))
            for rotated in path.parent.iterdir():
                self.assertIn("Thiếu trường tenant.", rotated.read_text(encoding="utf-8"))

    def test_unwritable_destination_falls_back_to_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            stderr = io.StringIO()
            with patch("sys.stderr", stderr):
                # Opening an existing directory as the log file fails on every OS.
                writer = AlertLogWriter(Path(directory), max_bytes=120, backup_count=2)
                try:
                    writer.write("audit record survives unavailable file")
                finally:
                    writer.close()
            self.assertIn("audit record survives unavailable file", stderr.getvalue())

    def test_rotation_failure_preserves_record_on_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            stderr = io.StringIO()
            with patch("sys.stderr", stderr):
                writer = AlertLogWriter(Path(directory) / "alerts.log", max_bytes=1, backup_count=2)
                try:
                    with patch.object(writer.handler, "doRollover", side_effect=OSError("disk unavailable")):
                        writer.write("audit record survives failed rotation")
                finally:
                    writer.close()
            self.assertIn("audit record survives failed rotation", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
