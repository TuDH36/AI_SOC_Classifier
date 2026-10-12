"""Kho model theo (tenant, version), registry và FieldMapper. Không cần MinIO/model thật."""
import hashlib
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from minio.datatypes import Object
from minio.error import S3Error

from app import tenant_registry
from app.errors import (ModelIntegrityError, ModelStoreUnavailableError, UnknownModelVersionError,
                        UnknownTenantError)
from app.field_mapping import FieldMapper
from app.model_store import REQUIRED_ARTIFACTS, LocalStore, MinioStore
from app.tenant_registry import ModelRegistry


def make_version_files(tenant="VND", version="v1.0", **manifest_over):
    """Bộ file giả của 1 version: {tên file: bytes} kèm manifest có checksum đúng."""
    files = {name: f"{tenant}-{version}-{name}".encode() for name in REQUIRED_ARTIFACTS}
    manifest = {
        "tenant": tenant, "model_version": version, "text_cols": ["events.command"],
        "artifacts": [{"file": n, "sha256": hashlib.sha256(b).hexdigest(), "size_bytes": len(b)} for n, b in files.items()],
    }
    manifest.update(manifest_over)
    files["manifest.json"] = json.dumps(manifest).encode()
    return files


def write_tree(root, tenant, version, files):
    path = os.path.join(root, "tenants", tenant, "versions", version)
    os.makedirs(path, exist_ok=True)
    for name, data in files.items():
        with open(os.path.join(path, name), "wb") as f:
            f.write(data)
    return path


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)


class LocalStoreTests(TempDirCase):
    def test_fetch_lists_and_verifies(self):
        path = write_tree(self.root, "VND", "v1.0", make_version_files())
        write_tree(self.root, "ABC", "v2.0", make_version_files("ABC", "v2.0"))
        store = LocalStore(self.root, "tenants")
        self.assertEqual(store.list_tenants(), ["ABC", "VND"])
        self.assertEqual(store.fetch("VND", "v1.0"), path)

    def test_unknown_version(self):
        write_tree(self.root, "VND", "v1.0", make_version_files())
        with self.assertRaises(UnknownModelVersionError):
            LocalStore(self.root, "tenants").fetch("VND", "v1.1")

    def test_tampered_or_mismatched_artifacts_are_rejected(self):
        cases = {
            "checksum": lambda f: f.update({"lgbm_clf.pkl": b"tampered"}),
            "missing_file": lambda f: f.pop("tfidf_word.pkl"),
            "wrong_version": lambda f: f.update({"manifest.json": make_version_files(version="v9")["manifest.json"]}),
            "wrong_tenant": lambda f: f.update({"manifest.json": make_version_files(tenant="ABC")["manifest.json"]}),
            "no_checksums": lambda f: f.update({"manifest.json": json.dumps({"model_version": "v1.0"}).encode()}),
        }
        for name, mutate in cases.items():
            with self.subTest(case=name):
                root = os.path.join(self.root, name)
                files = make_version_files()
                mutate(files)
                write_tree(root, "VND", "v1.0", files)
                with self.assertRaises(ModelIntegrityError):
                    LocalStore(root, "tenants").fetch("VND", "v1.0")


def s3_error(code):
    return S3Error(MagicMock(), code, code, "/x", "req", "host")


class FakeMinio:
    """Giả lập client minio: objects = {key: bytes}."""

    def __init__(self, objects, fail=False):
        self.objects = dict(objects)
        self.fail = fail
        self.downloads = []

    def list_objects(self, bucket, prefix, recursive):
        if self.fail:
            raise OSError("connection refused")
        names = sorted({k[len(prefix):].split("/")[0] for k in self.objects if k.startswith(prefix)})
        return [Object(bucket, f"{prefix}{n}/") for n in names]

    def fget_object(self, bucket, key, file_path):
        if self.fail:
            raise OSError("connection refused")
        if key not in self.objects:
            raise s3_error("NoSuchKey")
        self.downloads.append(key)
        with open(file_path, "wb") as f:
            f.write(self.objects[key])


def minio_objects(tenant="VND", version="v1.0", files=None):
    files = files or make_version_files(tenant, version)
    return {f"tenants/{tenant}/versions/{version}/{n}": b for n, b in files.items()}


class MinioStoreTests(TempDirCase):
    def store(self, client):
        return MinioStore(client, "soar-models", "tenants", os.path.join(self.root, "cache"))

    def test_download_verify_then_reuse_cache(self):
        client = FakeMinio(minio_objects())
        store = self.store(client)
        path = store.fetch("VND", "v1.0")
        self.assertEqual(path, os.path.join(self.root, "cache", "VND", "v1.0"))
        self.assertEqual(len(client.downloads), 5)
        self.assertEqual(store.fetch("VND", "v1.0"), path)
        self.assertEqual(len(client.downloads), 5)  # lần 2 dùng cache, không tải lại
        self.assertEqual(os.listdir(os.path.join(self.root, "cache", "VND")), ["v1.0"])  # không còn thư mục tạm

    def test_corrupted_cache_is_downloaded_again(self):
        client = FakeMinio(minio_objects())
        store = self.store(client)
        path = store.fetch("VND", "v1.0")
        with open(os.path.join(path, "lgbm_clf.pkl"), "wb") as f:
            f.write(b"broken")
        store.fetch("VND", "v1.0")
        self.assertEqual(len(client.downloads), 10)

    def test_missing_manifest_is_unknown_version_and_bad_checksum_never_cached(self):
        store = self.store(FakeMinio(minio_objects()))
        with self.assertRaises(UnknownModelVersionError):
            store.fetch("VND", "v2.0")
        files = make_version_files()
        files["cat_encoder.pkl"] = b"tampered"
        store = self.store(FakeMinio(minio_objects(files=files)))
        with self.assertRaises(ModelIntegrityError):
            store.fetch("VND", "v1.0")
        self.assertFalse(os.path.exists(os.path.join(self.root, "cache", "VND", "v1.0")))
        self.assertEqual(os.listdir(os.path.join(self.root, "cache", "VND")), [])

    def test_unavailable_store_uses_cache_when_possible(self):
        client = FakeMinio({**minio_objects(), **minio_objects("ABC", "v1.0")})
        store = self.store(client)
        self.assertEqual(store.list_tenants(), ["ABC", "VND"])
        store.fetch("VND", "v1.0")
        client.fail = True
        self.assertEqual(store.list_tenants(), ["VND"])  # chỉ còn tenant đã có cache
        store.fetch("VND", "v1.0")  # bản cache vẫn phục vụ được
        with self.assertRaises(ModelStoreUnavailableError) as ctx:
            store.fetch("VND", "v1.1")
        self.assertTrue(ctx.exception.to_body()["retryable"])
        empty_cache = MinioStore(FakeMinio({}, fail=True), "soar-models", "tenants", os.path.join(self.root, "empty"))
        with self.assertRaises(ModelStoreUnavailableError):
            empty_cache.list_tenants()  # không có cache -> 503


class FakeStore:
    def __init__(self, tenants, versions=("v1.0",)):
        self.tenants = list(tenants)
        self.versions = set(versions)
        self.list_calls = 0
        self.fetch_calls = []
        self.fail_list = False

    def list_tenants(self):
        self.list_calls += 1
        if self.fail_list:
            raise ModelStoreUnavailableError("down")
        return self.tenants

    def fetch(self, tenant, version):
        self.fetch_calls.append((tenant, version))
        if version not in self.versions:
            raise UnknownModelVersionError("no version")
        time.sleep(0.05)
        return f"/models/{tenant}/{version}"


class FakeModel:
    def __init__(self, tenant, path):
        self.tenant, self.path = tenant, path


class ModelRegistryTests(unittest.TestCase):
    def test_tenant_is_case_insensitive_and_canonical(self):
        store = FakeStore(["VND"])
        reg = ModelRegistry(store, loader=FakeModel)
        model = reg.get(" vnd ", "v1.0")
        self.assertEqual((model.tenant, model.path), ("VND", "/models/VND/v1.0"))
        self.assertIs(reg.get("VND", "v1.0"), model)
        self.assertEqual(store.fetch_calls, [("VND", "v1.0")])

    def test_unknown_tenant_and_version(self):
        reg = ModelRegistry(FakeStore(["VND"]), loader=FakeModel)
        with self.assertRaises(UnknownTenantError):
            reg.get("abc", "v1.0")
        with self.assertRaises(UnknownTenantError):
            reg.get(" ", "v1.0")
        with self.assertRaises(UnknownModelVersionError):
            reg.get("vnd", "v2.0")

    def test_concurrent_requests_load_each_version_once(self):
        store = FakeStore(["VND"], versions=("v1.0", "v1.1"))
        reg = ModelRegistry(store, loader=FakeModel)
        results = []
        threads = [threading.Thread(target=lambda v=v: results.append(reg.get("vnd", v)))
                   for v in ["v1.0", "v1.1"] * 8]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(store.fetch_calls), [("VND", "v1.0"), ("VND", "v1.1")])
        self.assertEqual(len({id(m) for m in results}), 2)

    def test_lru_eviction(self):
        store = FakeStore(["VND", "ABC"], versions=("v1", "v2"))
        reg = ModelRegistry(store, loader=FakeModel, max_loaded=2)
        a = reg.get("vnd", "v1")
        reg.get("vnd", "v2")
        reg.get("vnd", "v1")  # dùng lại v1 -> v2 thành cũ nhất
        reg.get("abc", "v1")
        self.assertEqual(reg.loaded_models(), [("VND", "v1"), ("ABC", "v1")])
        self.assertIs(reg.get("vnd", "v1"), a)

    def test_loader_failure_becomes_integrity_error(self):
        def broken_loader(tenant, path):
            raise ValueError("manifest thiếu text_cols")
        reg = ModelRegistry(FakeStore(["VND"]), loader=broken_loader)
        with self.assertRaises(ModelIntegrityError):
            reg.get("vnd", "v1.0")

    def test_tenant_list_refresh_and_outage(self):
        store = FakeStore(["VND"])
        reg = ModelRegistry(store, loader=FakeModel, tenant_ttl=60)
        reg.get("vnd", "v1.0")
        store.tenants = ["VND", "ABC"]
        with patch.object(tenant_registry, "_MIN_REFRESH_SECONDS", 0):
            reg.get("abc", "v1.0")  # tenant mới -> liệt kê lại ngay, không chờ hết TTL
        store.fail_list = True
        reg.tenant_ttl = 0
        reg.get("vnd", "v1.0")  # store lỗi -> dùng danh sách tenant cũ
        with self.assertRaises(ModelStoreUnavailableError):
            ModelRegistry(store, loader=FakeModel).get("vnd", "v1.0")  # chưa từng liệt kê được -> 503


class FieldMapperTests(unittest.TestCase):
    COLS = ["events.processname", "events.process_name", "events.sourcetype", "events._sourcetype", "events.src_ip"]

    def test_event_keys_without_prefix_map_to_exact_column(self):
        mapper = FieldMapper(self.COLS)
        self.assertEqual(mapper.resolve("process_name"), "events.process_name")
        self.assertEqual(mapper.resolve("ProcessName"), "events.processname")
        self.assertEqual(mapper.resolve("_sourcetype"), "events._sourcetype")
        self.assertEqual(mapper.resolve("sourcetype"), "events.sourcetype")
        self.assertEqual(mapper.resolve("Src IP"), "events.src_ip")  # vẫn nhận tên "xấu"

    def test_placeholder_never_overwrites_real_value(self):
        mapper = FieldMapper(self.COLS)
        mapped, _ = mapper.map_payload({"src_ip": "10.0.0.1", "Src IP": "-"})
        self.assertEqual(mapped["events.src_ip"], "10.0.0.1")
        mapped, _ = mapper.map_payload({"src_ip": "-", "Src IP": "10.0.0.2"})
        self.assertEqual(mapped["events.src_ip"], "10.0.0.2")


if __name__ == "__main__":
    unittest.main()
