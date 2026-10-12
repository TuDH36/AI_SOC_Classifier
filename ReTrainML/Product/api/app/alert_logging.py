"""Ghi kết quả từng alert, giữ thời gian nhận request theo giờ Việt Nam."""
import logging
import os
import sys
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from typing import Any, List, Optional

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from . import config
from .validation import find_alert_id


VIETNAM_TIMEZONE = timezone(timedelta(hours=7))


def now_vietnam() -> datetime:
    return datetime.now(VIETNAM_TIMEZONE)


def _safe_text(value: Any) -> str:
    """Escape dấu phân cách và ký tự điều khiển; không ghi object đầu vào."""
    if value is None or not isinstance(value, (str, int, float, bool)):
        return "-"
    result = []
    for char in str(value):
        if char == "\\":
            result.append("\\\\")
        elif char == "|":
            result.append("\\u007c")
        elif char == "\n":
            result.append("\\n")
        elif char == "\r":
            result.append("\\r")
        elif char == "\t":
            result.append("\\t")
        elif unicodedata.category(char).startswith("C") or char in "\u2028\u2029":
            result.append("\\u%04x" % ord(char))
        else:
            result.append(char)
    return "".join(result) or "-"


def _raw_data_value_for_log(payload: Any, field_key: str) -> Any:
    """Giá trị raw_data.<field_key> (tenant/version) để ghi log; object/list -> None."""
    if not isinstance(payload, dict):
        return None
    raw_data = payload.get(config.RAW_DATA_KEY)
    if isinstance(raw_data, dict):
        for key, value in raw_data.items():
            if str(key).strip().lower() == field_key.lower():
                if isinstance(value, str):
                    return value.strip() or None
                return value if isinstance(value, (int, float, bool)) else None
    return None


def _tenant_for_log(payload: Any) -> Any:
    return _raw_data_value_for_log(payload, config.TENANT_KEY)


def _version_for_log(payload: Any) -> Any:
    return _raw_data_value_for_log(payload, config.MODEL_VERSION_KEY)


class _FallbackRotatingHandler(RotatingFileHandler):
    """Khi ổ đĩa lỗi, giữ dòng log trên stderr và không làm hỏng request."""

    def __init__(self, *args: Any, fallback: logging.Handler, **kwargs: Any):
        self.fallback = fallback
        super().__init__(*args, **kwargs)

    def handleError(self, record: logging.LogRecord) -> None:
        self.fallback.handle(record)


class AlertLogWriter:
    def __init__(self, path: str, max_bytes: int, backup_count: int):
        self.logger = logging.Logger("soc.alerts", level=logging.INFO)
        self.logger.propagate = False
        self.fallback = logging.StreamHandler(sys.stderr)
        formatter = logging.Formatter("%(message)s")
        self.fallback.setFormatter(formatter)
        try:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            self.handler = _FallbackRotatingHandler(
                path, maxBytes=max_bytes, backupCount=backup_count,
                encoding="utf-8", fallback=self.fallback,
            )
        except OSError:
            self.handler = self.fallback
            self.logger.addHandler(self.handler)
            self.logger.warning("Không mở được file log alert; ghi log vào stderr.")
        else:
            self.handler.setFormatter(formatter)
            self.logger.addHandler(self.handler)

    def write(self, line: str) -> None:
        try:
            self.logger.info(line)
        except Exception:
            # Việc ghi log không được đổi kết quả phân loại/HTTP của API.
            record = self.logger.makeRecord(
                self.logger.name, logging.INFO, "", 0, line, (), None,
            )
            self.fallback.handle(record)

    def close(self) -> None:
        self.handler.close()
        if self.handler is not self.fallback:
            self.fallback.close()


@dataclass
class AlertLogEntry:
    alert_id: Any = None
    tenant: Any = None
    model_version: Any = None
    item: Optional[int] = None
    code: str = "NOT_PROCESSED"
    detail: str = "Alert chưa được xử lý."


class AlertLogContext:
    def __init__(self, path: str):
        self.received_at = now_vietnam()
        self.request_id = uuid.uuid4().hex
        self.path = path
        self.entries: List[AlertLogEntry] = []
        self.active_index: Optional[int] = None

    def prepare(self, payload: Any) -> None:
        is_batch = self.path.rstrip("/") == "/predict/batch"
        if is_batch and isinstance(payload, list) and payload:
            self.entries = [
                AlertLogEntry(find_alert_id(alert), _tenant_for_log(alert), _version_for_log(alert), i)
                for i, alert in enumerate(payload, start=1)
            ]
        else:
            self.entries = [
                AlertLogEntry(find_alert_id(payload), _tenant_for_log(payload), _version_for_log(payload))
            ]

    def activate(self, index: int) -> None:
        self.active_index = index

    def result(self, code: str, detail: str) -> None:
        if not self.entries:
            self.prepare(None)
        if code == "UNKNOWN_TENANT":
            # API hiện ép tenant object sang str trong lỗi; không chép object vào log.
            detail = "Tenant không tồn tại hoặc chưa có đủ model."
        entry = self.entries[self.active_index if self.active_index is not None else 0]
        entry.code, entry.detail = code, detail

    def success(self, rate: float) -> None:
        self.result("SUCCESS", f"rate={rate:.6f}")

    def request_error(self, code: str, detail: str) -> None:
        if not self.entries:
            self.prepare(None)
        for entry in self.entries:
            entry.code, entry.detail = code, detail

    def internal_error(self, exc: Exception) -> None:
        if not self.entries:
            self.prepare(None)
        # Không chép str(exc): thông báo thư viện có thể chứa dữ liệu SIEM/model.
        detail = f"Lỗi nội bộ khi xử lý request ({type(exc).__name__})."
        for index, entry in enumerate(self.entries):
            if self.active_index is None or index == self.active_index:
                entry.code, entry.detail = "INTERNAL_ERROR", detail
            elif index < self.active_index:
                entry.code = "REQUEST_FAILED"
                entry.detail = "Request lỗi nội bộ; kết quả alert chưa được trả về."
            else:
                entry.code = "NOT_PROCESSED"
                entry.detail = "Alert chưa được xử lý vì request lỗi nội bộ."

    def lines(self, status_code: int) -> List[str]:
        if not self.entries:
            self.request_error("REQUEST_ERROR", "Request không trả về kết quả phân loại.")
        timestamp = self.received_at.astimezone(VIETNAM_TIMEZONE).strftime("%H:%M:%S %d/%m/%Y")
        lines = []
        for entry in self.entries:
            parts = [f'"{timestamp}"', f"req={self.request_id}", _safe_text(self.path)]
            if entry.item is not None:
                parts.append(f"item={entry.item}")
            parts.extend([
                f"alert_id={_safe_text(entry.alert_id)}",
                f"tenant={_safe_text(entry.tenant)}",
                f"model_version={_safe_text(entry.model_version)}",
                f"http={status_code}", entry.code, _safe_text(entry.detail),
            ])
            lines.append(" | ".join(parts))
        return lines


def get_alert_log(scope: Scope) -> Optional[AlertLogContext]:
    return scope.get("alert_log")


class AlertLogMiddleware:
    """Giữ metadata riêng từng request; không đọc/lưu thêm bản sao raw body."""

    def __init__(
        self, app: ASGIApp, log_path: Optional[str] = None,
        max_bytes: Optional[int] = None, backup_count: Optional[int] = None,
    ):
        self.app = app
        self.writer = AlertLogWriter(
            config.ALERT_LOG_PATH if log_path is None else log_path,
            config.ALERT_LOG_MAX_BYTES if max_bytes is None else max_bytes,
            config.ALERT_LOG_BACKUP_COUNT if backup_count is None else backup_count,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            try:
                await self.app(scope, receive, send)
            finally:
                self.writer.close()
            return
        if (scope["type"] != "http" or scope["method"] != "POST"
                or scope["path"].rstrip("/") not in ("/predict", "/predict/batch")):
            await self.app(scope, receive, send)
            return

        context = AlertLogContext(scope["path"])
        scope["alert_log"] = context
        # ServerErrorMiddleware bên ngoài trả 500 nếu app ném lỗi trước response.
        status_code = 500
        response_complete = False

        async def send_with_status(message: Message) -> None:
            nonlocal status_code, response_complete
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)
            if message["type"] == "http.response.body" and not message.get("more_body", False):
                response_complete = True

        try:
            await self.app(scope, receive, send_with_status)
        except Exception as exc:
            if not response_complete:
                context.internal_error(exc)
            raise
        finally:
            try:
                for line in context.lines(status_code):
                    self.writer.write(line)
            except Exception:
                logging.getLogger("uvicorn.error").exception("Không ghi được log alert.")
