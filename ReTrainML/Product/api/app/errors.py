"""Exception nghiệp vụ -> map sang HTTP response có cấu trúc rõ ràng."""


class APIError(Exception):
    """Base. status_code + error_code + detail + extra (đưa vào body)."""

    status_code = 400
    error_code = "ERROR"

    def __init__(self, detail: str, **extra):
        super().__init__(detail)
        self.detail = detail
        self.extra = extra

    def to_body(self) -> dict:
        body = {"error_code": self.error_code, "detail": self.detail}
        body.update(self.extra)
        return body


class InvalidStructureError(APIError):
    """Body không phải object hợp lệ / thiếu trường tenant."""
    status_code = 422
    error_code = "INVALID_STRUCTURE"


class UnknownTenantError(APIError):
    """Mã tenant không tồn tại trong registry."""
    status_code = 404
    error_code = "UNKNOWN_TENANT"


class InvalidAlertError(APIError):
    """Map được < ngưỡng % trường quan trọng -> cảnh báo không hợp lệ."""
    status_code = 422
    error_code = "INVALID_ALERT"


class UnknownModelVersionError(APIError):
    """Tenant có tồn tại nhưng không có phiên bản model được yêu cầu."""
    status_code = 404
    error_code = "UNKNOWN_MODEL_VERSION"


class ModelStoreUnavailableError(APIError):
    """Không kết nối/đọc được kho model (MinIO) và chưa có bản cache -> BE nên thử lại sau."""
    status_code = 503
    error_code = "MODEL_STORE_UNAVAILABLE"

    def __init__(self, detail: str, **extra):
        super().__init__(detail, retryable=True, **extra)


class ModelIntegrityError(APIError):
    """Bộ artifact thiếu/hỏng/sai checksum/không nạp được. KHÔNG fallback sang version khác."""
    status_code = 500
    error_code = "MODEL_INTEGRITY_ERROR"
