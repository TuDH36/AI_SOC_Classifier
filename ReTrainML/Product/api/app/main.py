"""
FastAPI service phân loại cảnh báo SIEM (True Positive / False Positive), đa tenant.

Mỗi khách hàng (tenant) có nhiều phiên bản model. Tenant và phiên bản do BE gửi trong
`raw_data.tenant` + `raw_data.model_version`; cột feature lấy từ mảng `events`.

5 cổng validate cho mỗi cảnh báo:
  ① JSON hợp lệ        -> FastAPI tự xử lý (422 nếu sai cú pháp).
  ② Cấu trúc đúng      -> có raw_data.tenant + raw_data.model_version + mảng events (422).
  ③ Tenant tồn tại     -> 404 UNKNOWN_TENANT.
  ④ Version tồn tại    -> 404 UNKNOWN_MODEL_VERSION; kho model lỗi -> 503 (retryable);
                          artifact hỏng/sai checksum -> 500 MODEL_INTEGRITY_ERROR.
  ⑤ Đủ dữ liệu         -> >= min_important_fields cột quan trọng có giá trị (422).

Output:
    /predict        -> { "_id", "tenant", "model_version", "rate": <float 0..1> }
    /predict/batch  -> list các { "_id", "tenant", "model_version", "rate" } theo đúng thứ tự
                       (phần tử lỗi trả { "_id", <body lỗi> } ngay tại vị trí đó)

Endpoints:
    POST /predict           body: 1 envelope cảnh báo
    POST /predict/batch     body: list các envelope (mỗi cái có tenant/version riêng)
"""
from typing import Any, Dict, List

# Khi file được chạy TRỰC TIẾP như script ("Run Python File", python app/main.py),
# Python không coi nó là một phần của package -> relative import (from . import ...)
# sẽ lỗi. Ta thêm thư mục gốc project vào sys.path để import tuyệt đối (from app ...)
# hoạt động được. Khi chạy qua uvicorn (import dưới dạng app.main) thì __package__
# là "app" nên nhánh này tự bỏ qua.
if __package__ in (None, ""):
    import os
    import sys

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import Body, FastAPI, Request
from fastapi.exception_handlers import http_exception_handler, request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.alert_logging import AlertLogMiddleware, get_alert_log
from app.errors import APIError, InvalidStructureError
from app.tenant_registry import get_registry
from app.validation import extract_alert, extract_model_version, find_alert_id

API_DESCRIPTION = """
Phân loại cảnh báo SIEM True/False Positive theo **(tenant, phiên bản model)**.

- Tenant: `raw_data.tenant` (không phân biệt hoa/thường). Phiên bản: `raw_data.model_version` (**bắt buộc**).
- Feature chỉ lấy từ mảng `events`. Phần còn lại của envelope bị bỏ qua.
- Kết quả: `rate` = xác suất True Positive (0..1) + `model_version` đã dùng.

| HTTP | error_code | Ý nghĩa | BE xử lý |
|---|---|---|---|
| 422 | INVALID_STRUCTURE | Thiếu/sai raw_data.tenant, raw_data.model_version hoặc events | Sửa request, không retry |
| 422 | INVALID_ALERT | < 2 trường quan trọng có dữ liệu | Không phân tích được, không retry |
| 404 | UNKNOWN_TENANT | Tenant chưa có model | Không retry |
| 404 | UNKNOWN_MODEL_VERSION | Tenant không có phiên bản này | Kiểm tra version đang áp dụng |
| 503 | MODEL_STORE_UNAVAILABLE | Kho model (MinIO) tạm lỗi, `retryable: true` | Retry sau |
| 500 | MODEL_INTEGRITY_ERROR | Bộ model hỏng/sai checksum | Báo đội AI |

`/predict/batch` luôn trả HTTP 200 nếu body là list hợp lệ; lỗi từng alert nằm đúng vị trí trong list.
"""

ALERT_EXAMPLE = {
    "id": "seed-stg-NCS-972189_VND",
    "tenancy_id": 1,
    "severity": "HIGH",
    "content": "[VND6826cb451ab402aa] Suspicious code execution",
    "raw_data": {"tenant": "vnd", "model_version": "v1.0"},
    "events": [
        {"Command": "powershell.exe -enc SQBFAFgA", "host": "PTI-JUMP-NCS",
         "process_name": "powershell.exe", "parent_process": "C:\\Windows\\explorer.exe"},
        {"host": "PTI-JUMP-NCS", "signature": "Suspicious PowerShell", "EventCode": "4688"},
    ],
}

app = FastAPI(
    title="SOC Alert Classifier (multi-tenant)",
    description=API_DESCRIPTION,
    version="2.1.0",
)
app.add_middleware(AlertLogMiddleware)


# Output: {"_id": <id alert>, "tenant": "...", "rate": <float>}. Không dùng
# response_model (Pydantic) vì tên trường "_id" có gạch dưới đầu khó khai báo;
# trả thẳng dict cho rõ ràng.


@app.exception_handler(APIError)
def _api_error_handler(request: Request, exc: APIError) -> JSONResponse:
    log = get_alert_log(request.scope)
    if log is not None:
        log.result(exc.error_code, exc.detail)
    return JSONResponse(status_code=exc.status_code, content=exc.to_body())


@app.exception_handler(RequestValidationError)
async def _validation_error_handler(request: Request, exc: RequestValidationError):
    log = get_alert_log(request.scope)
    if log is not None:
        errors = exc.errors()
        invalid_json = any(error.get("type") == "json_invalid" for error in errors)
        log.prepare(None if invalid_json else exc.body)
        if invalid_json:
            log.request_error("JSON_INVALID", "JSON sai cú pháp, không đọc được alert_id.")
        else:
            # Chỉ ghi vị trí/loại lỗi; không ghi input có trong errors().
            reasons = []
            # Giới hạn phần mô tả để batch lỗi lớn không lặp O(N²) nội dung.
            for error in errors[:3]:
                location = ".".join(str(part) for part in error.get("loc", ()))
                reasons.append(f"{location}: {error.get('type', 'invalid')}")
            if len(errors) > 3:
                reasons.append(f"còn {len(errors) - 3} lỗi cấu trúc khác")
            log.request_error(
                "REQUEST_VALIDATION_ERROR",
                "Dữ liệu request không đúng cấu trúc: " + "; ".join(reasons),
            )
    return await request_validation_exception_handler(request, exc)


@app.exception_handler(StarletteHTTPException)
async def _http_error_handler(request: Request, exc: StarletteHTTPException):
    log = get_alert_log(request.scope)
    if log is not None:
        log.request_error("REQUEST_ERROR", "Request bị từ chối trước khi phân loại alert.")
    return await http_exception_handler(request, exc)


@app.on_event("startup")
def _warmup() -> None:
    # Chỉ tạo registry; danh sách tenant + model nạp lazy theo request đầu tiên.
    get_registry()


@app.post("/predict")
def predict(
    request: Request,
    payload: Dict[str, Any] = Body(
        ...,
        description="1 envelope cảnh báo (raw_data.tenant + raw_data.model_version + events[]).",
        openapi_examples={"alert": {"summary": "1 alert VND, model v1.0", "value": ALERT_EXAMPLE}},
    )
) -> Any:
    log = get_alert_log(request.scope)
    if log is not None:
        log.prepare(payload)
        log.activate(0)
    # ② cấu trúc: id + tenant + version (raw_data) + gộp cột feature từ events
    alert_id, tenant, alert = extract_alert(payload)
    version = extract_model_version(payload)
    # ③ tenant + version tồn tại  ④ đủ dữ liệu (trong predict_one) -> dự đoán
    clf = get_registry().get(tenant, version)
    result = clf.predict_one(alert)
    if log is not None:
        log.success(result["rate"])
    return {"_id": alert_id, "tenant": tenant, "model_version": version, "rate": result["rate"]}


@app.post("/predict/batch")
def predict_batch(
    request: Request,
    payload: List[Dict[str, Any]] = Body(
        ...,
        description="Danh sách envelope cảnh báo, mỗi cái có raw_data.tenant + raw_data.model_version riêng.",
        openapi_examples={"batch": {"summary": "2 alert: 1 hợp lệ, 1 sai version", "value": [
            ALERT_EXAMPLE,
            {**ALERT_EXAMPLE, "id": "alert-2", "raw_data": {"tenant": "vnd", "model_version": "v9.9"}},
        ]}},
    )
) -> Any:
    log = get_alert_log(request.scope)
    if log is not None:
        log.prepare(payload)
    if not isinstance(payload, list) or not payload:
        raise InvalidStructureError("Body phải là danh sách cảnh báo (list không rỗng).")

    reg = get_registry()
    # Trả về list kết quả theo đúng thứ tự đầu vào: mỗi cảnh báo 1 phần tử.
    results: List[Dict[str, Any]] = []
    for index, envelope in enumerate(payload):
        if log is not None:
            log.activate(index)
        # Lấy _id trước (best-effort) để kể cả khi lỗi vẫn đối chiếu được.
        alert_id = find_alert_id(envelope)
        try:
            # Mỗi cảnh báo có tenant + version riêng -> tra model theo từng cái.
            _, tenant, alert = extract_alert(envelope)
            version = extract_model_version(envelope)
            clf = reg.get(tenant, version)
            r = clf.predict_one(alert)
            results.append({"_id": alert_id, "tenant": tenant, "model_version": version, "rate": float(r["rate"])})
            if log is not None:
                log.success(r["rate"])
        except APIError as e:
            # Một cảnh báo lỗi không làm hỏng cả batch -> trả body lỗi ngay tại vị trí đó.
            results.append({"_id": alert_id, **e.to_body()})
            if log is not None:
                log.result(e.error_code, e.detail)

    return results


# Cho phép chạy trực tiếp ("Run" trong IDE / `python -m app.main`).
# Production vẫn nên gọi: uvicorn app.main:app --host 0.0.0.0 --port 8000
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
