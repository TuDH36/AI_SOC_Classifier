"""Cổng validate cấu trúc & bóc tách (tenant, cột feature) từ payload format mới.

Format đầu vào (1 cảnh báo):
{
  "id": "...", "tenancy_id": 1001, "severity": "...", "content": "...",
  "raw_data": { ..., "tenant": "vnd", "model_version": "v1.0", ... },  # tenant + version LỒNG ở đây
  "events": [ { "Computer": "...", "EventData_Xml": "...", ... } ]  # cột feature
}

Quy tắc:
  - tenant: CHỈ lấy ở `raw_data.tenant`. Không có -> báo lỗi (không tìm chỗ khác).
  - version: CHỈ lấy ở `raw_data.model_version` (cùng cấp tenant). Không có -> 422.
  - cột feature: CHỈ lấy từ mảng `events`. Bỏ qua id/severity/content và phần còn
    lại của raw_data (đặc biệt `raw_data.resolution` là NHÃN ĐÚNG -> không được
    đưa vào model để tránh data leakage).
  - `events` có nhiều phần tử -> gộp thành 1 dict, mỗi cột lấy giá trị "có nghĩa"
    đầu tiên (event sau chỉ lấp chỗ trống mà event trước chưa có giá trị thật).
"""
import re
from typing import Any, Dict, List, Tuple

from . import config
from .errors import InvalidStructureError
from .preprocessing import is_meaningful

# Version dùng làm 1 đoạn key trên kho model -> chỉ cho ký tự an toàn (chặn "../", "/", ...).
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def find_alert_id(payload: Any) -> Any:
    """Lấy id alert ở top-level (chấp nhận cả 'id' lẫn '_id', không phân biệt hoa/thường).

    Best-effort: trả None nếu payload không phải dict hoặc không có id. Tách riêng để
    batch có thể đính kèm _id ngay cả khi cảnh báo lỗi cấu trúc.
    """
    if not isinstance(payload, dict):
        return None
    for k, v in payload.items():
        if str(k).strip().lower() in ("id", "_id"):
            return v
    return None


def _find_tenant(raw_data: Dict[str, Any]) -> str:
    """Lấy tenant trong raw_data (không phân biệt hoa/thường tên khóa)."""
    target = config.TENANT_KEY.lower()
    for k, v in raw_data.items():
        if str(k).strip().lower() == target:
            if v is None or str(v).strip() == "":
                raise InvalidStructureError(
                    f"Trường '{config.RAW_DATA_KEY}.{config.TENANT_KEY}' rỗng.",
                    tenant_key=config.TENANT_KEY,
                )
            return str(v).strip()
    raise InvalidStructureError(
        f"Thiếu trường '{config.RAW_DATA_KEY}.{config.TENANT_KEY}' để xác định tenant.",
        tenant_key=config.TENANT_KEY,
    )


def extract_model_version(payload: Dict[str, Any]) -> str:
    """Lấy phiên bản model ở raw_data.model_version (cùng cấp tenant). Thiếu/sai -> 422.

    Gọi SAU extract_alert (khi đó raw_data chắc chắn là object).
    """
    field_name = f"{config.RAW_DATA_KEY}.{config.MODEL_VERSION_KEY}"
    raw_data = payload.get(config.RAW_DATA_KEY) if isinstance(payload, dict) else None
    target = config.MODEL_VERSION_KEY.lower()
    for k, v in (raw_data or {}).items():
        if str(k).strip().lower() == target:
            version = v.strip() if isinstance(v, str) else ""
            if not version:
                break
            if not _VERSION_RE.match(version) or ".." in version:
                raise InvalidStructureError(
                    f"Giá trị '{field_name}' không hợp lệ (chỉ gồm chữ, số, '.', '_', '-').",
                    version_key=config.MODEL_VERSION_KEY,
                )
            return version
    raise InvalidStructureError(
        f"Thiếu trường '{field_name}' (phiên bản model, vd 'v1.0').",
        version_key=config.MODEL_VERSION_KEY,
    )


def _merge_events(events: List[Any]) -> Dict[str, Any]:
    """Gộp mảng event -> 1 dict phẳng. Mỗi cột giữ giá trị 'có nghĩa' đầu tiên."""
    merged: Dict[str, Any] = {}
    for ev in events:
        if not isinstance(ev, dict):
            continue
        for k, v in ev.items():
            # Lấp giá trị nếu cột chưa có, hoặc giá trị đang giữ là rỗng/"-".
            if k not in merged or (not is_meaningful(merged[k]) and is_meaningful(v)):
                merged[k] = v
    return merged


def extract_alert(payload: Dict[str, Any]) -> Tuple[Any, str, Dict[str, Any]]:
    """Kiểm tra cấu trúc envelope + trả (alert_id, tenant, dict cột feature gộp từ events).

    Raise InvalidStructureError nếu body không phải object, thiếu raw_data.tenant,
    hoặc thiếu mảng events hợp lệ.
    """
    if not isinstance(payload, dict):
        raise InvalidStructureError("Body phải là một JSON object (key-value).")
    if not payload:
        raise InvalidStructureError("Body rỗng.")

    alert_id = find_alert_id(payload)

    # ── tenant: CHỈ trong raw_data ──────────────────────────────────────────
    raw_data = payload.get(config.RAW_DATA_KEY)
    if not isinstance(raw_data, dict) or not raw_data:
        raise InvalidStructureError(
            f"Thiếu khối '{config.RAW_DATA_KEY}' (object) để xác định tenant."
        )
    tenant = _find_tenant(raw_data)

    # ── cột feature: CHỈ trong mảng events ──────────────────────────────────
    events = payload.get(config.EVENTS_KEY)
    if not isinstance(events, list) or not events:
        raise InvalidStructureError(
            f"Thiếu mảng '{config.EVENTS_KEY}' (list không rỗng) chứa dữ liệu cảnh báo."
        )
    merged = _merge_events(events)
    if not merged:
        raise InvalidStructureError(
            f"Mảng '{config.EVENTS_KEY}' không có event hợp lệ (object) nào."
        )

    return alert_id, tenant, merged
