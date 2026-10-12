"""
Đọc & kiểm tra manifest.json của từng tenant.

manifest.json (đặt cạnh các .pkl trong thư mục tenant) khai báo metadata riêng:

{
  "tenant": "VND",
  "text_cols": ["events.command", "events._raw", ...],   // bắt buộc
  "threshold": 0.5,                                        // optional
  "min_important_fields": 2,                               // optional (số cột tối thiểu)
  "required_fields": [],                                   // optional (chưa dùng mặc định)
  "field_aliases": { "src_address": "events.src_ip" },     // optional
  "model_version": "2026-05-29",                           // optional, để log
  "sklearn_version": "1.3.0"                               // optional, để log
}

- cat_cols KHÔNG khai trong manifest: luôn lấy từ cat_encoder.feature_names_in_
  (nguồn chân lý) lúc load model.
- Nếu manifest thiếu/không đọc được -> dùng default (xem from_dict).
"""
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import config


@dataclass
class TenantManifest:
    tenant: str
    text_cols: List[str]
    threshold: float = config.DEFAULT_THRESHOLD
    min_important_fields: int = config.DEFAULT_MIN_IMPORTANT_FIELDS
    required_fields: List[str] = field(default_factory=list)
    field_aliases: Dict[str, str] = field(default_factory=dict)
    model_version: Optional[str] = None
    sklearn_version: Optional[str] = None

    @classmethod
    def from_dict(cls, tenant: str, data: dict) -> "TenantManifest":
        return cls(
            tenant=data.get("tenant", tenant),
            # text_cols là RIÊNG mỗi tenant -> KHÔNG fallback sang list tenant khác.
            # Thiếu -> để rỗng, AlertClassifier sẽ fail-fast với thông báo rõ ràng.
            text_cols=list(data.get("text_cols") or []),
            threshold=float(data.get("threshold", config.DEFAULT_THRESHOLD)),
            min_important_fields=int(
                data.get("min_important_fields", config.DEFAULT_MIN_IMPORTANT_FIELDS)
            ),
            required_fields=list(data.get("required_fields") or []),
            field_aliases=dict(data.get("field_aliases") or {}),
            model_version=data.get("model_version"),
            sklearn_version=data.get("sklearn_version"),
        )

    @classmethod
    def load(cls, tenant: str, tenant_dir: str) -> "TenantManifest":
        path = os.path.join(tenant_dir, config.MANIFEST_FILE)
        data: dict = {}
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        # Không có manifest vẫn chạy được với default (text_cols mặc định).
        return cls.from_dict(tenant, data)
