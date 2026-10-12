"""
AlertClassifier (per-tenant) — pipeline phục vụ khớp tuyệt đối với Code_thuan.ipynb.

Mỗi instance gắn với 1 tenant: load 4 artifact + manifest, build FieldMapper riêng.

Luồng dự đoán cho 1 cảnh báo (mirror predict_new):
    JSON (đã bỏ trường tenant)
      -> FieldMapper.map_payload()  map tên trường -> canonical; bỏ id/hash/time/...
      -> kiểm tra số cột quan trọng có giá trị >= min_important_fields (vd 2)
      -> clean_value()              clean_data + clean_noisy_values
      -> combined_text              join text cols (cột thiếu -> "-")
      -> tfidf_char/.word.transform
      -> cat_enc.transform()+1      (cột thiếu -> "-")
      -> hstack -> lgbm.predict_proba()[:,1]
"""
import os
import warnings
from typing import Any, Dict, List, Tuple

import joblib
import pandas as pd
from scipy.sparse import hstack, csr_matrix

from . import config
from .errors import InvalidAlertError
from .field_mapping import FieldMapper, flatten_json
from .manifest import TenantManifest
from .preprocessing import clean_value, is_meaningful

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")


class AlertClassifier:
    def __init__(self, tenant: str, tenant_dir: str):
        self.tenant = tenant
        self.tenant_dir = tenant_dir
        self.manifest = TenantManifest.load(tenant, tenant_dir)
        self.model_version = self.manifest.model_version
        self._load_artifacts()
        self._build_mapper()

    def _load_artifacts(self) -> None:
        d = self.tenant_dir
        paths = {
            "tfidf_char": os.path.join(d, config.TFIDF_CHAR_FILE),
            "tfidf_word": os.path.join(d, config.TFIDF_WORD_FILE),
            "cat_enc": os.path.join(d, config.CAT_ENCODER_FILE),
            "clf": os.path.join(d, config.LGBM_FILE),
        }
        for name, p in paths.items():
            if not os.path.exists(p):
                raise FileNotFoundError(f"[{self.tenant}] Thiếu artifact '{name}': {p}")

        self.tfidf_char = joblib.load(paths["tfidf_char"])
        self.tfidf_word = joblib.load(paths["tfidf_word"])
        self.cat_enc = joblib.load(paths["cat_enc"])
        self.clf = joblib.load(paths["clf"])

        # cat_cols: nguồn chân lý là encoder (đúng thứ tự + số lượng đã fit).
        self.cat_cols: List[str] = list(self.cat_enc.feature_names_in_)
        # text_cols: RIÊNG mỗi tenant, BẮT BUỘC khai trong manifest.json.
        self.text_cols: List[str] = list(self.manifest.text_cols)
        if not self.text_cols:
            raise ValueError(
                f"[{self.tenant}] manifest.json thiếu 'text_cols'. Mỗi tenant phải tự "
                f"khai danh sách cột text của mình (không dùng chung với tenant khác)."
            )
        # Tập trường "quan trọng" để tính tỉ lệ khớp validation.
        self.important_cols: List[str] = self.text_cols + self.cat_cols
        self.n_features_expected = int(getattr(self.clf, "n_features_in_", -1))

    def _build_mapper(self) -> None:
        self.mapper = FieldMapper(
            feature_columns=self.important_cols,
            extra_aliases=self.manifest.field_aliases,
        )

    # ── Tiền xử lý + đặc trưng ──────────────────────────────────────────────
    def _prepare(self, payload: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str], List[str]]:
        """map + tìm cột quan trọng có giá trị. Trả (mapped, ignored, present_cols)."""
        flat = flatten_json(payload)
        mapped, ignored = self.mapper.map_payload(flat)

        # Cột quan trọng map được VÀ có DỮ LIỆU THẬT (loại rỗng/"-"/"nan"/"none"/"_").
        present = [
            c for c in self.important_cols
            if c in mapped and is_meaningful(mapped[c])
        ]
        return mapped, ignored, present

    def _build_features(self, mapped: Dict[str, Any]):
        text_parts = [
            clean_value(mapped[c], config.FILL_VALUE) if c in mapped else config.FILL_VALUE
            for c in self.text_cols
        ]
        combined_text = " ".join(text_parts)

        cat_row = {
            c: (clean_value(mapped[c], config.FILL_VALUE) if c in mapped else config.FILL_VALUE)
            for c in self.cat_cols
        }
        df_cat = pd.DataFrame([cat_row], columns=self.cat_cols)

        x_char = self.tfidf_char.transform([combined_text])
        x_word = self.tfidf_word.transform([combined_text])
        x_cat = self.cat_enc.transform(df_cat) + 1
        return hstack([x_char, x_word, csr_matrix(x_cat)])

    # ── Dự đoán 1 cảnh báo ──────────────────────────────────────────────────
    def predict_one(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        mapped, ignored, present = self._prepare(payload)
        n_present = len(present)
        min_fields = self.manifest.min_important_fields

        if n_present < min_fields:
            raise InvalidAlertError(
                f"Cảnh báo không hợp lệ cho tenant '{self.tenant}': chỉ có "
                f"{n_present} cột quan trọng có giá trị (yêu cầu >= {min_fields}).",
                tenant=self.tenant,
                n_important_fields=n_present,
                min_important_fields=min_fields,
                present_fields=present,
                ignored_fields=ignored,
            )

        x = self._build_features(mapped)
        proba_tp = float(self.clf.predict_proba(x)[:, 1][0])
        thr = self.manifest.threshold
        is_tp = proba_tp >= thr
        label = config.LABEL_TRUE if is_tp else config.LABEL_FALSE
        # rate = xác suất true positive: càng gần 1 -> càng nghiêng TP,
        # càng gần 0 -> càng nghiêng FP. Mốc quyết định label là threshold.
        rate = proba_tp

        return {
            "label": label,
            "rate": round(rate, 6),
            "_meta": {
                "tenant": self.tenant,
                "proba_true_positive": round(proba_tp, 6),
                "threshold": thr,
                "n_important_fields": n_present,
                "matched_fields": sorted(mapped.keys()),
                "ignored_fields": ignored,
            },
        }
