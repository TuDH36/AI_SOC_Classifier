"""Cấu hình runtime — đọc từ biến môi trường (12-factor, tiện cho Docker).

Thứ tự ưu tiên cấu hình:
  1. Biến môi trường thật (vd ENV trong Dockerfile, hay `$env:X` trong shell).
  2. File .env ở thư mục gốc project (nếu có) — tiện cho chạy local/dev.
  3. Giá trị mặc định trong file này.
load_dotenv KHÔNG ghi đè biến đã set sẵn (override=False) -> môi trường thật thắng.
"""
import os

from dotenv import load_dotenv

# .env nằm ở thư mục gốc project (cha của thư mục app/). Không có file vẫn chạy bình thường.
_ENV_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
load_dotenv(_ENV_PATH, override=False)

# ── Nguồn model theo (tenant, version) ──────────────────────────────────────
# Cấu trúc key GIỐNG NHAU cho MinIO và thư mục local:
#   <MODEL_PREFIX>/<TENANT>/versions/<VERSION>/{manifest.json, tfidf_char.pkl,
#                                              tfidf_word.pkl, cat_encoder.pkl, lgbm_clf.pkl}
# "minio" (production) hoặc "local" (đọc MODELS_ROOT; vd bản chép bằng `mc mirror`).
MODEL_STORE = os.environ.get("MODEL_STORE", "local").strip().lower()
MODEL_PREFIX = os.environ.get("MODEL_PREFIX", "tenants").strip("/")

# Thư mục GỐC khi MODEL_STORE=local (chứa <MODEL_PREFIX>/...).
MODELS_ROOT = os.environ.get("MODELS_ROOT", "/app/models")

# MinIO (MODEL_STORE=minio). Secret chỉ truyền qua biến môi trường, không ghi vào code/image.
MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "")          # host:port, vd 192.168.143.73:9000
MINIO_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY", "")
MINIO_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY", "")
MINIO_BUCKET = os.environ.get("MINIO_BUCKET", "soar-models")
MINIO_SECURE = os.environ.get("MINIO_SECURE", "false").strip().lower() in ("1", "true", "yes")
MINIO_TIMEOUT_SECONDS = float(os.environ.get("MINIO_TIMEOUT_SECONDS", "10"))

# Artifact tải từ MinIO được lưu (đã kiểm tra checksum) tại đây: restart không phải tải lại,
# và bộ đã có vẫn phục vụ được khi MinIO tạm mất kết nối.
MODEL_CACHE_DIR = os.environ.get(
    "MODEL_CACHE_DIR",
    os.path.join(os.path.dirname(_ENV_PATH), "model-cache"),
)

# Số bộ model (tenant, version) giữ trong RAM; vượt quá -> bỏ bộ lâu không dùng nhất.
MAX_LOADED_MODELS = int(os.environ.get("MAX_LOADED_MODELS", "20"))

# Chu kỳ (giây) liệt kê lại danh sách tenant trên store -> thêm tenant mới không cần restart.
TENANT_LIST_TTL_SECONDS = float(os.environ.get("TENANT_LIST_TTL_SECONDS", "60"))

# Tên file artifact (giữ đúng tên như notebook lưu).
TFIDF_CHAR_FILE = os.environ.get("TFIDF_CHAR_FILE", "tfidf_char.pkl")
TFIDF_WORD_FILE = os.environ.get("TFIDF_WORD_FILE", "tfidf_word.pkl")
CAT_ENCODER_FILE = os.environ.get("CAT_ENCODER_FILE", "cat_encoder.pkl")
LGBM_FILE = os.environ.get("LGBM_FILE", "lgbm_clf.pkl")
MANIFEST_FILE = os.environ.get("MANIFEST_FILE", "manifest.json")

# Khóa trong JSON đầu vào dùng để xác định tenant.
# Trong format mới, tenant nằm LỒNG trong khối `raw_data` -> raw_data.tenant.
TENANT_KEY = os.environ.get("TENANT_KEY", "tenant")

# Khối chứa metadata case (trong đó có tenant). Bắt buộc có để lấy tenant.
RAW_DATA_KEY = os.environ.get("RAW_DATA_KEY", "raw_data")

# Khóa chứa phiên bản model, nằm CÙNG CẤP với tenant: raw_data.model_version. Bắt buộc
# (thiếu -> 422). BE chọn version cho từng request; AI không tự chọn bản "đang áp dụng".
MODEL_VERSION_KEY = os.environ.get("MODEL_VERSION_KEY", "model_version")

# Khóa chứa MẢNG các event SIEM — nguồn DUY NHẤT lấy cột feature cho model.
EVENTS_KEY = os.environ.get("EVENTS_KEY", "events")

# ── Ngưỡng mặc định (có thể override per-tenant trong manifest.json) ─────────
# Ngưỡng xác suất gán True Positive.
DEFAULT_THRESHOLD = float(os.environ.get("THRESHOLD", "0.5"))

# SỐ cột quan trọng TỐI THIỂU (có giá trị thực) thì mới cho dự đoán.
# Data SIEM thưa: mỗi cảnh báo chỉ điền vài cột trong ~69 cột candidate, nên dùng
# NGƯỠNG TUYỆT ĐỐI (số cột) thay vì tỉ lệ %. < ngưỡng -> "cảnh báo không hợp lệ".
DEFAULT_MIN_IMPORTANT_FIELDS = int(os.environ.get("MIN_IMPORTANT_FIELDS", "2"))

# Giá trị fill cho cột bị thiếu (đúng như train: dùng "-").
FILL_VALUE = os.environ.get("FILL_VALUE", "-")

LABEL_TRUE = "true positive"
LABEL_FALSE = "false positive"

# Log kết quả alert: giờ Việt Nam, 10 MiB/file, giữ tối đa 5 file đã xoay.
ALERT_LOG_PATH = os.environ.get(
    "ALERT_LOG_PATH", os.path.join(os.path.dirname(_ENV_PATH), "logs", "alerts.log")
)
ALERT_LOG_MAX_BYTES = int(os.environ.get("ALERT_LOG_MAX_BYTES", str(10 * 1024 * 1024)))
ALERT_LOG_BACKUP_COUNT = int(os.environ.get("ALERT_LOG_BACKUP_COUNT", "5"))
