# ── SOC Alert Classifier — image phục vụ trên server SOAR ────────────────
# Python 3.11 khớp môi trường train.
FROM python:3.11-slim

# LightGBM cần libgomp (OpenMP runtime).
# Khóa đúng phiên bản hiện có trong Debian Trixie.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1=14.2.0-19 \
    && rm -rf /var/lib/apt/lists/*

# MODEL_STORE=local dùng bộ model đóng sẵn trong image (models/tenants/...).
# Production: docker run -e MODEL_STORE=minio -e MINIO_ENDPOINT=... -e MINIO_ACCESS_KEY=... -e MINIO_SECRET_KEY=...
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MODEL_STORE=local \
    MODELS_ROOT=/app/models \
    MODEL_CACHE_DIR=/app/model-cache \
    MINIO_BUCKET=soar-models \
    THRESHOLD=0.5 \
    MIN_IMPORTANT_FIELDS=2

WORKDIR /app

# Cài dependencies trước để tận dụng Docker layer cache.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Mã nguồn và artifact model.
COPY app/ ./app/
# Bộ model theo cấu trúc MinIO (dự phòng khi MODEL_STORE=local).
COPY models/tenants/ ./models/tenants/

# Thư mục log và cache model (tải từ MinIO) phải ghi được bởi user chạy API.
# Nên mount volume vào /app/model-cache để restart không phải tải lại model.
RUN mkdir -p /app/logs /app/model-cache && chown 10001:10001 /app/logs /app/model-cache

EXPOSE 8000

# Chạy API bằng UID/GID không có quyền root.
USER 10001:10001

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
