# SOC Alert Classifier API (multi-tenant)

Service phân loại cảnh báo SIEM **True Positive / False Positive** bằng LightGBM +
TF-IDF (train trong `Module_Training.ipynb`). **Mỗi khách hàng (tenant) có nhiều phiên bản
model**; BE chọn phiên bản cho từng request. Model đọc từ **MinIO** (hoặc thư mục local cùng
cấu trúc). Đóng gói Docker để chạy trên SOAR.

## Đầu vào / Đầu ra

**Input** — 1 JSON envelope cảnh báo. **Tenant và phiên bản model bắt buộc nằm trong
`raw_data`** (`raw_data.tenant`, `raw_data.model_version`); cột feature lấy từ **mảng `events`**:

```json
{
  "id": "mVdH2Z0...",
  "tenancy_id": 1001,
  "severity": "Low",
  "content": "Changes in system's time",
  "raw_data": { "tenant": "vnd", "model_version": "v1.0", "resolution": "False Positive", "...": "..." },
  "events": [
    { "LogonProcessName": "...", "EventData_Xml": "...", "MachineName": "...", "...": "..." }
  ]
}
```
- **Tenant**: chỉ đọc ở `raw_data.tenant` (không tìm chỗ khác) → thiếu = `INVALID_STRUCTURE`.
  Không phân biệt hoa/thường (`vnd` ↔ thư mục/prefix `VND`).
- **Phiên bản**: chỉ đọc ở `raw_data.model_version` → thiếu/rỗng/sai định dạng = 422
  `INVALID_STRUCTURE`. Chỉ nhận chữ, số, `.`, `_`, `-` (vd `v1.0`). AI không tự chọn bản
  "đang áp dụng" và **không fallback** sang bản khác khi bản được yêu cầu thiếu/hỏng.
- **Feature**: chỉ lấy từ `events[]`. Toàn bộ `id/tenancy_id/severity/content` và phần
  còn lại của `raw_data` **bị bỏ qua** (đặc biệt `raw_data.resolution` là nhãn đúng,
  không đưa vào model → tránh data leakage).
- `events` nhiều phần tử → **gộp**, mỗi cột lấy giá trị "có nghĩa" đầu tiên.
- Tên cột trong event có thể "xấu" (hoa/thường, space, thiếu prefix `events.`) — service
  tự **map về schema chuẩn của tenant**. Cột thuộc schema nhưng thiếu → fill `"-"`.

**Output**

```json
{ "_id": "mVdH2Z0...", "tenant": "vnd", "model_version": "v1.0", "rate": 0.0024 }
```
- `_id`  : id của alert (đọc từ `id`/`_id` top-level; `null` nếu không có).
- `tenant`: tenant lấy từ alert.
- `model_version`: phiên bản model đã dùng (BE ghi vào `aiModelVersion`).
- `rate` : xác suất True Positive (0..1), càng gần 1 càng nghiêng về TP.

`/predict/batch` trả list cùng dạng; phần tử lỗi vẫn kèm `_id` + body lỗi để đối chiếu.

## 5 cổng validate mỗi request

| # | Kiểm tra | Lỗi (HTTP) |
|---|----------|-----------|
| ① | JSON hợp lệ | 422 (FastAPI) |
| ② | Body là object + có `raw_data.tenant` + `raw_data.model_version` + mảng `events` không rỗng | 422 `INVALID_STRUCTURE` |
| ③ | Tenant tồn tại trên kho model | 404 `UNKNOWN_TENANT` |
| ④ | Phiên bản tồn tại và bộ artifact hợp lệ | 404 `UNKNOWN_MODEL_VERSION`; 503 `MODEL_STORE_UNAVAILABLE` (`retryable: true`, MinIO lỗi và chưa có cache); 500 `MODEL_INTEGRITY_ERROR` (thiếu file/sai SHA-256/không nạp được) |
| ⑤ | Có ≥ `min_important_fields` (mặc định **2**) **cột quan trọng** có giá trị | 422 `INVALID_ALERT` |

Cổng ⑤: 1 cảnh báo phải có **≥ N cột quan trọng** (text_cols + cat_cols) mang giá
trị thực thì mới cho dự đoán; ít hơn → `INVALID_ALERT` (chặn data rỗng / gửi nhầm
tenant). Dùng ngưỡng TUYỆT ĐỐI (số cột) vì data SIEM thưa: mỗi cảnh báo thường chỉ
điền ~6–8 trong ~69 cột candidate. Cột thuộc schema nhưng thiếu vẫn được fill `"-"`.

## Bố cục model theo tenant/phiên bản

Cùng một cấu trúc key cho MinIO (bucket `soar-models`) và thư mục local (`MODELS_ROOT`):

```
tenants/
└── VND/
    └── versions/
        └── v1.0/
            ├── manifest.json    ← metadata + checksum của cả bộ
            ├── tfidf_char.pkl
            ├── tfidf_word.pkl
            ├── cat_encoder.pkl
            └── lgbm_clf.pkl
```

`manifest.json` (rút gọn):
```json
{
  "tenant": "VND",
  "model_version": "v1.0",
  "text_cols": ["events.command", "events._raw", "..."],
  "threshold": 0.5,
  "min_important_fields": 2,
  "field_aliases": {},
  "sklearn_version": "1.3.0",
  "artifacts": [{ "file": "lgbm_clf.pkl", "sha256": "0f8b2e…", "size_bytes": 1478156 }, "..."]
}
```
> `cat_cols` (vd 38 cột VND) luôn tự lấy từ `cat_encoder.feature_names_in_` —
> không khai trong manifest. `text_cols` lấy từ manifest (mỗi tenant khác nhau).
> Tập "trường quan trọng" để tính cổng ⑤ = `text_cols + cat_cols`.
> `model_version` và `tenant` trong manifest phải khớp đường dẫn; `artifacts` phải khai
> SHA-256 đủ 4 file — sai một điều kiện là `MODEL_INTEGRITY_ERROR`, không nạp.

Nạp model: lazy theo request đầu tiên của mỗi `(tenant, version)`, giữ trong RAM tối đa
`MAX_LOADED_MODELS` bộ (LRU). Với MinIO, bộ đã tải + kiểm tra được lưu ở `MODEL_CACHE_DIR`:
restart không tải lại và vẫn phục vụ được khi MinIO tạm mất kết nối.

### Thêm tenant / phiên bản mới
1. Train (notebook) → 4 file `.pkl` + `manifest.json` có `model_version` và `artifacts`.
2. Upload cả bộ lên `soar-models/tenants/<TENANT>/versions/<VERSION>/` (ghi `manifest.json` cuối cùng).
3. Không cần restart: tenant mới được nhận sau tối đa `TENANT_LIST_TTL_SECONDS`; version mới
   được tải khi có request đầu tiên. Phiên bản đã xuất bản không ghi đè (tạo version mới).

## Endpoints

| Method | Path | Mô tả |
|--------|------|-------|
| POST | `/predict` | 1 envelope cảnh báo → `{_id, tenant, model_version, rate}` |
| POST | `/predict/batch` | **list** envelope (mỗi cái có `raw_data.tenant` + `raw_data.model_version` riêng) → list kết quả |

`/predict/batch` xử lý từng cảnh báo độc lập: 1 cái lỗi (sai cấu trúc / tenant hoặc version
lạ / kho model lỗi / không đủ dữ liệu) trả body lỗi tại đúng vị trí đó, **không làm hỏng cả lô**.

## Chạy local (dev)

```bash
pip install -r requirements.txt
# Model local, cùng cấu trúc MinIO: models/tenants/<TENANT>/versions/<VERSION>/
export MODEL_STORE=local MODELS_ROOT=$(pwd)/models
# Hoặc đọc thẳng MinIO:
# export MODEL_STORE=minio MINIO_ENDPOINT=192.168.143.73:9000 MINIO_ACCESS_KEY=... MINIO_SECRET_KEY=...
uvicorn app.main:app --host 0.0.0.0 --port 8000
# Swagger: http://localhost:8000/docs
```

> `.env` local có thể đặt `MODELS_ROOT` sang cây thư mục khác; biến môi trường thật luôn
> ghi đè `.env`, nên đặt `MODELS_ROOT` rõ ràng khi chạy.

## Docker (trên SOAR)

```bash
docker build -t soc-alert-classifier:2.1 .
# Production: đọc model từ MinIO, cache vào volume riêng
docker run -d --name soc-clf -p 8000:8000 \
  -e MODEL_STORE=minio -e MINIO_ENDPOINT=192.168.143.73:9000 \
  -e MINIO_ACCESS_KEY=... -e MINIO_SECRET_KEY=... \
  -v soc-clf-model-cache:/app/model-cache -v soc-clf-logs:/app/logs \
  soc-alert-classifier:2.1
# Không có MinIO: dùng bộ model đóng sẵn trong image (MODEL_STORE=local, mặc định)
docker run -d -p 8000:8000 soc-alert-classifier:2.1
```

Từ trong container, `127.0.0.1` là chính container: `MINIO_ENDPOINT` phải là IP host
hoặc tên service trong cùng Docker network.

## Gọi API

```bash
# 1 cảnh báo (tenant + version trong raw_data, feature trong events[])
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"raw_data":{"tenant":"vnd","model_version":"v1.0"},"events":[{"LogonProcessName":"x","MachineName":"y"}]}'
# Ví dụ định dạng: {"_id":null,"tenant":"vnd","model_version":"v1.0","rate":0.0024}

# Nhiều cảnh báo: body là 1 list, mỗi phần tử có tenant/version riêng
curl -X POST http://localhost:8000/predict/batch \
  -H "Content-Type: application/json" -d '[{...}, {...}]'   # body mẫu đầy đủ có trong Swagger /docs
```

## Cấu hình (ENV)

| Biến | Mặc định | Ý nghĩa |
|------|----------|---------|
| `MODEL_STORE` | `local` | `minio` hoặc `local` |
| `MODEL_PREFIX` | `tenants` | tiền tố key/thư mục: `<prefix>/<TENANT>/versions/<VERSION>/` |
| `MODELS_ROOT` | `/app/models` | thư mục gốc khi `MODEL_STORE=local` |
| `MINIO_ENDPOINT` | — | `host:port` của MinIO (S3 API), vd `192.168.143.73:9000` |
| `MINIO_ACCESS_KEY` / `MINIO_SECRET_KEY` | — | tài khoản MinIO (chỉ truyền qua ENV/secret) |
| `MINIO_BUCKET` | `soar-models` | bucket chứa model |
| `MINIO_SECURE` | `false` | `true` nếu MinIO dùng HTTPS |
| `MINIO_TIMEOUT_SECONDS` | `10` | timeout kết nối/đọc MinIO |
| `MODEL_CACHE_DIR` | `model-cache` trong thư mục API; Docker `/app/model-cache` | nơi lưu bộ model đã tải + kiểm tra |
| `MAX_LOADED_MODELS` | `20` | số bộ `(tenant, version)` giữ trong RAM (LRU) |
| `TENANT_LIST_TTL_SECONDS` | `60` | chu kỳ liệt kê lại tenant trên kho model |
| `RAW_DATA_KEY` | `raw_data` | khối chứa tenant + version |
| `MODEL_VERSION_KEY` | `model_version` | tên khóa phiên bản bên trong `raw_data` |
| `EVENTS_KEY` | `events` | mảng chứa cột feature của cảnh báo |
| `TENANT_KEY` | `tenant` | tên khóa tenant bên trong `raw_data` |
| `THRESHOLD` | `0.5` | ngưỡng TP mặc định (manifest override được) |
| `MIN_IMPORTANT_FIELDS` | `2` | số cột quan trọng tối thiểu phải có giá trị (manifest override được) |
| `FILL_VALUE` | `-` | fill cột thiếu |
| `ALERT_LOG_PATH` | `logs/alerts.log` trong thư mục API | file log alert; Docker mặc định `/app/logs/alerts.log` |
| `ALERT_LOG_MAX_BYTES` | `10485760` | xoay file ở khoảng 10 MiB |
| `ALERT_LOG_BACKUP_COUNT` | `5` | số file log cũ giữ lại |

## Log kết quả alert

API tự tạo file UTF-8 `logs/alerts.log`, ghi nối tiếp **mỗi alert một dòng**.
Đầu dòng là thời điểm request đi vào API, trước khi đọc/kiểm tra body, theo giờ
Việt Nam (UTC+7): `"giờ:phút:giây ngày/tháng/năm"`. Dòng log được ghi sau khi xác
định phản hồi; thời gian vẫn là lúc nhận request.

```text
"10:00:01 10/09/2026" | req=7c70c42b33554f20876ec6110cf118d2 | /predict | alert_id=A001 | tenant=vnd | model_version=v1.0 | http=200 | SUCCESS | rate=0.982100
"10:00:02 10/09/2026" | req=80a4812acba94a389bb0698fa1ddfe36 | /predict | alert_id=A002 | tenant=- | model_version=- | http=422 | INVALID_STRUCTURE | Thiếu khối 'raw_data' (object) để xác định tenant.
"10:00:03 10/09/2026" | req=e9956a8762ca45aa9a74c46f904db8555 | /predict/batch | item=1 | alert_id=A003 | tenant=vnd | model_version=v1.0 | http=200 | SUCCESS | rate=0.013200
```

- `alert_id`: giá trị `id`/`_id` của alert; `-` nếu không xác định được. `req` là
  mã riêng cho mỗi request, giúp đối chiếu các lần gửi lại cùng alert.
- Batch dùng chung thời gian và `req`, thêm `item` đánh số từ 1. `http` luôn là
  mã phản hồi của request: batch có lỗi từng alert vẫn có thể trả HTTP 200.
- `SUCCESS` ghi `rate`; lỗi ghi mã và lý do. JSON sai cú pháp ghi `JSON_INVALID`;
  lỗi cấu trúc do FastAPI chặn ghi `REQUEST_VALIDATION_ERROR`. Body không đọc được
  tạo một dòng log; batch đọc được nhưng bị từ chối toàn bộ đánh dấu lỗi mọi phần tử.
- Lỗi nội bộ trong batch trả HTTP 500: alert đang xử lý ghi `INTERNAL_ERROR`,
  phần tử trước đó ghi `REQUEST_FAILED`, phần tử chưa chạy ghi `NOT_PROCESSED`.
  Các kết quả chưa trả về không được ghi là `SUCCESS`.
- Log chỉ lưu thông tin nhận diện và kết quả, không lưu toàn bộ payload hay nội
  dung exception ngoài dự kiến. Ký tự xuống dòng/dấu `|` trong giá trị được escape.
  Khi đưa vào ES, cấu hình bộ thu log tách `alert_id` thành field và phân tích ngày
  theo `HH:mm:ss dd/MM/yyyy`, múi giờ `+07:00`; API không tự gửi log lên ES.
- File cũ là `alerts.log.1` đến `alerts.log.5` (file `.1` mới nhất). Nếu không ghi
  được file, dòng log được chuyển sang stderr để API tiếp tục trả kết quả.

Đọc log trực tiếp trên PowerShell:

```powershell
Get-Content .\logs\alerts.log -Encoding UTF8 -Tail 10 -Wait
```

Docker đã tạo `/app/logs` cho UID/GID `10001:10001`. Để giữ log khi thay container,
dùng volume riêng cho instance:

```bash
docker run --rm -p 8000:8000 -v soc-clf-logs:/app/logs soc-alert-classifier:2.1
```

Nếu bind-mount thư mục có sẵn, cấp quyền ghi cho UID/GID `10001:10001` trên host.
Chạy **một worker/process ghi mỗi file** để xoay log đúng; các instance khác dùng
file/volume riêng. Không cấu hình nhiều worker cùng ghi `ALERT_LOG_PATH`.

## Kiểm thử nhanh

Mở Swagger `http://<host>:<port>/docs`, chọn `POST /predict/batch` → *Try it out* → *Execute*
với body mẫu có sẵn: phần tử 1 trả `rate`, phần tử 2 (version `v9.9`) trả `UNKNOWN_MODEL_VERSION`.
Trên Windows, nếu pip lỗi đọc comment tiếng Việt trong requirements, dùng
`python -X utf8 -m pip install -r requirements.txt`.

## Lưu ý version

Artifact pickle bằng **scikit-learn 1.3.0**. `requirements.txt` đã pin đúng bộ
version. **Không nâng cấp tùy tiện** — pickle TF-IDF/Encoder nhạy version.
