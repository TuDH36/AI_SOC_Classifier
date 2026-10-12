"""
Kho artifact model theo (tenant, version).

Cấu trúc key GIỐNG NHAU cho MinIO và thư mục local:
    <MODEL_PREFIX>/<TENANT>/versions/<VERSION>/manifest.json
    <MODEL_PREFIX>/<TENANT>/versions/<VERSION>/{tfidf_char,tfidf_word,cat_encoder,lgbm_clf}.pkl

manifest.json khai `artifacts`: [{"file", "sha256", "size_bytes"}]. Mọi bộ artifact đều được kiểm
tra đủ file + kích thước + SHA-256 + đúng tenant/version TRƯỚC khi nạp; lỗi -> không nạp, không
fallback sang version khác.

MinioStore tải vào thư mục tạm trong MODEL_CACHE_DIR/<TENANT>/, kiểm tra xong mới đổi tên thành
MODEL_CACHE_DIR/<TENANT>/<VERSION>/ -> không bao giờ có bộ dở dang hoặc lẫn 2 version.
"""
import hashlib
import json
import logging
import os
import shutil
import tempfile
from typing import Any, Dict, List

from . import config
from .errors import ModelIntegrityError, ModelStoreUnavailableError, UnknownModelVersionError

log = logging.getLogger("uvicorn.error")

REQUIRED_ARTIFACTS = [
    config.TFIDF_CHAR_FILE,
    config.TFIDF_WORD_FILE,
    config.CAT_ENCODER_FILE,
    config.LGBM_FILE,
]


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def verify_dir(path: str, tenant: str, version: str) -> Dict[str, Any]:
    """Kiểm tra manifest + 4 artifact trong `path`. Trả manifest; sai -> ModelIntegrityError."""
    where = f"{tenant}/{version}"
    try:
        with open(os.path.join(path, config.MANIFEST_FILE), encoding="utf-8") as f:
            manifest = json.load(f)
    except (OSError, ValueError) as e:
        raise ModelIntegrityError(f"Không đọc được manifest của model {where}.",
                                  tenant=tenant, model_version=version) from e
    if str(manifest.get("model_version")) != version:
        raise ModelIntegrityError(
            f"Manifest {where} khai model_version='{manifest.get('model_version')}', không khớp.",
            tenant=tenant, model_version=version)
    if str(manifest.get("tenant", tenant)).lower() != tenant.lower():
        raise ModelIntegrityError(f"Manifest {where} thuộc tenant '{manifest.get('tenant')}'.",
                                  tenant=tenant, model_version=version)
    artifacts = {a.get("file"): a for a in manifest.get("artifacts") or [] if isinstance(a, dict)}
    for name in REQUIRED_ARTIFACTS:
        entry, file_path = artifacts.get(name), os.path.join(path, name)
        if not entry or not entry.get("sha256"):
            raise ModelIntegrityError(f"Manifest {where} không khai checksum cho {name}.",
                                      tenant=tenant, model_version=version)
        if not os.path.isfile(file_path):
            raise ModelIntegrityError(f"Thiếu artifact {name} của model {where}.",
                                      tenant=tenant, model_version=version)
        if entry.get("size_bytes") is not None and os.path.getsize(file_path) != int(entry["size_bytes"]):
            raise ModelIntegrityError(f"Sai kích thước {name} của model {where}.",
                                      tenant=tenant, model_version=version)
        if _sha256(file_path) != str(entry["sha256"]).lower():
            raise ModelIntegrityError(f"Sai SHA-256 {name} của model {where}.",
                                      tenant=tenant, model_version=version)
    return manifest


class ModelStore:
    """Giao diện chung. `tenant` truyền vào luôn là tên CHUẨN (đúng hoa/thường như trên store)."""

    def list_tenants(self) -> List[str]:
        raise NotImplementedError

    def fetch(self, tenant: str, version: str) -> str:
        """Trả thư mục local chứa bộ artifact ĐÃ KIỂM TRA của (tenant, version)."""
        raise NotImplementedError


class LocalStore(ModelStore):
    def __init__(self, root: str, prefix: str = config.MODEL_PREFIX):
        self.base = os.path.join(root, prefix) if prefix else root

    def list_tenants(self) -> List[str]:
        if not os.path.isdir(self.base):
            return []
        return sorted(n for n in os.listdir(self.base) if os.path.isdir(os.path.join(self.base, n, "versions")))

    def fetch(self, tenant: str, version: str) -> str:
        path = os.path.join(self.base, tenant, "versions", version)
        if not os.path.isfile(os.path.join(path, config.MANIFEST_FILE)):
            raise UnknownModelVersionError(f"Tenant '{tenant}' không có phiên bản model '{version}'.",
                                           tenant=tenant, model_version=version)
        verify_dir(path, tenant, version)
        return path


class MinioStore(ModelStore):
    def __init__(self, client: Any, bucket: str, prefix: str, cache_dir: str):
        self.client = client
        self.bucket = bucket
        self.prefix = prefix
        self.cache_dir = cache_dir

    @classmethod
    def from_config(cls) -> "MinioStore":
        import urllib3
        from minio import Minio

        if not config.MINIO_ENDPOINT:
            raise ValueError("MODEL_STORE=minio nhưng chưa cấu hình MINIO_ENDPOINT")
        http = urllib3.PoolManager(
            timeout=urllib3.Timeout(connect=config.MINIO_TIMEOUT_SECONDS, read=config.MINIO_TIMEOUT_SECONDS),
            retries=urllib3.Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504]),
        )
        client = Minio(config.MINIO_ENDPOINT, access_key=config.MINIO_ACCESS_KEY,
                       secret_key=config.MINIO_SECRET_KEY, secure=config.MINIO_SECURE, http_client=http)
        return cls(client, config.MINIO_BUCKET, config.MODEL_PREFIX, config.MODEL_CACHE_DIR)

    def _key(self, tenant: str, version: str, name: str) -> str:
        return f"{self.prefix}/{tenant}/versions/{version}/{name}"

    def _unavailable(self, e: Exception, **extra: Any) -> ModelStoreUnavailableError:
        # Không đưa str(e) ra response: có thể chứa endpoint/bucket nội bộ.
        log.warning("MinIO lỗi (%s): %s", type(e).__name__, e)
        return ModelStoreUnavailableError("Không đọc được kho model, thử lại sau.", **extra)

    def _cached_tenants(self) -> List[str]:
        if not os.path.isdir(self.cache_dir):
            return []
        return sorted(n for n in os.listdir(self.cache_dir) if os.path.isdir(os.path.join(self.cache_dir, n)))

    def list_tenants(self) -> List[str]:
        try:
            objects = self.client.list_objects(self.bucket, prefix=f"{self.prefix}/", recursive=False)
            return sorted(o.object_name[len(self.prefix) + 1:].strip("/") for o in objects if o.is_dir)
        except Exception as e:  # S3Error, urllib3 MaxRetryError...: đều coi là kho tạm không đọc được
            cached = self._cached_tenants()
            if cached:
                log.warning("Không liệt kê được tenant trên MinIO, dùng danh sách trong cache: %s", cached)
                return cached
            raise self._unavailable(e) from e

    def _download(self, tenant: str, version: str, name: str, dest_dir: str) -> None:
        from minio.error import S3Error

        try:
            self.client.fget_object(self.bucket, self._key(tenant, version, name), os.path.join(dest_dir, name))
        except S3Error as e:
            if e.code == "NoSuchKey" and name == config.MANIFEST_FILE:
                raise UnknownModelVersionError(f"Tenant '{tenant}' không có phiên bản model '{version}'.",
                                               tenant=tenant, model_version=version) from e
            if e.code == "NoSuchKey":
                raise ModelIntegrityError(f"Thiếu artifact {name} của model {tenant}/{version} trên kho.",
                                          tenant=tenant, model_version=version) from e
            raise self._unavailable(e, tenant=tenant, model_version=version) from e
        except Exception as e:
            raise self._unavailable(e, tenant=tenant, model_version=version) from e

    def fetch(self, tenant: str, version: str) -> str:
        final = os.path.join(self.cache_dir, tenant, version)
        if os.path.isdir(final):
            try:
                verify_dir(final, tenant, version)
                return final
            except ModelIntegrityError:
                log.warning("Cache model %s/%s hỏng, tải lại từ MinIO", tenant, version)
                shutil.rmtree(final, ignore_errors=True)

        os.makedirs(os.path.join(self.cache_dir, tenant), exist_ok=True)
        tmp = tempfile.mkdtemp(prefix=f".{version}-", dir=os.path.join(self.cache_dir, tenant))
        try:
            self._download(tenant, version, config.MANIFEST_FILE, tmp)
            for name in REQUIRED_ARTIFACTS:
                self._download(tenant, version, name, tmp)
            verify_dir(tmp, tenant, version)
            try:
                os.rename(tmp, final)
            except OSError:
                # Process khác vừa ghi xong cùng version -> dùng bản đó (đã kiểm tra lại bên dưới).
                if not os.path.isdir(final):
                    raise
            verify_dir(final, tenant, version)
            return final
        finally:
            if os.path.isdir(tmp):
                shutil.rmtree(tmp, ignore_errors=True)


def build_store() -> ModelStore:
    if config.MODEL_STORE == "minio":
        return MinioStore.from_config()
    if config.MODEL_STORE == "local":
        return LocalStore(config.MODELS_ROOT, config.MODEL_PREFIX)
    raise ValueError(f"MODEL_STORE không hợp lệ: '{config.MODEL_STORE}' (chỉ nhận 'minio' hoặc 'local')")
