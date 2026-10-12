"""
ModelRegistry — quản lý model theo (tenant, version) cho nhiều tenant.

- Tenant: tra không phân biệt hoa/thường, quy về tên CHUẨN trên store (vd "vnd" -> "VND").
  Danh sách tenant được liệt kê lại theo chu kỳ TENANT_LIST_TTL_SECONDS -> thêm tenant không cần restart.
- Version: do BE gửi trong từng request; AI không tự chọn/áp dụng version.
- Lazy-load + cache RAM theo (tenant, version), tối đa MAX_LOADED_MODELS bộ (LRU). Bộ bị đẩy
  khỏi cache vẫn an toàn với request đang dùng (request giữ tham chiếu riêng).
- Mỗi (tenant, version) có khóa riêng: request cùng bộ chỉ tải/nạp 1 lần, tenant/version khác
  không phải chờ nhau.
"""
import threading
import time
from collections import OrderedDict
from typing import Callable, Dict, List, Optional, Tuple

from . import config
from .errors import APIError, ModelIntegrityError, ModelStoreUnavailableError, UnknownTenantError
from .model_store import ModelStore, build_store
from .pipeline import AlertClassifier

# Tenant lạ -> cho phép liệt kê lại store sớm hơn TTL, nhưng không quá 1 lần / khoảng này.
_MIN_REFRESH_SECONDS = 5.0

Key = Tuple[str, str]


class ModelRegistry:
    def __init__(
        self,
        store: Optional[ModelStore] = None,
        loader: Callable[[str, str], AlertClassifier] = AlertClassifier,
        max_loaded: Optional[int] = None,
        tenant_ttl: Optional[float] = None,
    ):
        self._store = store
        self._loader = loader
        self.max_loaded = max(1, max_loaded or config.MAX_LOADED_MODELS)
        self.tenant_ttl = config.TENANT_LIST_TTL_SECONDS if tenant_ttl is None else tenant_ttl
        self._models: "OrderedDict[Key, AlertClassifier]" = OrderedDict()
        self._key_locks: Dict[Key, threading.Lock] = {}
        self._lock = threading.Lock()
        self._tenants: Dict[str, str] = {}
        self._tenants_at: Optional[float] = None

    @property
    def store(self) -> ModelStore:
        # Tạo store khi cần lần đầu: cấu hình MinIO sai không làm API chết lúc khởi động.
        if self._store is None:
            self._store = build_store()
        return self._store

    # ── Tenant ──────────────────────────────────────────────────────────────
    def _tenant_map(self, force: bool = False) -> Dict[str, str]:
        now = time.monotonic()
        with self._lock:
            age = None if self._tenants_at is None else now - self._tenants_at
            stale = age is None or age > self.tenant_ttl or (force and age > _MIN_REFRESH_SECONDS)
            if stale:
                try:
                    names = self.store.list_tenants()
                except ModelStoreUnavailableError:
                    if self._tenants_at is None:
                        raise
                    names = list(self._tenants.values())  # store tạm lỗi -> dùng danh sách cũ
                self._tenants = {n.lower(): n for n in names}
                self._tenants_at = now
            return dict(self._tenants)

    def list_tenants(self) -> List[str]:
        try:
            return sorted(self._tenant_map().values())
        except APIError:
            return []

    def canonical_tenant(self, tenant: Optional[str]) -> str:
        if tenant is None or not str(tenant).strip():
            raise UnknownTenantError("Thiếu giá trị tenant.", available_tenants=self.list_tenants())
        key = str(tenant).strip().lower()
        tenants = self._tenant_map()
        if key not in tenants:
            tenants = self._tenant_map(force=True)
        if key not in tenants:
            raise UnknownTenantError(f"Tenant '{tenant}' không tồn tại.", tenant=tenant,
                                     available_tenants=sorted(tenants.values()))
        return tenants[key]

    # ── Model ───────────────────────────────────────────────────────────────
    def get(self, tenant: Optional[str], version: str) -> AlertClassifier:
        key = (self.canonical_tenant(tenant), version)
        with self._lock:
            model = self._models.get(key)
            if model is not None:
                self._models.move_to_end(key)
                return model
            key_lock = self._key_locks.setdefault(key, threading.Lock())
        with key_lock:
            with self._lock:
                model = self._models.get(key)
                if model is not None:
                    self._models.move_to_end(key)
                    return model
            path = self.store.fetch(*key)
            try:
                model = self._loader(key[0], path)
            except APIError:
                raise
            except Exception as e:
                raise ModelIntegrityError(f"Không nạp được model {key[0]}/{key[1]} ({type(e).__name__}).",
                                          tenant=key[0], model_version=key[1]) from e
            with self._lock:
                self._models[key] = model
                while len(self._models) > self.max_loaded:
                    self._models.popitem(last=False)
                self._key_locks.pop(key, None)
            return model

    def loaded_models(self) -> List[Key]:
        with self._lock:
            return list(self._models.keys())


_registry: Optional[ModelRegistry] = None
_registry_lock = threading.Lock()


def get_registry() -> ModelRegistry:
    global _registry
    if _registry is None:
        with _registry_lock:
            if _registry is None:
                _registry = ModelRegistry()
    return _registry
