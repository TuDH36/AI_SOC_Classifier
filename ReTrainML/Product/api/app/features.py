"""
Danh sách feature columns THAM CHIẾU của tenant VND (sao từ Code_thuan.ipynb cell 7).

⚠️ ĐÂY KHÔNG PHẢI list dùng chung cho mọi tenant. MỖI TENANT CÓ BỘ CỘT RIÊNG.
Lúc chạy (serving), bộ cột của mỗi tenant được lấy hoàn toàn riêng biệt:

  - cat_cols  : LẤY TỪ `cat_encoder.feature_names_in_` của chính model tenant đó
                (encoder tự mô tả nó đã fit trên cột nào — không cần khai ở đây).
  - text_cols : LẤY TỪ `manifest.json` -> "text_cols" của tenant đó (BẮT BUỘC khai;
                thiếu -> AlertClassifier báo lỗi, KHÔNG mượn list của tenant khác).

=> Các hằng số dưới chỉ là tham chiếu/đối chiếu cho VND và để seed manifest VND
   ban đầu. Code serving KHÔNG dùng chúng làm nguồn cột cho tenant nào.
"""

# ── Categorical: đưa vào OrdinalEncoder ─────────────────────────────────────
OLD_BASE_CAT_CANDIDATES = [
    "events.signature",
    "events.original_file_name",
    "events.dest",
    "events.src", "events.src_ip", "events.ip", "events.ipaddress2", "events.ipaddress",
    "events.logonprocessname", "events.logontype",
    "events.machinename",
    "events.url_domain",
    "events.host",
    "events.src_user",
    "events.subjectdomainname",
    "events.domain",
    "events._si",
    "events.violations",
    "events.vendor_product",
    "events.action", "events.method", "events.type",
    "events.response_code", "events.status", "events.status4",
    "events.source", "events.sourcetype", "events._sourcetype",
    "events.splunk_server", "events.index", "events.name",
    "events.accessmask",
    "events.analyzerdetectionmethod",
    "events.authenticationpackagename",
    "events.substatus",
    "events.threatactiontaken",
    "events.registry_value_data",
    "events.registry_value_type",
]

# ── Text: free-text -> `combined_text` -> TF-IDF ────────────────────────────
OLD_BASE_TEXT_CANDIDATES = [
    "events.command",
    "events.scriptblocktext",
    "events.image",
    "events.sourceimage",
    "events.targetimage",
    "events.targetfilename",
    "events.taskname",
    "events._raw",
    "events.processname",
    "events.process",
    "events.parent_process",
    "events.process_name", "events.process_path", "events.process_exec", "events.parent_process_path",
    "events.objectname",
    "events.details",
    "events.devicedescription",
    "events.request",
    "events.response",
    "events.uri",
    "events.eventdata_xml",
    "events.system_props_xml",
    "events.targetdomainname",
    "events.naturallangdescription",
    "events.compatibleids",
    "events.startfunction",
    "events.startmodule",
    "events.registry_hive",
    "events.registry_path",
    "events.registry_key_name",
]

# Toàn bộ cột "có ý nghĩa" mà model quan tâm. Mọi trường khác trong JSON đầu vào
# (id, hash, time, keyword, ...) sẽ bị bỏ qua — đúng tinh thần notebook.
ALL_FEATURE_COLUMNS = OLD_BASE_TEXT_CANDIDATES + OLD_BASE_CAT_CANDIDATES
