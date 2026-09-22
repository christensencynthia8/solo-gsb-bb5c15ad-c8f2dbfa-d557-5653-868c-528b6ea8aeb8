r"""审计结果的可验证导出包：确定性 JSONL、逐条 sha256 与整体 manifest 摘要。

格式约定（导出与校验双方共用）：

- 每条审计记录序列化为**规范 JSON**（键按字典序、紧凑分隔符、保留非 ASCII 字符），
  一行一条记录，行尾 ``\n``；
- 逐条摘要 = 该行文本（不含行尾换行）UTF-8 字节的 sha256；
- 整体摘要 = manifest 规范 JSON 的 sha256；
- gzip 载荷为 ``{"manifest": ..., "jsonl": ...}`` 的规范 JSON，``mtime=0``
  保证相同输入产生相同字节。
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple

BUNDLE_FORMAT_VERSION = 1

# 校验错误类型（与 models.VerifyErrorType 保持一致）
ERROR_INVALID_MANIFEST = "invalid_manifest"
ERROR_INVALID_JSONL = "invalid_jsonl"
ERROR_RECORD_COUNT_MISMATCH = "record_count_mismatch"
ERROR_RECORD_ORDER_MISMATCH = "record_order_mismatch"
ERROR_RECORD_HASH_MISMATCH = "record_hash_mismatch"
ERROR_MANIFEST_HASH_MISMATCH = "manifest_hash_mismatch"


def canonical_json(obj: Any) -> str:
    """确定性 JSON 序列化：键排序、紧凑分隔符、保留非 ASCII 字符。"""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_hex(text: str) -> str:
    """文本 UTF-8 编码后的 sha256 十六进制摘要。"""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_record_line(result: Dict[str, Any], include_conflicts: bool) -> str:
    """把一条审计结果序列化为一行规范 JSON（可选剔除 conflicts）。"""
    record = dict(result)
    if not include_conflicts:
        record.pop("conflicts", None)
    return canonical_json(record)


def build_jsonl(lines: List[str]) -> str:
    r"""拼接 JSONL：每行以 ``\n`` 结尾。"""
    return "".join(line + "\n" for line in lines)


def split_jsonl(jsonl_text: str) -> List[str]:
    """拆分 JSONL；仅规范化掉末尾一个空行，其余空行由调用方判定为非法。"""
    lines = jsonl_text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def gzip_base64(payload: Dict[str, Any]) -> str:
    """规范 JSON -> gzip(mtime=0) -> Base64，保证字节级确定性。"""
    raw = canonical_json(payload).encode("utf-8")
    return base64.b64encode(gzip.compress(raw, compresslevel=9, mtime=0)).decode("ascii")


def verify_bundle(
    manifest: Dict[str, Any],
    manifest_sha256: str,
    jsonl_text: str,
) -> Tuple[bool, Optional[int], Optional[str]]:
    """依次校验 manifest、记录顺序、逐条摘要与整体摘要。

    返回 ``(verified, first_error_index, error)``；纯函数，不访问数据库。
    ``first_error_index`` 为首个出错记录的 0 基下标，全局错误为 None。
    """
    records = manifest.get("records", [])
    record_count = manifest.get("record_count", len(records))

    # 1. manifest 内部一致性：record_count 与 records 长度、index 连续性
    if record_count != len(records):
        return False, None, ERROR_INVALID_MANIFEST
    for i, rec in enumerate(records):
        if rec.get("index") != i:
            return False, None, ERROR_INVALID_MANIFEST

    # 2. JSONL 可解析，且每条记录都是带字符串 id 的对象
    lines = split_jsonl(jsonl_text)
    parsed: List[Dict[str, Any]] = []
    for i, line in enumerate(lines):
        if not line:
            return False, i, ERROR_INVALID_JSONL
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return False, i, ERROR_INVALID_JSONL
        if not isinstance(obj, dict) or not isinstance(obj.get("id"), str):
            return False, i, ERROR_INVALID_JSONL
        parsed.append(obj)

    # 3. 记录数与 manifest 声明一致
    if len(lines) != record_count:
        return False, None, ERROR_RECORD_COUNT_MISMATCH

    # 4. 记录顺序与 manifest 声明的 audit_id 序列一致
    for i, obj in enumerate(parsed):
        if obj["id"] != records[i].get("audit_id"):
            return False, i, ERROR_RECORD_ORDER_MISMATCH

    # 5. 逐条摘要与 manifest 声明一致
    for i, line in enumerate(lines):
        if sha256_hex(line) != records[i].get("sha256"):
            return False, i, ERROR_RECORD_HASH_MISMATCH

    # 6. 整体摘要：manifest 规范 JSON 的 sha256
    if sha256_hex(canonical_json(manifest)) != manifest_sha256:
        return False, None, ERROR_MANIFEST_HASH_MISMATCH

    return True, None, None
