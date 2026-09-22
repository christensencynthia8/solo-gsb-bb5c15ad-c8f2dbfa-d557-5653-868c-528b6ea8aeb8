"""可验证导出包：导出确定性、摘要一致性、篡改与乱序检测、错误码。"""

import base64
import gzip
import hashlib
import json


def _canonical(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _create_audit(client, payload=None):
    resp = client.post(
        "/api/v1/audits",
        json=payload
        or {
            "plugin_name": "megaplugin",
            "plugin_version": "1.0.0",
            "dependencies": [],
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _export(client, ids, include_conflicts=True):
    resp = client.post(
        "/api/v1/audits/export-bundle",
        json={"audit_ids": ids, "include_conflicts": include_conflicts},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _verify(client, bundle, jsonl=None, manifest=None, manifest_sha256=None):
    resp = client.post(
        "/api/v1/audits/verify-bundle",
        json={
            "manifest": manifest if manifest is not None else bundle["manifest"],
            "manifest_sha256": (
                manifest_sha256 if manifest_sha256 is not None else bundle["manifest_sha256"]
            ),
            "jsonl": jsonl if jsonl is not None else bundle["jsonl"],
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_export_bundle_deterministic_and_self_consistent(client):
    ids = [_create_audit(client) for _ in range(2)]
    first = _export(client, ids)
    second = _export(client, ids)
    assert first == second, "相同输入必须产生字节级一致的导出包"

    lines = first["jsonl"].split("\n")
    assert lines[-1] == "", "每条记录以换行结尾"
    lines = lines[:-1]
    assert len(lines) == 2
    for line, audit_id, digest in zip(lines, ids, first["record_sha256"]):
        assert _sha(line) == digest, "逐条摘要必须等于该行（不含换行）的 sha256"
        assert json.loads(line)["id"] == audit_id

    manifest = first["manifest"]
    assert manifest["record_count"] == 2
    assert manifest["include_conflicts"] is True
    assert [r["index"] for r in manifest["records"]] == [0, 1]
    assert [r["audit_id"] for r in manifest["records"]] == ids
    assert [r["sha256"] for r in manifest["records"]] == first["record_sha256"]
    assert _sha(_canonical(manifest)) == first["manifest_sha256"]

    # gzip+Base64 载荷可解码，且内容与响应字段一致
    payload = json.loads(gzip.decompress(base64.b64decode(first["bundle_gzip_base64"])).decode("utf-8"))
    assert payload["manifest"] == manifest
    assert payload["jsonl"] == first["jsonl"]


def test_export_include_conflicts_flag(client):
    audit_id = _create_audit(
        client,
        {
            "dependencies": [
                {"name": "cachekit", "range": "^1.0.0"},
                {"name": "loggerkit", "range": "^0.9.0"},
            ]
        },
    )
    with_conflicts = _export(client, [audit_id], include_conflicts=True)
    without = _export(client, [audit_id], include_conflicts=False)

    record_with = json.loads(with_conflicts["jsonl"].split("\n")[0])
    record_without = json.loads(without["jsonl"].split("\n")[0])
    assert record_with["conflicts"], "include_conflicts=true 时必须包含冲突明细"
    assert "conflicts" not in record_without, "include_conflicts=false 时不得包含 conflicts"
    assert with_conflicts["manifest"]["include_conflicts"] is True
    assert without["manifest"]["include_conflicts"] is False

    # 两种导出都可独立通过校验
    assert _verify(client, with_conflicts)["verified"] is True
    assert _verify(client, without)["verified"] is True


def test_export_unknown_audit_404(client):
    resp = client.post(
        "/api/v1/audits/export-bundle", json={"audit_ids": ["no-such-id"]}
    )
    assert resp.status_code == 404


def test_export_duplicate_ids_422(client):
    audit_id = _create_audit(client)
    resp = client.post(
        "/api/v1/audits/export-bundle", json={"audit_ids": [audit_id, audit_id]}
    )
    assert resp.status_code == 422


def test_export_id_list_size_limits(client):
    assert client.post("/api/v1/audits/export-bundle", json={"audit_ids": []}).status_code == 422
    assert (
        client.post(
            "/api/v1/audits/export-bundle",
            json={"audit_ids": [f"id-{i}" for i in range(101)]},
        ).status_code
        == 422
    )


def test_verify_bundle_roundtrip_ok(client):
    ids = [_create_audit(client) for _ in range(3)]
    bundle = _export(client, ids)
    body = _verify(client, bundle)
    assert body == {"verified": True, "first_error_index": None, "error": None}


def test_verify_detects_single_byte_tamper(client):
    ids = [_create_audit(client) for _ in range(2)]
    bundle = _export(client, ids)
    lines = bundle["jsonl"].split("\n")
    # 修改第二条记录的一个字节（保持 JSON 合法、id 不变）
    assert '"status":"feasible"' in lines[1]
    lines[1] = lines[1].replace('"status":"feasible"', '"status":"Feasible"', 1)
    body = _verify(client, bundle, jsonl="\n".join(lines))
    assert body["verified"] is False
    assert body["error"] == "record_hash_mismatch"
    assert body["first_error_index"] == 1


def test_verify_detects_record_order_swap(client):
    ids = [_create_audit(client) for _ in range(2)]
    bundle = _export(client, ids)
    lines = bundle["jsonl"].split("\n")[:-1]
    swapped = "\n".join([lines[1], lines[0]]) + "\n"
    body = _verify(client, bundle, jsonl=swapped)
    assert body["verified"] is False
    assert body["error"] == "record_order_mismatch"
    assert body["first_error_index"] == 0


def test_verify_detects_record_count_mismatch(client):
    ids = [_create_audit(client) for _ in range(2)]
    bundle = _export(client, ids)
    only_first = bundle["jsonl"].split("\n")[0] + "\n"
    body = _verify(client, bundle, jsonl=only_first)
    assert body["verified"] is False
    assert body["error"] == "record_count_mismatch"


def test_verify_detects_invalid_jsonl(client):
    bundle = _export(client, [_create_audit(client)])
    body = _verify(client, bundle, jsonl="{not-json}\n")
    assert body["verified"] is False
    assert body["error"] == "invalid_jsonl"
    assert body["first_error_index"] == 0


def test_verify_detects_manifest_record_tamper(client):
    bundle = _export(client, [_create_audit(client)])
    manifest = json.loads(json.dumps(bundle["manifest"]))
    manifest["records"][0]["sha256"] = "0" * 64
    body = _verify(client, bundle, manifest=manifest)
    assert body["verified"] is False
    assert body["error"] == "record_hash_mismatch"
    assert body["first_error_index"] == 0


def test_verify_detects_manifest_hash_tamper(client):
    bundle = _export(client, [_create_audit(client)])
    flipped = ("0" if bundle["manifest_sha256"][0] != "0" else "1") + bundle["manifest_sha256"][1:]
    body = _verify(client, bundle, manifest_sha256=flipped)
    assert body["verified"] is False
    assert body["error"] == "manifest_hash_mismatch"
    assert body["first_error_index"] is None


def test_export_and_verify_do_not_write_db(client):
    ids = [_create_audit(client) for _ in range(2)]
    before = client.get("/api/v1/audits").json()["total"]
    bundle = _export(client, ids)
    _verify(client, bundle)
    after = client.get("/api/v1/audits").json()["total"]
    assert after == before, "导出与校验均不得写入数据库"
