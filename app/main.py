"""FastAPI 入口：插件依赖兼容性审计 API。"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse

from . import __version__
from .bundle import build_bundle, decode_bundle_base64, verify_bundle
from .database import (
    DEFAULT_DB_PATH,
    connect,
    count_audits,
    get_audit,
    init_db,
    insert_audit,
    list_audits,
    load_registry,
    package_count,
    upsert_package,
)
from .models import (
    AuditResponse,
    AuditSummary,
    BundleExportIn,
    BundleExportResponse,
    BundleVerifyIn,
    BundleVerifyResponse,
    HealthResponse,
    ManifestIn,
    PackageIn,
)
from .semver import VersionError
from .solver import Solver

SEED_PATH = os.environ.get("AUDIT_SEED_PATH", "/app/data/seed_registry.json")
MAX_LIMIT = 100


@asynccontextmanager
async def lifespan(_app: FastAPI):
    conn = connect()
    init_db(conn)
    # 仅在注册表为空时播种，避免覆盖用户通过 API 写入的数据
    if package_count(conn) == 0:
        seed_file = Path(SEED_PATH)
        if seed_file.is_file():
            seed = json.loads(seed_file.read_text(encoding="utf-8"))
            for name, payload in seed.items():
                upsert_package(conn, name, payload["versions"])
    conn.close()
    # 常驻连接（WAL 模式，FastAPI 同步路由）
    app.state.conn = connect(DEFAULT_DB_PATH)
    try:
        yield
    finally:
        app.state.conn.close()


app = FastAPI(
    title="插件依赖兼容性审计 API",
    version=__version__,
    lifespan=lifespan,
    description=(
        "提交插件清单（依赖名 + SemVer 范围），服务解析传递依赖、搜索可行版本组合；"
        "无解时返回全部最小冲突链及每条约束的来源链。"
    ),
)


def get_conn(request: Request) -> sqlite3.Connection:
    return request.app.state.conn  # type: ignore[no-any-return]


@app.exception_handler(VersionError)
async def _version_error_handler(_request: Request, exc: VersionError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.get("/", tags=["meta"])
def index() -> dict:
    return {
        "service": "plugin-dependency-audit",
        "version": __version__,
        "docs": "/docs",
        "endpoints": [
            "GET /health",
            "POST /api/v1/audits",
            "GET /api/v1/audits",
            "GET /api/v1/audits/{audit_id}",
            "POST /api/v1/audits/export-bundle",
            "POST /api/v1/audits/verify-bundle",
            "PUT /api/v1/registry/packages/{name}",
            "GET /api/v1/registry/packages",
        ],
    }


@app.get("/health", response_model=HealthResponse, tags=["meta"])
def health(request: Request) -> HealthResponse:
    db_ok = True
    packages = 0
    try:
        conn = get_conn(request)
        conn.execute("SELECT 1").fetchone()
        packages = package_count(conn)
    except Exception:
        db_ok = False
    return HealthResponse(
        status="ok" if db_ok else "degraded",
        database="ok" if db_ok else "error",
        packages=packages,
    )


@app.post(
    "/api/v1/audits",
    response_model=AuditResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["audits"],
)
def create_audit(manifest: ManifestIn, request: Request) -> AuditResponse:
    try:
        manifest.validate_root_consistency()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    conn = get_conn(request)
    registry = load_registry(conn)

    # 根插件版本必须存在于注册表（若声明了根插件）
    if manifest.plugin_name is not None and manifest.plugin_version not in registry.get(manifest.plugin_name, {}):
        raise HTTPException(
            status_code=422,
            detail=(
                f"根插件 {manifest.plugin_name}@{manifest.plugin_version} 不存在于注册表；"
                f"可用版本：{sorted(registry.get(manifest.plugin_name, {}), reverse=True)}"
            ),
        )

    solver = Solver(registry)
    result = solver.solve(
        root_dependencies=[(d.name, d.range) for d in manifest.dependencies],
        root_name=manifest.plugin_name,
        root_version=manifest.plugin_version,
    )

    audit_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    root_label = None
    if manifest.plugin_name:
        root_label = manifest.plugin_name
        if manifest.plugin_version:
            root_label = f"{manifest.plugin_name}@{manifest.plugin_version}"

    body = {
        "id": audit_id,
        "created_at": created_at,
        "status": result.status,
        "root_plugin": root_label,
        "root_version": manifest.plugin_version,
        "explanation": result.explanation,
        "node_count": result.node_count,
        "resolution": result.resolution,
        "sources": result.sources,
        "conflicts": result.conflicts,
    }
    insert_audit(
        conn,
        audit_id=audit_id,
        created_at=created_at,
        status=result.status,
        root_plugin=root_label,
        root_version=manifest.plugin_version,
        dependency_count=len(manifest.dependencies),
        manifest=manifest.model_dump(mode="json"),
        result=body,
        node_count=result.node_count,
    )
    return AuditResponse(**body)


@app.get("/api/v1/audits", response_model=dict, tags=["audits"])
def get_audits(
    request: Request,
    status_filter: Optional[str] = Query(None, alias="status", pattern="^(feasible|infeasible|inconclusive)$"),
    limit: int = Query(20, ge=1, le=MAX_LIMIT),
    offset: int = Query(0, ge=0),
) -> dict:
    conn = get_conn(request)
    rows = list_audits(conn, status=status_filter, limit=limit, offset=offset)
    total = count_audits(conn, status=status_filter)
    items = [
        AuditSummary(
            id=row["id"],
            created_at=row["created_at"],
            status=row["status"],
            root_plugin=row["root_plugin"],
            dependency_count=row["dependency_count"],
            conflict_count=row["conflict_count"] or 0,
        ).model_dump()
        for row in rows
    ]
    return {"total": total, "limit": limit, "offset": offset, "items": items}


@app.get("/api/v1/audits/{audit_id}", response_model=AuditResponse, tags=["audits"])
def get_audit_detail(audit_id: str, request: Request) -> AuditResponse:
    conn = get_conn(request)
    row = get_audit(conn, audit_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"审计记录不存在: {audit_id}")
    result = json.loads(row["result_json"])
    return AuditResponse(**result)


@app.post(
    "/api/v1/audits/export-bundle",
    response_model=BundleExportResponse,
    tags=["audits"],
)
def export_bundle(payload: BundleExportIn, request: Request) -> BundleExportResponse:
    """把已存在的审计结果打包成确定性、可验证的 JSONL 导出包。

    只读数据库，不写入任何内容。
    """
    audit_ids = payload.audit_ids
    duplicates = sorted({aid for aid in audit_ids if audit_ids.count(aid) > 1})
    if duplicates:
        raise HTTPException(
            status_code=422, detail=f"audit_ids 包含重复 ID: {duplicates}"
        )

    conn = get_conn(request)
    records: list[dict] = []
    for audit_id in audit_ids:
        row = get_audit(conn, audit_id)
        if row is None:
            raise HTTPException(status_code=404, detail=f"审计记录不存在: {audit_id}")
        result = json.loads(row["result_json"])
        # 复用现有响应模型序列化，保证字段形态与 GET 详情一致
        records.append(AuditResponse(**result).model_dump(mode="json"))

    bundle = build_bundle(records, include_conflicts=payload.include_conflicts)
    return BundleExportResponse(**bundle)


@app.post(
    "/api/v1/audits/verify-bundle",
    response_model=BundleVerifyResponse,
    tags=["audits"],
)
def verify_bundle_endpoint(payload: BundleVerifyIn) -> BundleVerifyResponse:
    """校验导出包：manifest、记录顺序、逐条摘要与整体摘要。

    纯内存计算，不读写数据库。任何字节或顺序改动都会返回 verified=false。
    """
    if payload.gzip_base64 is not None:
        envelope, error_type = decode_bundle_base64(payload.gzip_base64)
        if error_type is not None:
            return BundleVerifyResponse(
                verified=False, first_error_index=-1, error_type=error_type
            )
        verified, index, error_type, detail = verify_bundle(
            envelope["manifest"], envelope["jsonl"]
        )
        return BundleVerifyResponse(
            verified=verified,
            first_error_index=index,
            error_type=error_type,
            error_detail=detail,
        )

    if payload.jsonl is not None and payload.manifest is not None:
        verified, index, error_type, detail = verify_bundle(
            payload.manifest, payload.jsonl
        )
        return BundleVerifyResponse(
            verified=verified,
            first_error_index=index,
            error_type=error_type,
            error_detail=detail,
        )

    raise HTTPException(
        status_code=422,
        detail="必须提供 gzip_base64，或同时提供 jsonl 与 manifest",
    )


@app.put("/api/v1/registry/packages/{name}", response_model=dict, tags=["registry"])
def put_package(name: str, payload: PackageIn, request: Request) -> dict:
    if name != payload.name:
        raise HTTPException(status_code=422, detail="路径包名与请求体 name 不一致")
    conn = get_conn(request)
    upsert_package(
        conn,
        name,
        [{"version": v.version, "dependencies": v.dependencies} for v in payload.versions],
    )
    return {
        "name": name,
        "versions": [v.version for v in payload.versions],
        "stored": len(payload.versions),
    }


@app.get("/api/v1/registry/packages", response_model=dict, tags=["registry"])
def list_packages(request: Request) -> dict:
    conn = get_conn(request)
    registry = load_registry(conn)
    return {
        "packages": {
            name: {"versions": sorted(versions.keys(), reverse=True), "version_count": len(versions)}
            for name, versions in sorted(registry.items())
        }
    }
