"""HTTP 请求 / 响应的 Pydantic 模型。"""

from __future__ import annotations

from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator

from .semver import Version, VersionError, VersionRange


class DependencySpec(BaseModel):
    """清单中声明的一条依赖。"""

    name: str = Field(..., min_length=1, description="依赖包名")
    range: str = Field(..., min_length=1, description="SemVer 版本范围，如 ^1.2.0、>=1.0.0 <2.0.0")

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("依赖名不能为空")
        if any(ch.isspace() for ch in value):
            raise ValueError("依赖名不能包含空白字符")
        return value

    @field_validator("range")
    @classmethod
    def _validate_range(cls, value: str) -> str:
        try:
            VersionRange.parse(value)
        except VersionError as exc:
            raise ValueError(f"非法版本范围 {value!r}: {exc}") from exc
        return value


class ManifestIn(BaseModel):
    """客户端提交的插件清单。"""

    plugin_name: Optional[str] = Field(
        None, description="清单自身（根插件）名称；填写后会一并解析其注册表依赖"
    )
    plugin_version: Optional[str] = Field(None, description="根插件版本，需为合法 SemVer")
    dependencies: List[DependencySpec] = Field(default_factory=list)

    @field_validator("plugin_version")
    @classmethod
    def _validate_plugin_version(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        try:
            return str(Version.parse(value))
        except VersionError as exc:
            raise ValueError(f"非法插件版本 {value!r}: {exc}") from exc

    def validate_root_consistency(self) -> None:
        if (self.plugin_name is None) != (self.plugin_version is None):
            raise ValueError("plugin_name 与 plugin_version 必须同时提供或同时省略")


class PackageVersionIn(BaseModel):
    """注册表写入：单个版本。"""

    version: str
    dependencies: Dict[str, str] = Field(
        default_factory=dict, description="包名 -> SemVer 范围"
    )

    @field_validator("version")
    @classmethod
    def _validate_version(cls, value: str) -> str:
        try:
            return str(Version.parse(value))
        except VersionError as exc:
            raise ValueError(f"非法版本 {value!r}: {exc}") from exc

    @field_validator("dependencies")
    @classmethod
    def _validate_dependencies(cls, value: Dict[str, str]) -> Dict[str, str]:
        for name, spec in value.items():
            if not name.strip() or any(ch.isspace() for ch in name):
                raise ValueError(f"非法依赖名: {name!r}")
            try:
                VersionRange.parse(spec)
            except VersionError as exc:
                raise ValueError(f"依赖 {name} 的范围非法 {spec!r}: {exc}") from exc
        return value


class PackageIn(BaseModel):
    """注册表写入：整包。"""

    name: str = Field(..., min_length=1)
    versions: List[PackageVersionIn] = Field(..., min_length=1)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        value = value.strip()
        if not value or any(ch.isspace() for ch in value):
            raise ValueError("包名非法")
        return value


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    database: Literal["ok", "error"]
    packages: int


class AuditSummary(BaseModel):
    id: str
    created_at: str
    status: Literal["feasible", "infeasible", "inconclusive"]
    root_plugin: Optional[str]
    dependency_count: int
    conflict_count: int


class ConflictStepOut(BaseModel):
    package: str
    version_range: str
    version: Optional[str] = None


class ConstraintOut(BaseModel):
    package: str
    version_range: str
    source_chain: List[ConflictStepOut]


class ConflictOut(BaseModel):
    package: str
    kind: Literal["range_conflict", "selection_conflict", "package_missing"]
    locked_version: Optional[str] = None
    message: str
    minimal_constraints: List[ConstraintOut]
    all_constraints: List[ConstraintOut]


class ResolutionSourceOut(BaseModel):
    package: str
    version: str
    requested_by: List[ConflictStepOut]


class AuditResponse(BaseModel):
    id: str
    created_at: str
    status: Literal["feasible", "infeasible", "inconclusive"]
    root_plugin: Optional[str]
    root_version: Optional[str]
    explanation: str
    node_count: int
    resolution: Optional[Dict[str, str]]
    sources: Optional[List[ResolutionSourceOut]]
    conflicts: List[ConflictOut]


# ---------- 可验证导出包 ----------

class BundleExportIn(BaseModel):
    """导出包请求：按时间排序的审计 ID 列表（1～100）。"""

    audit_ids: List[str] = Field(
        ...,
        min_length=1,
        max_length=100,
        description="按创建时间排序的审计 ID 列表（1～100 个，不可重复）",
    )
    include_conflicts: bool = Field(
        False, description="导出的每条记录是否包含 conflicts 字段"
    )

    @field_validator("audit_ids")
    @classmethod
    def _validate_audit_ids(cls, value: List[str]) -> List[str]:
        for audit_id in value:
            if not isinstance(audit_id, str) or not audit_id.strip():
                raise ValueError("audit_id 不能为空")
        return value


class BundleRecordDigest(BaseModel):
    audit_id: str
    sha256: str


class BundleManifest(BaseModel):
    format: str
    format_version: str
    include_conflicts: bool
    record_count: int
    payload_sha256: str
    records: List[BundleRecordDigest]
    manifest_sha256: str


class BundleExportResponse(BaseModel):
    format: str
    format_version: str
    include_conflicts: bool
    record_count: int
    jsonl: str = Field(..., description="确定性 JSONL 文本，每行一条审计记录并以 \\n 结尾")
    records: List[BundleRecordDigest] = Field(..., description="每条记录的 sha256（对该行字节）")
    manifest: BundleManifest
    manifest_sha256: str = Field(..., description="清单自身（除该字段外）的 sha256")
    gzip_base64: str = Field(..., description="信封 JSON（manifest+jsonl）经 gzip 后的 Base64")


class BundleVerifyIn(BaseModel):
    """校验请求：二选一——直接传包的 Base64，或分别传 jsonl/manifest。"""

    gzip_base64: Optional[str] = Field(None, description="导出接口返回的 gzip Base64 包")
    jsonl: Optional[str] = Field(None, description="与 manifest 一起提交的 JSONL 文本")
    manifest: Optional[Dict[str, object]] = Field(None, description="与 jsonl 一起提交的清单")


class BundleVerifyResponse(BaseModel):
    verified: bool
    first_error_index: int = Field(
        ..., description="首个出错记录下标（0 起）；错误不针对记录时为 -1"
    )
    error_type: Optional[
        Literal[
            "bundle_base64_invalid",
            "bundle_gzip_invalid",
            "bundle_envelope_invalid",
            "malformed_manifest",
            "manifest_digest_mismatch",
            "unsupported_format",
            "malformed_jsonl",
            "record_count_mismatch",
            "record_parse_error",
            "record_id_missing",
            "record_order_mismatch",
            "record_digest_mismatch",
            "conflicts_flag_mismatch",
            "payload_digest_mismatch",
        ]
    ] = None
    error_detail: Optional[str] = None
