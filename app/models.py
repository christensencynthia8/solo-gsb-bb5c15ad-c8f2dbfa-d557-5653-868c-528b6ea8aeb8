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


class ExportBundleIn(BaseModel):
    """导出包请求：按时间排序的审计 ID 列表（1~100 个）。"""

    audit_ids: List[str] = Field(
        ...,
        min_length=1,
        max_length=100,
        description="按时间排序的审计 ID 列表，不得重复",
    )
    include_conflicts: bool = Field(True, description="导出记录中是否包含 conflicts 字段")

    @field_validator("audit_ids")
    @classmethod
    def _validate_unique_ids(cls, value: List[str]) -> List[str]:
        if len(set(value)) != len(value):
            raise ValueError("audit_ids 包含重复 ID")
        return value


class ManifestRecordOut(BaseModel):
    """manifest 中一条记录的摘要条目。"""

    index: int
    audit_id: str
    created_at: str
    sha256: str


class BundleManifest(BaseModel):
    """导出包 manifest：记录导出参数与逐条摘要。"""

    version: int
    generator: str
    include_conflicts: bool
    record_count: int
    records: List[ManifestRecordOut]


class ExportBundleResponse(BaseModel):
    manifest: BundleManifest
    manifest_sha256: str = Field(..., description="manifest 规范 JSON 的 sha256（整体摘要）")
    record_sha256: List[str] = Field(
        ..., description="每条 JSONL 记录（不含换行）的 sha256，与 manifest.records 一致"
    )
    jsonl: str = Field(..., description="确定性 JSONL 内容：每条记录一行规范 JSON，行尾 \\n")
    bundle_gzip_base64: str = Field(
        ..., description='{"manifest","jsonl"} 规范 JSON 的 gzip（mtime=0）+ Base64'
    )


class VerifyBundleIn(BaseModel):
    """校验请求：回传导出响应中的 manifest / manifest_sha256 / jsonl。"""

    manifest: BundleManifest
    manifest_sha256: str = Field(..., description="导出时返回的整体摘要，作为信任锚点")
    jsonl: str = Field(..., description="导出时返回的 JSONL 内容")


VerifyErrorType = Literal[
    "invalid_manifest",
    "invalid_jsonl",
    "record_count_mismatch",
    "record_order_mismatch",
    "record_hash_mismatch",
    "manifest_hash_mismatch",
]


class VerifyBundleResponse(BaseModel):
    verified: bool
    first_error_index: Optional[int] = Field(
        ..., description="首个出错记录的 0 基下标；manifest 级/全局错误为 null"
    )
    error: Optional[VerifyErrorType] = Field(..., description="错误类型；verified=true 时为 null")
