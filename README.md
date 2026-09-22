# 插件依赖兼容性审计 API

一个基于 **FastAPI + SQLite** 的插件依赖兼容性审计服务：

- 客户端提交插件清单（插件版本 + 依赖名 + SemVer 版本范围）；
- 服务解析**传递依赖**，在版本注册表上搜索可行的版本组合（回溯 + MRV 启发式）；
- **无解时不会只报第一个冲突**：遍历整棵搜索树，汇总所有本质不同的死路，
  对每条死路的约束集合做贪心极小化，返回**最小冲突链**以及链上**每一条约束的逐跳来源**；
- 所有审计结果持久化到 SQLite，支持按 ID 查询、列表过滤；
- 自带健康检查、OpenAPI 文档、示例注册表与一键 Docker Compose 启动。

## 一条命令启动

```bash
docker compose up --build
```

启动后：

| 用途 | 地址 |
| --- | --- |
| API 服务 | <http://localhost:8000> |
| Swagger UI（可直接发请求） | <http://localhost:8000/docs> |
| 健康检查 | <http://localhost:8000/health> |

首次启动会自动建表并把 `data/seed_registry.json` 里的示例包注册表写入 SQLite 卷（仅当注册表为空时播种）。

本地直接运行（需要 Python 3.11）：

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
# 数据库默认位于 ./data/audits.db
```

## 快速上手

### 1. 提交一份可行清单

```bash
curl -s -X POST http://localhost:8000/api/v1/audits \
  -H 'Content-Type: application/json' \
  -d '{"plugin_name":"megaplugin","plugin_version":"1.0.0","dependencies":[]}' | jq
```

关键返回字段：

```json
{
  "id": "…",
  "status": "feasible",
  "resolution": {
    "megaplugin": "1.0.0",
    "authkit": "1.2.0",
    "cachekit": "1.3.0",
    "core-lib": "1.5.0",
    "httpkit": "2.2.0",
    "loggerkit": "0.5.0"
  },
  "sources": [ /* 每个被选中版本都列出全部约束及来源链 */ ]
}
```

### 2. 提交一份无解清单（返回全部最小冲突链）

```bash
curl -s -X POST http://localhost:8000/api/v1/audits \
  -H 'Content-Type: application/json' \
  -d '{"dependencies":[
    {"name":"cachekit","range":"^1.0.0"},
    {"name":"loggerkit","range":"^0.9.0"}
  ]}' | jq '.conflicts[0]'
```

示例（节选）：

```json
{
  "package": "core-lib",
  "kind": "selection_conflict",
  "locked_version": "2.0.0",
  "message": "core-lib 已被锁定为 2.0.0，但该版本不满足来自 cachekit@1.3.0 的约束 …",
  "minimal_constraints": [
    {
      "package": "core-lib",
      "version_range": "^1.4.0",
      "source_chain": [
        {"package": "<manifest>", "version_range": "*", "version": null},
        {"package": "cachekit",  "version_range": "=1.3.0", "version": "1.3.0"}
      ]
    },
    {
      "package": "core-lib",
      "version_range": "^2.0.0",
      "source_chain": [
        {"package": "<manifest>", "version_range": "*", "version": null},
        {"package": "loggerkit", "version_range": "=0.9.0", "version": "0.9.0"}
      ]
    }
  ]
}
```

要点：

- `conflicts` 是**所有**本质不同冲突的列表（上限 50 条），按包名/类型/链长排序；
- `minimal_constraints` 是贪心极小化后的不可满足子集（去掉任何一条就可能消解冲突）；
- `all_constraints` 保留该死路点上该包的全部约束，便于诊断；
- `source_chain` 从 `<manifest>` 根跳开始，逐跳记录“谁的哪个版本要求了什么范围”，传递依赖来源完整可追溯。

### 3. 查询审计结果

```bash
# 列表（可选 status=feasible|infeasible|inconclusive、limit、offset）
curl -s 'http://localhost:8000/api/v1/audits?status=infeasible' | jq

# 详情
curl -s http://localhost:8000/api/v1/audits/<id> | jq
```

### 4. 导出可验证审计包并校验

把**按创建时间排序**的 `audit_id` 列表（1～100 个、不可重复）交给导出接口，
得到确定性的 JSONL 导出包：每条记录是规范化 JSON（键排序、紧凑、UTF-8），
附带逐行 `sha256`、整体 `payload_sha256`、清单摘要 `manifest_sha256`，
以及整个包 gzip 后的 Base64。导出与校验均为只读，不写入数据库。

```bash
# include_conflicts=false（默认）时行内不含 conflicts 字段
curl -s -X POST http://localhost:8000/api/v1/audits/export-bundle \
  -H 'Content-Type: application/json' \
  -d '{"audit_ids":["<id-早>","<id-晚>"],"include_conflicts":true}' \
  | jq '{record_count, manifest_sha256, records, jsonl}'
```

返回（节选）：

```json
{
  "record_count": 2,
  "manifest_sha256": "…",
  "records": [
    {"audit_id": "…", "sha256": "…（对该行字节）"},
    {"audit_id": "…", "sha256": "…"}
  ],
  "jsonl": "{…id=早…}\n{…id=晚…}\n",
  "manifest": {
    "format": "audit-jsonl-bundle",
    "format_version": "1.0",
    "include_conflicts": true,
    "record_count": 2,
    "payload_sha256": "…（对整个 JSONL 字节串）",
    "records": [ …同上… ],
    "manifest_sha256": "…（对清单自身规范化 JSON 的摘要）"
  },
  "gzip_base64": "…（信封 JSON 经 gzip、再 Base64，确定性压缩 mtime=0）"
}
```

同样的输入每次导出的 `jsonl` / `manifest_sha256` / `gzip_base64` 字节完全一致。
错误码：未知 ID 返回 `404`；重复 ID、列表为空或超过 100 个返回 `422`。

校验时直接回传 `gzip_base64`（也可以分别提交 `jsonl` + `manifest`）：

```bash
curl -s -X POST http://localhost:8000/api/v1/audits/verify-bundle \
  -H 'Content-Type: application/json' \
  -d "{\"gzip_base64\":\"$BUNDLE_B64\"}" | jq
```

通过时：

```json
{"verified": true, "first_error_index": -1, "error_type": null, "error_detail": null}
```

任何字节或记录顺序被改动都会失败，`first_error_index` 指向第一条出错的记录
（错误不针对记录时为 `-1`），`error_type` 给出错误类别：

| error_type | 含义 |
| --- | --- |
| `bundle_base64_invalid` / `bundle_gzip_invalid` / `bundle_envelope_invalid` | Base64 / gzip / 信封无法解码 |
| `malformed_manifest` | 清单缺字段或字段类型错误 |
| `manifest_digest_mismatch` | `manifest_sha256` 与清单内容不一致（清单被改动） |
| `unsupported_format` | 格式名或版本不支持 |
| `malformed_jsonl` | JSONL 不是字符串、未以换行结尾或含空行 |
| `record_count_mismatch` | JSONL 行数与清单记录数不一致 |
| `record_parse_error` | 某行不是合法 JSON |
| `record_id_missing` / `record_order_mismatch` | 记录缺少 id / id 与清单顺序不符（**顺序被改动**） |
| `record_digest_mismatch` | 某行 sha256 与清单不符（**行字节被改动**） |
| `conflicts_flag_mismatch` | 行内 conflicts 字段与 `include_conflicts` 标志不一致 |
| `payload_digest_mismatch` | `payload_sha256` 与整体 JSONL 不一致（换行等跨行字节改动） |

本地离线校验（不依赖服务端、不需要数据库）也可以直接用标准库：

```python
import base64, gzip, hashlib, json

def verify(gzip_base64):
    env = json.loads(gzip.decompress(base64.b64decode(gzip_base64)))
    m = env["manifest"]
    body = {k: v for k, v in m.items() if k != "manifest_sha256"}
    canon = lambda o: json.dumps(o, ensure_ascii=False, sort_keys=True,
                                 separators=(",", ":")).encode()
    assert hashlib.sha256(canon(body)).hexdigest() == m["manifest_sha256"]   # 清单
    lines = env["jsonl"].encode()[:-1].split(b"\n")
    assert len(lines) == m["record_count"]                                  # 记录数
    for i, line in enumerate(lines):
        assert json.loads(line)["id"] == m["records"][i]["audit_id"]        # 顺序
        assert hashlib.sha256(line).hexdigest() == m["records"][i]["sha256"]  # 逐条摘要
    assert hashlib.sha256(env["jsonl"].encode()).hexdigest() == m["payload_sha256"]  # 整体
```

## API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET`  | `/health` | 健康检查（含数据库连通性与注册表包数量） |
| `POST` | `/api/v1/audits` | 提交清单进行审计，返回求解结果并落库（`201`） |
| `GET`  | `/api/v1/audits` | 审计记录列表，支持 `status` / `limit` / `offset` |
| `GET`  | `/api/v1/audits/{id}` | 查询单条审计的完整结果 |
| `POST` | `/api/v1/audits/export-bundle` | 把已有审计结果打包为确定性、可验证的 JSONL 导出包（只读，不写库） |
| `POST` | `/api/v1/audits/verify-bundle` | 校验导出包：manifest、记录顺序、逐条摘要、整体摘要（不写库） |
| `GET`  | `/api/v1/registry/packages` | 查看注册表全部包与版本 |
| `PUT`  | `/api/v1/registry/packages/{name}` | 新增/覆盖一个包及其版本依赖 |

### 清单格式

```json
{
  "plugin_name": "可选，根插件名（需存在于注册表）",
  "plugin_version": "可选，与 plugin_name 同时提供，SemVer",
  "dependencies": [
    {"name": "authkit", "range": "^1.0.0"}
  ]
}
```

- 根插件在注册表中声明的依赖会作为传递依赖自动纳入解析；
- `dependencies` 是清单直接声明的根约束；
- 状态码：非法 SemVer / 范围返回 `422`，审计记录不存在返回 `404`。

### 支持的范围语法（npm 风格）

比较器 `>= > <= < =`、caret `^`、tilde `~`、X 范围（`1.x`、`1.2.*`、`*`）、
hyphen（`1.0.0 - 2.0.0`）、OR（`||`）、AND（空格），以及 SemVer 预发布可见性规则。

### 审计状态

- `feasible`：存在一组满足全部传递约束的版本，返回 `resolution` 与 `sources`；
- `infeasible`：搜索树已穷尽，无可行组合，返回全部最小冲突链；
- `inconclusive`：搜索节点超过预算（默认 20000），未能在预算内判定。

## 求解与冲突报告原理

- 搜索算法：约束传播 + MRV（候选交集最小的包优先）+ 时间顺序回溯，遍历完整搜索树；
- 冲突收集：每个死路记录一次，按“冲突类型 + 包 + 最小约束签名”去重；
- 极小化：对死路约束集合做逐个删除的贪心化简（range 冲突求空交集最小子集；
  锁定冲突求仍排除已锁版本的最小子集），保证输出的是最小冲突链；
- 来源链：每条约束记录从根跳 `<manifest>` 到提出者的完整路径
  （`谁@版本 -> 谁@版本 -> requires 包 范围`）。

## 测试

```bash
pip install -r requirements.txt
pytest -q
```

测试覆盖 SemVer 解析（含预发布排序与 npm 范围语义）、求解器
（可行/无解/深层传递/多冲突枚举/预算保护）、全部 HTTP 接口（临时 SQLite，互不污染），
以及导出包的确定性、重复/未知 ID 错误码与逐字节/顺序篡改识别。

## 项目结构

```
app/
  main.py       # FastAPI 路由与生命周期
  solver.py     # 回溯求解器、冲突极小化与来源链
  semver.py     # SemVer 2.0.0 与版本范围解析
  database.py   # SQLite 建表/注册表/审计记录
  models.py     # Pydantic 请求/响应模型
  bundle.py     # 可验证 JSONL 导出包的确定性构造与校验（sha256/gzip，纯内存）
data/
  seed_registry.json   # 示例注册表
tests/                  # pytest 测试套件
Dockerfile
docker-compose.yml
```

## 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `AUDIT_DB_PATH` | 容器内 `/data/audits.db`，本地 `./data/audits.db` | SQLite 数据库路径 |
| `AUDIT_SEED_PATH` | 容器内 `/app/data/seed_registry.json` | 首次启动的示例注册表 |
