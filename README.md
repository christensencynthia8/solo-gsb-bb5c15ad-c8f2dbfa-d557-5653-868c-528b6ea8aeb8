# 插件依赖兼容性审计 API

一个基于 **FastAPI + SQLite** 的插件依赖兼容性审计服务：

- 客户端提交插件清单（插件版本 + 依赖名 + SemVer 版本范围）；
- 服务解析**传递依赖**，在版本注册表上搜索可行的版本组合（回溯 + MRV 启发式）；
- **无解时不会只报第一个冲突**：遍历整棵搜索树，汇总所有本质不同的死路，
  对每条死路的约束集合做贪心极小化，返回**最小冲突链**以及链上**每一条约束的逐跳来源**；
- 所有审计结果持久化到 SQLite，支持按 ID 查询、列表过滤；
- 审计结果可导出为**可验证导出包**（确定性 JSONL + 逐条 sha256 + 整体 manifest 摘要 +
  gzip/Base64），并可随时回传校验完整性与顺序，任何字节或顺序改动都会被识别；
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

### 4. 导出可验证的审计包并校验

```bash
# 导出：audit_ids 按时间排序（1~100 个，不得重复），include_conflicts 控制是否包含冲突明细
curl -s -X POST http://localhost:8000/api/v1/audits/export-bundle \
  -H 'Content-Type: application/json' \
  -d '{"audit_ids":["<id1>","<id2>"],"include_conflicts":true}' > bundle.json

jq '{manifest_sha256, record_sha256}' bundle.json
```

```bash
# 校验：把导出响应中的 manifest / manifest_sha256 / jsonl 原样回传
jq '{manifest, manifest_sha256, jsonl}' bundle.json | \
  curl -s -X POST http://localhost:8000/api/v1/audits/verify-bundle \
    -H 'Content-Type: application/json' -d @- | jq
# => {"verified":true,"first_error_index":null,"error":null}
```

一条命令从列表到导出再到校验：

```bash
ids=$(curl -s 'http://localhost:8000/api/v1/audits?limit=5' | jq -c '[.items[].id]')
curl -s -X POST http://localhost:8000/api/v1/audits/export-bundle \
  -H 'Content-Type: application/json' \
  -d "{\"audit_ids\":$ids,\"include_conflicts\":true}" \
| jq '{manifest, manifest_sha256, jsonl}' \
| curl -s -X POST http://localhost:8000/api/v1/audits/verify-bundle \
    -H 'Content-Type: application/json' -d @- | jq
```

#### 导出包格式与校验规则

- 每条记录序列化为**规范 JSON**（键按字典序、紧凑分隔符、UTF-8），一行一条，行尾 `\n`；
- `record_sha256[i]` = 第 i 行（不含换行）的 sha256；`manifest.records` 同步记录
  `(index, audit_id, created_at, sha256)`；
- `manifest_sha256` = manifest 规范 JSON 的 sha256，是整体摘要与信任锚点；
- `bundle_gzip_base64` = `{"manifest":…,"jsonl":…}` 规范 JSON 的 gzip（`mtime=0`）+ Base64，
  相同输入产生字节级一致的输出；
- 校验依次检查：manifest 内部一致性 → JSONL 可解析 → 记录数 → 记录顺序
  （每行 `id` 与 manifest 声明的 `audit_id` 一致）→ 逐条 sha256 → 整体 manifest 摘要；
  任一失败返回 `verified=false`、`first_error_index`（记录级错误的 0 基下标，全局错误为
  `null`）与错误类型（`invalid_manifest` / `invalid_jsonl` / `record_count_mismatch` /
  `record_order_mismatch` / `record_hash_mismatch` / `manifest_hash_mismatch`），
  任何字节或顺序改动都会被识别；
- 导出与校验均**不写入数据库**（校验为纯计算）；未知 ID 返回 `404`，
  重复 ID 或列表越界（1~100）返回 `422`。

## API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET`  | `/health` | 健康检查（含数据库连通性与注册表包数量） |
| `POST` | `/api/v1/audits` | 提交清单进行审计，返回求解结果并落库（`201`） |
| `GET`  | `/api/v1/audits` | 审计记录列表，支持 `status` / `limit` / `offset` |
| `GET`  | `/api/v1/audits/{id}` | 查询单条审计的完整结果 |
| `POST` | `/api/v1/audits/export-bundle` | 按给定顺序导出可验证审计包（确定性 JSONL + 逐条 sha256 + manifest 摘要 + gzip Base64），不落库 |
| `POST` | `/api/v1/audits/verify-bundle` | 校验导出包的 manifest、记录顺序与各级摘要，返回首个错误位置与类型，不落库 |
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
（可行/无解/深层传递/多冲突枚举/预算保护）与全部 HTTP 接口（临时 SQLite，互不污染）。

## 项目结构

```
app/
  main.py       # FastAPI 路由与生命周期
  solver.py     # 回溯求解器、冲突极小化与来源链
  semver.py     # SemVer 2.0.0 与版本范围解析
  database.py   # SQLite 建表/注册表/审计记录
  bundle.py     # 可验证导出包：规范 JSONL、逐条/整体摘要与校验
  models.py     # Pydantic 请求/响应模型
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
