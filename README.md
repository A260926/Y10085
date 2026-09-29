# 配置影子演算室（Shadow Rules）

规则发布前，把同一批历史请求并行送入**当前版本**与**候选版本**，
逐条记录两边的决策、访问字段、短路路径与差异类别，并对差异写决议。

* FastAPI + SQLite（无外部服务），单页浏览器界面
* 规则是仓库自定义的**受限 JSON 表达式**，不调用 `eval`/`exec`，不能执行 Python
* 每次上传保存：原文 SHA256、规范化形式摘要、父版本
* 批次开始即冻结输入；幂等键重复启动返回原批次，键同输入不同返回 409
* 崩溃恢复只补缺失结果与汇总，不重复追加
* secret 字段按 schema 脱敏，规则只能判断“存在/不存在/显式 null”
* 决议支持接受 / 阻止 / 限时例外，乐观锁版本号处理并发，冲突时返回双方理由

## 安装与演示

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/pytest -q
.venv/bin/python -m shadow_rules --port 5215
```

打开 <http://127.0.0.1:5215/>，页面标题为“配置影子演算室”。
首次启动会预置两条规则版本与一批历史请求（幂等键 `seed-demo-batch`），
其中同时包含**同结果不同路径**与**决策结果不同**两类差异。

可选参数：`--host`、`--port`、`--db`（默认 `shadow_rules.db`）。

## 受限 JSON 表达式

顶层必须返回布尔值。合法节点：

| 节点 | 含义 |
| --- | --- |
| `{"lit": <bool\|number\|string\|null>}` | 字面量 |
| `{"field": "a.b.0"}` | 读取字段（点路径，数字索引数组） |
| `{"not": <expr>}` | 布尔非 |
| `{"and": [expr, ...]}` / `{"or": [...]}` | 短路布尔组合 |
| `{"cmp": [expr, "=="\|"!="\|"<"\|"<="\|">"\|">=", expr]}` | 比较 |
| `{"exists": "path"}` | 字段存在（显式 null 也算存在） |
| `{"is_missing": "path"}` / `{"is_null": "path"}` | 区分缺失与显式 null |
| `{"fallback": [expr, expr, ...]}` | 仅在缺字段/类型不匹配时显式顺延 |

三态区分：`ok`、`missing`（缺字段）、`null`（显式 null）、`type_error`（类型不匹配）。
`==`/`!=` 跨类型直接返回 false/true，其余比较跨类型为类型不匹配。
`fallback` 不会在第一项“正常返回 false”时顺延，只处理异常。

## 主要 API

* `POST /api/rules`：`{name, rule, parent_id?}` → 返回原文摘要与规范摘要
* `POST /api/batches`：`{idempotency_key?, current_rule_id, candidate_rule_id, secret_paths[], requests[{request}]}`
  * 相同幂等键 + 相同输入摘要：`200` 返回原批次（`reused: true`）
  * 相同幂等键 + 不同输入摘要：`409 idempotency_input_mismatch`
* `GET /api/batches/{id}`：逐条结果、字段轨迹、短路路径、决议
* `PUT /api/batches/{id}/requests/{rid}/decision`：
  `{verdict: accept|block|exception, reason, expires_at?, version}`
  * 无决议时 `version=0`；每次成功提交版本 +1
  * 过期版本返回 `409 decision_version_conflict`，含双方 verdict/reason
* `GET /api/batches/{id}/export`：规则摘要 + 输入摘要 + 差异 + 决议（不含任何 secret 原值）

## 测试

`tests/` 覆盖：短路访问轨迹、null 与缺失三态、显式 fallback、崩溃恢复
（结果已写/未写汇总两种崩溃点）、幂等冲突、secret 全表面泄露扫描
（API、页面、导出、SQLite 文件、stdout/stderr）、决议并发冲突与限时例外到期
（`FakeClock` 可注入时钟）、预置页面。
