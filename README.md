# 配置影子演算室 (shadow-rules)

发布新规则前,把历史脱敏请求同时送进当前版本与候选版本,解释两边决策为何不同。

## 安装与运行

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
.venv/bin/pytest -q
.venv/bin/python -m shadow_rules --port 5215
```

打开 http://127.0.0.1:5215/ 可见「配置影子演算室」页面,预置批次
`seed:baseline-vs-candidate` 同时展示「不同结果」与「同结果不同路径」两类差异。

## 规则表达式(受限 JSON,不执行 Python)

- `{"op": "and"|"or", "args": [...]}` 短路布尔组合
- `{"op": "not", "arg": ...}`
- `{"op": "fallback", "args": [...]}` 依次尝试,取第一个不报错的结果
- `{"op": "exists"|"is_null", "field": "a.b"}`
- `{"op": "eq|ne|lt|le|gt|ge", "left": ..., "right": ...}`
- `{"field": "a.b"}` 字段读取;其余 JSON 标量为常量

求值记录访问字段、短路路径,并区分 `missing` / `null` / `type_mismatch` /
`forbidden`(秘密字段)。每次上传保存原文摘要、规范化形式与父版本。

## 关键行为

- 批次创建即冻结输入(规则摘要 + 请求摘要 → `input_digest`);幂等键相同且
  摘要相同返回原批次,摘要不同返回 409 冲突。
- 结果逐条落库后再写汇总;进程在写汇总前退出,重启只补缺失汇总,不重复追加结果。
- `secret` 字段按 schema(默认 `ssn`、`secret`、`profile.token`)在入库前脱敏,
  原值不进入日志、页面或导出;`exists` 仍可判断存在性。
- 决议(接受/阻止/限时例外)绑定批次修订,规则重传不自动沿用;乐观版本号
  处理并发冲突,409 返回双方理由;时钟可注入,例外到期自动失效。
- `GET /api/batches/{id}/export` 导出规则摘要、输入摘要、差异与决议,不含秘密。
