"""演示预置：两条规则链 + 一批脱敏历史请求。"""
from __future__ import annotations

from typing import Any

from .service import Service

# 当前版本：vip 优先，命中即短路；age 缺失直接报错（无兜底）
CURRENT_RULE: dict[str, Any] = {
    "or": [
        {"field": "profile.vip"},
        {"and": [
            {"cmp": [{"field": "profile.age"}, ">=", {"lit": 18}]},
            {"cmp": [{"field": "risk.score"}, "<", {"lit": 80}]},
        ]},
    ]
}

# 候选版本：age 缺失时显式 fallback 到 false（同结果不同路径），
# 并允许 token 存在即放行（产生不同结果）
CANDIDATE_RULE: dict[str, Any] = {
    "or": [
        {"exists": "auth.token"},
        {"field": "profile.vip"},
        {"and": [
            {"fallback": [
                {"cmp": [{"field": "profile.age"}, ">=", {"lit": 18}]},
                {"lit": False},
            ]},
            {"cmp": [{"field": "risk.score"}, "<", {"lit": 80}]},
        ]},
    ]
}

SECRET_PATHS = ["auth.token"]

SEED_REQUESTS: list[dict[str, Any]] = [
    # 1) vip 短路：同结果（true）不同短路路径
    {"profile": {"vip": True, "age": 30}, "risk": {"score": 10},
     "auth": {"token": "tok-1"}},
    # 2) 普通成年人低风险：都为 true，字段轨迹不同
    {"profile": {"vip": False, "age": 25}, "risk": {"score": 20},
     "auth": {"token": "tok-2"}},
    # 3) 无 token 的未成年人：都为 false，路径不同
    {"profile": {"vip": False, "age": 15}, "risk": {"score": 20}, "auth": {}},
    # 4) 只有 token：当前 false / 候选 true —— 决策结果不同
    {"profile": {"vip": False, "age": 17}, "risk": {"score": 90},
     "auth": {"token": "tok-secret-4"}},
    # 5) age 缺失且无 token：当前 missing / 候选 fallback false —— 状态不同
    {"profile": {"vip": False}, "risk": {"score": 10}, "auth": {}},
]


def seed_if_empty(service: Service) -> str | None:
    if service.list_rules():
        return None
    cur = service.upload_rule("准入规则 v1（当前）", CURRENT_RULE, None)
    cand = service.upload_rule(
        "准入规则 v2（候选：token + age 兜底）", CANDIDATE_RULE, cur["id"]
    )
    batch = service.create_batch(
        idempotency_key="seed-demo-batch",
        current_rule_id=cur["id"],
        candidate_rule_id=cand["id"],
        secret_paths=list(SECRET_PATHS),
        requests=[{"request": r} for r in SEED_REQUESTS],
    )
    return batch["id"]
