import pytest

from shadow_rules.engine import (
    RuleError,
    compile_rule,
    evaluate,
)


def test_and_short_circuit_trace():
    rule = compile_rule({"and": [
        {"cmp": [{"field": "a"}, "==", {"lit": 1}]},
        {"field": "b"},
    ]})
    out = evaluate(rule, {"a": 1, "b": True})
    assert out.value is True

    out = evaluate(rule, {"a": 2, "b": True})
    assert out.value is False
    assert out.accessed == ["a"]  # 第二项未求值
    assert {"op": "and", "index": 1, "reason": "false"} in out.short_circuits


def test_or_short_circuit_trace():
    rule = compile_rule({"or": [
        {"field": "a"},
        {"field": "b"},
    ]})
    out = evaluate(rule, {"a": True, "b": False})
    assert out.value is True
    assert out.accessed == ["a"]
    assert {"op": "or", "index": 1, "reason": "true"} in out.short_circuits


def test_missing_null_type_error_are_distinct():
    rule = compile_rule({"cmp": [{"field": "x"}, "==", {"lit": 1}]})
    assert evaluate(rule, {}).status == "missing"
    assert evaluate(rule, {"x": None}).status == "null"
    assert evaluate(rule, {"x": "1"}).status == "ok"  # == 跨类型直接 false

    lt = compile_rule({"cmp": [{"field": "x"}, "<", {"lit": 1}]})
    assert evaluate(lt, {"x": "1"}).status == "type_error"


def test_explicit_null_differs_from_missing():
    req_null = {"x": None}
    req_gone = {}
    is_null = compile_rule({"is_null": "x"})
    is_missing = compile_rule({"is_missing": "x"})
    exists = compile_rule({"exists": "x"})

    assert evaluate(is_null, req_null).value is True
    assert evaluate(is_null, req_gone).value is False
    assert evaluate(is_missing, req_null).value is False
    assert evaluate(is_missing, req_gone).value is True
    assert evaluate(exists, req_null).value is True
    assert evaluate(exists, req_gone).value is False


def test_fallback_explicit_only():
    rule = compile_rule({"fallback": [
        {"cmp": [{"field": "x"}, ">=", {"lit": 10}]},
        {"lit": False},
    ]})
    out = evaluate(rule, {})
    assert out.value is False
    assert out.status == "ok"
    fallback_events = [e for e in out.short_circuits if e.get("op") == "fallback"]
    assert any(e.get("reason") == "missing" for e in fallback_events)
    assert any(e.get("reason") == "used" for e in fallback_events)

    # 第一项正常为 false 时不应顺延（fallback 只处理缺字段/类型不匹配）
    out_ok = evaluate(rule, {"x": 5})
    assert out_ok.value is False
    assert not any(e.get("reason") == "used" for e in out_ok.short_circuits)


def test_secret_value_never_read_but_existence_works():
    rule = compile_rule({"or": [
        {"exists": "auth.token"},
        {"field": "flag"},
    ]})
    present = evaluate(rule, {"auth": {"token": "TOP-SECRET-123"}, "flag": False},
                       ["auth.token"])
    assert present.value is True
    assert present.accessed == ["auth.token"]
    assert present.secret_access == ["auth.token"]

    gone = evaluate(rule, {"auth": {}, "flag": False}, ["auth.token"])
    assert gone.value is False

    # 直接读取 secret 值 -> 类型不匹配，值不参与运算
    direct = compile_rule({"field": "auth.token"})
    out = evaluate(direct, {"auth": {"token": "TOP-SECRET-123"}}, ["auth.token"])
    assert out.status == "type_error"


@pytest.mark.parametrize("bad", [
    {"eval": "1+1"},
    {"field": 123},
    {"and": []},
    {"cmp": [{"lit": 1}, "??", {"lit": 2}]},
    {"unknown_op": 1},
    True,
    {"lit": {"x": 1}},
])
def test_rejected_expressions(bad):
    with pytest.raises(RuleError):
        compile_rule(bad)
