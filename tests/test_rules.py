"""Evaluator semantics: short-circuit traces, null vs missing, secrets."""
from shadow_rules.redact import sanitize
from shadow_rules.rules import Evaluator


def run(rule, body):
    return Evaluator(body).run(rule)


def test_and_short_circuits_and_records_path():
    rule = {"op": "and", "args": [
        {"op": "eq", "left": {"field": "a"}, "right": 1},
        {"op": "eq", "left": {"field": "b"}, "right": 2},
    ]}
    result = run(rule, {"a": 0, "b": 2})
    assert result["outcome"] is False
    # second field never touched thanks to short-circuit
    assert result["accessed_fields"] == ["a"]
    gate = [s for s in result["trace"] if s["op"] == "and"][0]
    assert gate["short_circuit"] is True
    assert gate["evaluated"] == 1


def test_or_short_circuits_on_first_true():
    rule = {"op": "or", "args": [
        {"op": "eq", "left": {"field": "a"}, "right": 1},
        {"op": "eq", "left": {"field": "b"}, "right": 2},
    ]}
    result = run(rule, {"a": 1, "b": 9})
    assert result["outcome"] is True
    assert result["accessed_fields"] == ["a"]


def test_missing_null_and_type_mismatch_are_distinct():
    rule = {"op": "le", "left": {"field": "x"}, "right": 5}
    missing = run(rule, {})
    assert missing["error"] == "missing"
    assert missing["trace"][0]["status"] == "missing"

    explicit_null = run(rule, {"x": None})
    assert explicit_null["error"] == "null"
    assert explicit_null["trace"][0]["status"] == "null"

    mismatch = run(rule, {"x": "oops"})
    assert mismatch["error"] == "type_mismatch"
    assert missing["error"] != explicit_null["error"] != mismatch["error"]


def test_fallback_recovers_from_missing_field():
    rule = {"op": "fallback", "args": [
        {"op": "le", "left": {"field": "score"}, "right": 700},
        False,
    ]}
    result = run(rule, {})
    assert result["outcome"] is False
    assert result["error"] is None
    skipped = [s for s in result["trace"] if s.get("skipped") == 0]
    assert skipped and skipped[0]["error"] == "missing"


def test_secret_field_exists_but_value_forbidden():
    body = sanitize({"ssn": "123-45-6789", "age": 30}, ["ssn"])
    exists = run({"op": "exists", "field": "ssn"}, body)
    assert exists["outcome"] is True

    read = run({"op": "eq", "left": {"field": "ssn"}, "right": "x"}, body)
    assert read["error"] == "forbidden"
    # the raw secret never appears anywhere in the trace
    assert "123-45-6789" not in str(read)


def test_no_python_execution_only_declarative_ops():
    result = run({"op": "import_os_system"}, {})
    assert result["error"] == "invalid_rule"
