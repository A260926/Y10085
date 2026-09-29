"""Restricted JSON rule expressions.

Supported forms (no Python code is ever executed):
  {"op": "and", "args": [...]}          short-circuit boolean AND
  {"op": "or", "args": [...]}           short-circuit boolean OR
  {"op": "not", "arg": ...}             boolean negation
  {"op": "fallback", "args": [...]}     first argument that does not raise
  {"op": "exists", "field": "a.b"}      presence check (works on redacted fields)
  {"op": "is_null", "field": "a.b"}     explicit-null check
  {"op": "eq"|"ne"|"lt"|"le"|"gt"|"ge", "left": ..., "right": ...}
  {"field": "a.b"}                      field read
  any other JSON scalar                 constant
"""
from __future__ import annotations

import hashlib
import json

COMPARISONS = ("eq", "ne", "lt", "le", "gt", "ge")

REDACTED_MARKER = {"__redacted__": True}


class RuleError(Exception):
    """Evaluation failure with a machine-readable kind.

    kind is one of: missing, null, type_mismatch, forbidden, invalid_rule.
    """

    def __init__(self, kind: str, detail: str = ""):
        super().__init__(f"{kind}: {detail}")
        self.kind = kind
        self.detail = detail


def is_redacted(value) -> bool:
    return isinstance(value, dict) and value.get("__redacted__") is True


def normalize(rule) -> str:
    """Canonical JSON form of a rule."""
    return json.dumps(rule, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def digest_rule(rule) -> str:
    return digest_text(normalize(rule))


def _compatible(left, right) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool)
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return True
    return isinstance(left, str) and isinstance(right, str)


def _compare(op, left, right, at, trace):
    for value in (left, right):
        if value is None:
            raise RuleError("null", at)
    if not _compatible(left, right):
        raise RuleError(
            "type_mismatch",
            f"{type(left).__name__} vs {type(right).__name__} at {at}",
        )
    if op == "eq":
        result = left == right
    elif op == "ne":
        result = left != right
    elif op == "lt":
        result = left < right
    elif op == "le":
        result = left <= right
    elif op == "gt":
        result = left > right
    else:
        result = left >= right
    trace.append({"at": at, "op": op, "left": left, "right": right, "result": result})
    return result


class Evaluator:
    """Evaluates one rule against one request body, recording a full trace."""

    def __init__(self, data):
        self.data = data
        self.trace: list[dict] = []
        self.accessed: list[str] = []

    def run(self, rule) -> dict:
        try:
            outcome = self._truthy(self._eval(rule, "$"), "$")
            error = None
        except RuleError as exc:
            outcome, error = None, exc.kind
        return {
            "outcome": outcome,
            "error": error,
            "accessed_fields": list(self.accessed),
            "trace": list(self.trace),
        }

    def _truthy(self, value, at):
        if value is None:
            raise RuleError("null", at)
        return bool(value)

    def _lookup(self, path, at):
        self.accessed.append(path)
        current = self.data
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                self.trace.append(
                    {"at": at, "op": "field", "path": path, "status": "missing"}
                )
                raise RuleError("missing", path)
            current = current[part]
        if is_redacted(current):
            self.trace.append(
                {"at": at, "op": "field", "path": path, "status": "forbidden"}
            )
            raise RuleError("forbidden", path)
        status = "null" if current is None else "ok"
        self.trace.append({"at": at, "op": "field", "path": path, "status": status})
        return current

    def _try_lookup(self, path, at):
        try:
            return "ok", self._lookup(path, at)
        except RuleError as exc:
            return exc.kind, None

    def _operand(self, expr, at):
        if isinstance(expr, dict):
            if "op" in expr:
                return self._eval(expr, at)
            if "field" in expr:
                return self._lookup(expr["field"], at)
            raise RuleError("invalid_rule", f"bad operand at {at}")
        return expr

    def _eval(self, expr, at):
        if not isinstance(expr, dict):
            return expr
        if "field" in expr and "op" not in expr:
            return self._lookup(expr["field"], at)
        if "op" not in expr:
            raise RuleError("invalid_rule", f"no op at {at}")
        op = expr["op"]

        if op in ("and", "or"):
            args = expr.get("args") or []
            want = op == "or"
            for index, arg in enumerate(args):
                value = self._truthy(self._eval(arg, f"{at}.{op}[{index}]"), at)
                if value == want:
                    self.trace.append(
                        {"at": at, "op": op, "evaluated": index + 1,
                         "short_circuit": True}
                    )
                    return value
            self.trace.append(
                {"at": at, "op": op, "evaluated": len(args), "short_circuit": False}
            )
            return not want

        if op == "not":
            return not self._truthy(self._eval(expr["arg"], f"{at}.not"), at)

        if op == "fallback":
            last_error = None
            for index, arg in enumerate(expr.get("args") or []):
                try:
                    value = self._eval(arg, f"{at}.fallback[{index}]")
                    self.trace.append({"at": at, "op": "fallback", "selected": index})
                    return value
                except RuleError as exc:
                    last_error = exc
                    self.trace.append(
                        {"at": at, "op": "fallback", "skipped": index,
                         "error": exc.kind}
                    )
            raise last_error if last_error else RuleError("invalid_rule", "empty fallback")

        if op == "exists":
            status, _ = self._try_lookup(expr["field"], f"{at}.exists")
            return status != "missing"

        if op == "is_null":
            status, value = self._try_lookup(expr["field"], f"{at}.is_null")
            return status == "ok" and value is None

        if op in COMPARISONS:
            left = self._operand(expr.get("left"), f"{at}.left")
            right = self._operand(expr.get("right"), f"{at}.right")
            return _compare(op, left, right, at, self.trace)

        raise RuleError("invalid_rule", f"unknown op {op!r}")


def categorize(result_a: dict, result_b: dict) -> str:
    """Diff category between the two sides of a shadow evaluation."""
    if result_a["outcome"] != result_b["outcome"] or result_a["error"] != result_b["error"]:
        return "outcome"
    if (
        result_a["accessed_fields"] != result_b["accessed_fields"]
        or result_a["trace"] != result_b["trace"]
    ):
        return "path"
    return "none"
