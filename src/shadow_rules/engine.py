"""受限 JSON 表达式规则引擎。

表达式只允许以下几种形式，全部为 JSON 可序列化结构：

* {"lit": <bool|number|string|null>}
* {"field": "a.b.0"}                     # 读取字段
* {"not": <expr>}
* {"and": [<expr>, ...]} / {"or": [...]} # 短路布尔组合
* {"cmp": [<expr>, "=="|"!="|"<"|"<="|">"|">=", <expr>]}
* {"exists": <path>}                     # 仅判断字段是否存在
* {"is_missing": <path>} / {"is_null": <path>}
* {"fallback": [<expr>, <expr>, ...]}    # 显式兜底：缺字段/类型不匹配时顺延

引擎永远不调用 eval/exec，不接受 Python 代码；被 schema 标记为 secret 的
路径只能用于 exists/is_missing/is_null 判断，值不可读出。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

REDACTED = "\u2758SECRET\u2758"  # 原值不会出现的脱敏占位

VALID_OPS = {"==", "!=", "<", "<=", ">", ">="}
MAX_NODES = 200


class RuleError(ValueError):
    """规则结构本身不合法（上传时拒绝）。"""


class ExpressionError(Exception):
    """求值期问题：缺字段 / 显式 null / 类型不匹配。"""

    def __init__(self, status: str, message: str, path: str | None = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.path = path


def missing(path: str) -> ExpressionError:
    return ExpressionError("missing", f"字段缺失: {path}", path)


def null_error(path: str) -> ExpressionError:
    return ExpressionError("null", f"字段为显式 null: {path}", path)


def type_error(path: str | None, message: str) -> ExpressionError:
    where = f"{path}: " if path else ""
    return ExpressionError("type_error", f"类型不匹配: {where}{message}", path)


@dataclass
class Trace:
    accessed: list[str] = field(default_factory=list)
    secret_access: list[str] = field(default_factory=list)
    short_circuits: list[dict[str, Any]] = field(default_factory=list)

    def touch(self, path: str, secret: bool, why: str) -> None:
        if path not in self.accessed:
            self.accessed.append(path)
        if secret:
            if path not in self.secret_access:
                self.secret_access.append(path)
        else:
            self.short_circuits.append({"op": "access", "path": path, "reason": why})


@dataclass
class Outcome:
    value: Any
    status: str
    accessed: list[str]
    secret_access: list[str]
    short_circuits: list[dict[str, Any]]
    error: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "status": self.status,
            "accessed": self.accessed,
            "secret_access": self.secret_access,
            "short_circuits": self.short_circuits,
            "error": self.error,
        }


def _path_parts(path: Any) -> list[str]:
    if not isinstance(path, str) or not path:
        raise RuleError("字段路径必须是非空字符串")
    if any(part == "" for part in path.split(".")):
        raise RuleError(f"非法字段路径: {path!r}")
    return path.split(".")


def validate(expr: Any, depth: int = 0) -> None:
    if depth > 40:
        raise RuleError("表达式嵌套过深")
    if isinstance(expr, bool) or not isinstance(expr, dict):
        raise RuleError('表达式节点必须是对象（原始布尔值请用 {"lit": ...}）')
    if len(expr) != 1:
        raise RuleError("每个表达式节点只能包含一个键")
    (key, body), = expr.items()
    if key == "lit":
        if not isinstance(body, (bool, int, float, str)) and body is not None:
            raise RuleError("lit 仅支持 bool/number/string/null")
    elif key == "field":
        _path_parts(body)
    elif key == "not":
        validate(body, depth + 1)
    elif key in ("and", "or"):
        if not isinstance(body, list) or not body:
            raise RuleError(f"{key} 需要非空表达式数组")
        for sub in body:
            validate(sub, depth + 1)
    elif key == "cmp":
        if (
            not isinstance(body, list)
            or len(body) != 3
            or not isinstance(body[1], str)
            or body[1] not in VALID_OPS
        ):
            raise RuleError('cmp 形如 [<expr>, "==", <expr>]')
        validate(body[0], depth + 1)
        validate(body[2], depth + 1)
    elif key in ("exists", "is_missing", "is_null"):
        _path_parts(body)
    elif key == "fallback":
        if not isinstance(body, list) or len(body) < 2:
            raise RuleError("fallback 需要至少两个表达式")
        for sub in body:
            validate(sub, depth + 1)
    else:
        raise RuleError(f"禁止或未知的表达式键: {key!r}")


def count_nodes(expr: Any) -> int:
    if isinstance(expr, bool) or not isinstance(expr, dict):
        return 1
    (key, body), = expr.items()
    if key in ("and", "or", "fallback"):
        return 1 + sum(count_nodes(sub) for sub in body)
    if key == "cmp":
        return 1 + count_nodes(body[0]) + count_nodes(body[2])
    if key == "not":
        return 1 + count_nodes(body)
    return 1


def compile_rule(expr: Any, max_nodes: int = MAX_NODES) -> Any:
    """结构校验并返回规范化后的表达式。"""
    if isinstance(expr, str):
        import json

        try:
            expr = json.loads(expr)
        except (ValueError, TypeError) as exc:
            raise RuleError(f"规则不是合法 JSON: {exc}") from exc
    validate(expr)
    normalized = normalize(expr)
    if count_nodes(normalized) > max_nodes:
        raise RuleError(f"表达式节点数超过上限 {max_nodes}")
    return normalized


def normalize(expr: Any) -> Any:
    if not isinstance(expr, dict):
        return expr
    (key, body), = expr.items()
    if key in ("and", "or", "fallback"):
        return {key: [normalize(sub) for sub in body]}
    if key == "cmp":
        return {"cmp": [normalize(body[0]), body[1], normalize(body[2])]}
    if key == "not":
        return {"not": normalize(body)}
    return {key: body}


def canonical(expr: Any) -> str:
    import json

    return json.dumps(normalize(expr), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def type_family(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    return "other"


def _secret_for(parts: list[str], secret_paths: list[str]) -> bool:
    path = ".".join(parts)
    for sp in secret_paths:
        if path == sp or path.startswith(sp + "."):
            return True
    return False


def _lookup(parts: list[str], request: Any, secret_paths: list[str], trace: Trace,
            reason: str) -> Any:
    secret = _secret_for(parts, secret_paths)
    path = ".".join(parts)
    cur: Any = request
    walked: list[str] = []
    for part in parts:
        walked.append(part)
        here = ".".join(walked)
        if isinstance(cur, dict):
            if part not in cur:
                trace.touch(here, _secret_for(walked, secret_paths), "missing")
                raise missing(here)
            cur = cur[part]
        elif isinstance(cur, list):
            try:
                idx = int(part)
            except ValueError:
                trace.touch(here, _secret_for(walked, secret_paths), "type_error")
                raise type_error(here, f"{part!r} 不能索引数组")
            if not (0 <= idx < len(cur)):
                trace.touch(here, _secret_for(walked, secret_paths), "missing")
                raise missing(here)
            cur = cur[idx]
        else:
            trace.touch(here, _secret_for(walked, secret_paths), "type_error")
            raise type_error(here, "中间路径不是对象或数组")
        if cur is None:
            trace.touch(here, _secret_for(walked, secret_paths), "null")
            raise null_error(here)
    trace.touch(path, secret, reason)
    if secret:
        raise type_error(path, "secret 字段只能判断存在性，禁止读取值")
    return cur


def _eval(expr: Any, request: Any, secret_paths: list[str], trace: Trace,
          reason: str = "read") -> Any:
    (key, body), = expr.items()
    if key == "lit":
        return body
    if key == "field":
        return _lookup(_path_parts(body), request, secret_paths, trace, reason)
    if key == "not":
        value = _eval(body, request, secret_paths, trace, "not.operand")
        if not isinstance(value, bool):
            raise type_error(None, "not 只接受布尔值")
        return not value
    if key == "and":
        value = True
        for index, sub in enumerate(body):
            value = _eval(sub, request, secret_paths, trace, f"and[{index}]")
            if not isinstance(value, bool):
                raise type_error(None, "and 只接受布尔值")
            if value is False:
                trace.short_circuits.append(
                    {"op": "and", "index": index + 1, "reason": "false"}
                )
                return False
        return value
    if key == "or":
        value = False
        for index, sub in enumerate(body):
            value = _eval(sub, request, secret_paths, trace, f"or[{index}]")
            if not isinstance(value, bool):
                raise type_error(None, "or 只接受布尔值")
            if value is True:
                trace.short_circuits.append(
                    {"op": "or", "index": index + 1, "reason": "true"}
                )
                return True
        return value
    if key == "cmp":
        left_expr, op, right_expr = body
        left = _eval(left_expr, request, secret_paths, trace, "cmp.left")
        right = _eval(right_expr, request, secret_paths, trace, "cmp.right")
        lf, rf = type_family(left), type_family(right)
        if lf != rf or lf in ("null", "other"):
            if op == "==":
                trace.short_circuits.append({"op": "cmp", "reason": "type_not_equal"})
                return False
            if op == "!=":
                trace.short_circuits.append({"op": "cmp", "reason": "type_not_equal"})
                return True
            raise type_error(None, f"无法比较 {lf} 与 {rf}")
        if op == "==":
            return left == right
        if op == "!=":
            return left != right
        if lf not in ("number", "string"):
            raise type_error(None, f"运算符 {op} 仅支持 number/string")
        if op == "<":
            return left < right
        if op == "<=":
            return left <= right
        if op == ">":
            return left > right
        return left >= right
    if key == "exists":
        return _probe(body, request, secret_paths, trace) != "missing"
    if key == "is_missing":
        return _probe(body, request, secret_paths, trace) == "missing"
    if key == "is_null":
        return _probe(body, request, secret_paths, trace) == "null"

    # fallback
    last_error: ExpressionError | None = None
    for index, sub in enumerate(body):
        try:
            value = _eval(sub, request, secret_paths, trace, f"fallback[{index}]")
        except ExpressionError as exc:
            last_error = exc
            trace.short_circuits.append(
                {"op": "fallback", "index": index, "reason": exc.status, "path": exc.path}
            )
            continue
        if index:
            trace.short_circuits.append({"op": "fallback", "index": index, "reason": "used"})
        return value
    assert last_error is not None
    raise last_error


def _probe(path: str, request: Any, secret_paths: list[str], trace: Trace) -> str:
    """只探测存在性：返回 present / null / missing，绝不读出 secret 值。"""
    parts = _path_parts(path)
    cur: Any = request
    walked: list[str] = []
    for part in parts:
        walked.append(part)
        here = ".".join(walked)
        is_secret = _secret_for(walked, secret_paths)
        if isinstance(cur, dict):
            if part not in cur:
                trace.touch(here, is_secret, "missing")
                return "missing"
            cur = cur[part]
        elif isinstance(cur, list):
            try:
                idx = int(part)
            except ValueError:
                trace.touch(here, is_secret, "type_error")
                return "missing"
            if not (0 <= idx < len(cur)):
                trace.touch(here, is_secret, "missing")
                return "missing"
            cur = cur[idx]
        else:
            trace.touch(here, is_secret, "type_error")
            return "missing"
        if cur is None:
            trace.touch(here, is_secret, "null")
            if len(walked) == len(parts):
                return "null"
            # 中间路径为 null，剩余部分必然缺失
            rest = parts[len(walked):]
            for extra in rest:
                walked.append(extra)
                trace.touch(".".join(walked), _secret_for(walked, secret_paths), "missing")
            return "missing"
    trace.touch(path, _secret_for(parts, secret_paths), "probe")
    return "present"


def evaluate(rule: Any, request: Any, secret_paths: list[str] | None = None) -> Outcome:
    trace = Trace()
    try:
        value = _eval(rule, request, secret_paths or [], trace)
        if not isinstance(value, bool):
            raise type_error(None, "规则顶层必须返回布尔值")
        status = "ok"
        error: str | None = None
    except ExpressionError as exc:
        value = None
        status = exc.status
        error = exc.message
    return Outcome(
        value=value,
        status=status,
        accessed=trace.accessed,
        secret_access=trace.secret_access,
        short_circuits=trace.short_circuits,
        error=error,
    )


STATUS_LABELS = {
    "ok": "正常",
    "missing": "缺字段",
    "null": "显式 null",
    "type_error": "类型不匹配",
}
