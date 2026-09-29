"""按 schema 对请求脱敏：secret 路径原值永不离开本模块的输出。"""
from __future__ import annotations

import copy
from typing import Any

from .engine import REDACTED


def _parts(path: str) -> list[str]:
    return path.split(".")


def _is_secret_prefix(path_parts: list[str], secret_paths: list[str]) -> bool:
    joined = ".".join(path_parts)
    for sp in secret_paths:
        if joined == sp or joined.startswith(sp + "."):
            return True
    return False


def redact(value: Any, secret_paths: list[str]) -> Any:
    """返回深拷贝；secret 叶子替换为占位，结构与“存在性”保持不变。"""
    secret_set = set(secret_paths)

    def walk(node: Any, parts: list[str]) -> Any:
        path = ".".join(parts)
        if path in secret_set:
            if isinstance(node, dict):
                return {k: REDACTED for k in node}
            if isinstance(node, list):
                return [REDACTED for _ in node]
            return REDACTED
        if isinstance(node, dict):
            return {k: walk(v, parts + [k]) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v, parts + [str(i)]) for i, v in enumerate(node)]
        return node

    return walk(copy.deepcopy(value), [])


def secret_leaf_paths(secret_paths: list[str]) -> list[str]:
    return list(dict.fromkeys(secret_paths))
