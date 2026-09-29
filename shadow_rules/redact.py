"""Schema-driven redaction of secret request fields.

Secret values are replaced with a marker *before* anything is persisted,
so the original value never reaches the database, logs, pages or exports.
Rules can still test presence/absence of the field via `exists`.
"""
from __future__ import annotations

import copy

from .rules import REDACTED_MARKER

DEFAULT_SECRET_FIELDS = ["ssn", "secret", "profile.token"]


def sanitize(body: dict, secret_fields: list[str]) -> dict:
    clean = copy.deepcopy(body)
    for path in secret_fields:
        parts = path.split(".")
        node = clean
        for part in parts[:-1]:
            if not isinstance(node, dict) or part not in node:
                node = None
                break
            node = node[part]
        if isinstance(node, dict) and parts[-1] in node:
            node[parts[-1]] = dict(REDACTED_MARKER)
    return clean
