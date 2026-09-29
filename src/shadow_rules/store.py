"""SQLite 持久化层。"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS rule_versions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    raw_text TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    normalized TEXT NOT NULL,
    digest TEXT NOT NULL,
    parent_id TEXT REFERENCES rule_versions(id),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS batches (
    id TEXT PRIMARY KEY,
    idempotency_key TEXT,
    input_digest TEXT NOT NULL,
    current_rule_id TEXT NOT NULL REFERENCES rule_versions(id),
    candidate_rule_id TEXT NOT NULL REFERENCES rule_versions(id),
    revision INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL,
    secret_schema TEXT NOT NULL,
    summary TEXT,
    created_at TEXT NOT NULL,
    finalized_at TEXT,
    UNIQUE(idempotency_key)
);

CREATE TABLE IF NOT EXISTS batch_requests (
    id TEXT PRIMARY KEY,
    batch_id TEXT NOT NULL REFERENCES batches(id),
    position INTEGER NOT NULL,
    redacted_json TEXT NOT NULL,
    digest TEXT NOT NULL,
    UNIQUE(batch_id, position)
);

CREATE TABLE IF NOT EXISTS request_results (
    request_id TEXT PRIMARY KEY REFERENCES batch_requests(id),
    current_json TEXT NOT NULL,
    candidate_json TEXT NOT NULL,
    diff_category TEXT,
    explanations_json TEXT
);

CREATE TABLE IF NOT EXISTS decisions (
    id TEXT PRIMARY KEY,
    batch_id TEXT NOT NULL REFERENCES batches(id),
    request_id TEXT NOT NULL REFERENCES batch_requests(id),
    batch_revision INTEGER NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    verdict TEXT NOT NULL,
    reason TEXT NOT NULL,
    expires_at TEXT,
    decided_at TEXT NOT NULL,
    UNIQUE(batch_id, request_id)
);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    else:
        conn.commit()


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def loads(text: str | None) -> Any:
    return json.loads(text) if text is not None else None
