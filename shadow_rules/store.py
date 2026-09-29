"""SQLite persistence layer."""
from __future__ import annotations

import json
import sqlite3
import threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS rule_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    source_text TEXT NOT NULL,
    source_digest TEXT NOT NULL,
    normalized TEXT NOT NULL,
    normalized_digest TEXT NOT NULL,
    parent_id INTEGER,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS requests (
    id TEXT PRIMARY KEY,
    body TEXT NOT NULL,
    digest TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS batches (
    id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    input_digest TEXT NOT NULL,
    rule_a_id INTEGER NOT NULL,
    rule_b_id INTEGER NOT NULL,
    request_ids TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL,
    summary TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS results (
    batch_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    a_result TEXT NOT NULL,
    b_result TEXT NOT NULL,
    category TEXT NOT NULL,
    PRIMARY KEY (batch_id, request_id)
);
CREATE TABLE IF NOT EXISTS decisions (
    batch_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    action TEXT NOT NULL,
    reason TEXT NOT NULL,
    version INTEGER NOT NULL,
    expires_at TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (batch_id, request_id, revision)
);
"""


def _now_iso(clock) -> str:
    return clock().isoformat()


class Store:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.lock = threading.Lock()
        with self.lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    def execute(self, sql, params=()):
        with self.lock:
            cursor = self.conn.execute(sql, params)
            self.conn.commit()
            return cursor

    def query(self, sql, params=()):
        with self.lock:
            return self.conn.execute(sql, params).fetchall()

    def one(self, sql, params=()):
        rows = self.query(sql, params)
        return rows[0] if rows else None

    # -- rules -----------------------------------------------------------
    def add_rule(self, name, source_text, source_digest, normalized,
                 normalized_digest, parent_id, clock):
        cursor = self.execute(
            "INSERT INTO rule_versions"
            " (name, source_text, source_digest, normalized, normalized_digest,"
            "  parent_id, created_at) VALUES (?,?,?,?,?,?,?)",
            (name, source_text, source_digest, normalized, normalized_digest,
             parent_id, _now_iso(clock)),
        )
        return self.get_rule(cursor.lastrowid)

    def get_rule(self, rule_id):
        return self.one("SELECT * FROM rule_versions WHERE id=?", (rule_id,))

    def list_rules(self):
        return self.query("SELECT * FROM rule_versions ORDER BY id")

    # -- requests ----------------------------------------------------------
    def add_request(self, request_id, body, digest, clock):
        self.execute(
            "INSERT OR IGNORE INTO requests (id, body, digest, created_at)"
            " VALUES (?,?,?,?)",
            (request_id, json.dumps(body, ensure_ascii=False), digest,
             _now_iso(clock)),
        )
        return self.get_request(request_id)

    def get_request(self, request_id):
        return self.one("SELECT * FROM requests WHERE id=?", (request_id,))

    def list_requests(self):
        return self.query("SELECT * FROM requests ORDER BY id")

    # -- batches -----------------------------------------------------------
    def add_batch(self, batch_id, key, input_digest, rule_a_id, rule_b_id,
                  request_ids, clock):
        self.execute(
            "INSERT INTO batches"
            " (id, idempotency_key, input_digest, rule_a_id, rule_b_id,"
            "  request_ids, revision, status, summary, created_at)"
            " VALUES (?,?,?,?,?,?,1,'running',NULL,?)",
            (batch_id, key, input_digest, rule_a_id, rule_b_id,
             json.dumps(request_ids), _now_iso(clock)),
        )
        return self.get_batch(batch_id)

    def get_batch(self, batch_id):
        return self.one("SELECT * FROM batches WHERE id=?", (batch_id,))

    def get_batch_by_key(self, key):
        return self.one("SELECT * FROM batches WHERE idempotency_key=?", (key,))

    def list_batches(self):
        return self.query("SELECT * FROM batches ORDER BY created_at, id")

    def running_batches(self):
        return self.query("SELECT * FROM batches WHERE status != 'done'")

    def finish_batch(self, batch_id, summary):
        self.execute(
            "UPDATE batches SET status='done', summary=? WHERE id=?",
            (json.dumps(summary, ensure_ascii=False), batch_id),
        )

    # -- results -----------------------------------------------------------
    def has_result(self, batch_id, request_id):
        row = self.one(
            "SELECT 1 AS x FROM results WHERE batch_id=? AND request_id=?",
            (batch_id, request_id),
        )
        return row is not None

    def add_result(self, batch_id, request_id, a_result, b_result, category):
        self.execute(
            "INSERT OR IGNORE INTO results"
            " (batch_id, request_id, a_result, b_result, category)"
            " VALUES (?,?,?,?,?)",
            (batch_id, request_id, json.dumps(a_result, ensure_ascii=False),
             json.dumps(b_result, ensure_ascii=False), category),
        )

    def list_results(self, batch_id):
        return self.query(
            "SELECT * FROM results WHERE batch_id=? ORDER BY request_id",
            (batch_id,),
        )

    def count_results(self, batch_id):
        row = self.one(
            "SELECT COUNT(*) AS n FROM results WHERE batch_id=?", (batch_id,)
        )
        return row["n"]

    # -- decisions ---------------------------------------------------------
    def get_decision(self, batch_id, request_id, revision):
        return self.one(
            "SELECT * FROM decisions"
            " WHERE batch_id=? AND request_id=? AND revision=?",
            (batch_id, request_id, revision),
        )

    def put_decision(self, batch_id, request_id, revision, action, reason,
                     version, expires_at, clock):
        self.execute(
            "INSERT OR REPLACE INTO decisions"
            " (batch_id, request_id, revision, action, reason, version,"
            "  expires_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
            (batch_id, request_id, revision, action, reason, version,
             expires_at, _now_iso(clock)),
        )
        return self.get_decision(batch_id, request_id, revision)

    def list_decisions(self, batch_id, revision):
        return self.query(
            "SELECT * FROM decisions WHERE batch_id=? AND revision=?",
            (batch_id, revision),
        )
