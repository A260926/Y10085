"""Batch evaluation engine: idempotent creation, crash recovery, decisions."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from .rules import Evaluator, categorize, digest_text, normalize
from .store import Store


class BatchConflict(Exception):
    def __init__(self, batch):
        self.batch = batch
        super().__init__("idempotency key reused with different inputs")


def _canonical(payload) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def input_digest(rule_a, rule_b, request_rows) -> str:
    payload = {
        "rule_a": rule_a["normalized_digest"],
        "rule_b": rule_b["normalized_digest"],
        "requests": [{"id": r["id"], "digest": r["digest"]} for r in request_rows],
    }
    return digest_text(_canonical(payload))


def create_batch(store: Store, key: str, rule_a_id: int, rule_b_id: int,
                 request_ids: list[str], clock):
    """Idempotent batch creation.

    Same key + same frozen input digest -> returns the existing batch.
    Same key + different digest -> BatchConflict.
    """
    rule_a = store.get_rule(rule_a_id)
    rule_b = store.get_rule(rule_b_id)
    if rule_a is None or rule_b is None:
        raise KeyError("unknown rule version")
    request_rows = []
    for request_id in request_ids:
        row = store.get_request(request_id)
        if row is None:
            raise KeyError(f"unknown request {request_id}")
        request_rows.append(row)
    digest = input_digest(rule_a, rule_b, request_rows)

    existing = store.get_batch_by_key(key)
    if existing is not None:
        if existing["input_digest"] == digest:
            return existing, False
        raise BatchConflict(existing)

    batch_id = uuid.uuid4().hex[:12]
    batch = store.add_batch(batch_id, key, digest, rule_a_id, rule_b_id,
                            request_ids, clock)
    evaluate_batch(store, batch_id, clock)
    return store.get_batch(batch_id), True


def evaluate_batch(store: Store, batch_id: str, clock,
                   stop_before_summary: bool = False):
    """Evaluate every frozen request against both rule versions.

    Results are appended with INSERT OR IGNORE, so re-running never
    duplicates rows. `stop_before_summary` simulates a crash after the
    results are computed but before the summary is written.
    """
    batch = store.get_batch(batch_id)
    rule_a = store.get_rule(batch["rule_a_id"])
    rule_b = store.get_rule(batch["rule_b_id"])
    source_a = json.loads(rule_a["normalized"])
    source_b = json.loads(rule_b["normalized"])
    for request_id in json.loads(batch["request_ids"]):
        if store.has_result(batch_id, request_id):
            continue
        body = json.loads(store.get_request(request_id)["body"])
        result_a = Evaluator(body).run(source_a)
        result_b = Evaluator(body).run(source_b)
        store.add_result(batch_id, request_id, result_a, result_b,
                         categorize(result_a, result_b))
    if stop_before_summary:
        return
    store.finish_batch(batch_id, build_summary(store, batch_id, clock))


def recover(store: Store, clock):
    """Called on startup: finish batches interrupted before summary write.

    Only fills in missing results (never duplicates) and writes the summary.
    """
    recovered = []
    for batch in store.running_batches():
        evaluate_batch(store, batch["id"], clock)
        recovered.append(batch["id"])
    return recovered


def _parse_dt(value):
    return datetime.fromisoformat(value) if value else None


def decision_is_active(decision, clock) -> bool:
    if decision is None:
        return False
    if decision["action"] == "exception":
        expires = _parse_dt(decision["expires_at"])
        if expires is not None and clock() >= expires:
            return False
    return True


def effective_decision(store: Store, batch_id: str, request_id: str,
                       revision: int, clock):
    decision = store.get_decision(batch_id, request_id, revision)
    if decision is None or not decision_is_active(decision, clock):
        return None
    return decision


def build_summary(store: Store, batch_id: str, clock) -> dict:
    batch = store.get_batch(batch_id)
    results = store.list_results(batch_id)
    categories = {"outcome": 0, "path": 0, "none": 0}
    for row in results:
        categories[row["category"]] = categories.get(row["category"], 0) + 1
    decisions = {"accept": 0, "block": 0, "exception": 0}
    for row in store.list_decisions(batch_id, batch["revision"]):
        if decision_is_active(row, clock):
            decisions[row["action"]] = decisions.get(row["action"], 0) + 1
    return {
        "batch_id": batch_id,
        "total": len(results),
        "categories": categories,
        "decisions": decisions,
        "generated_at": clock().isoformat(),
    }


def export_batch(store: Store, batch_id: str, clock) -> dict:
    """Export bundle: rule digests, input digest, diffs, decisions. No secrets."""
    batch = store.get_batch(batch_id)
    rule_a = store.get_rule(batch["rule_a_id"])
    rule_b = store.get_rule(batch["rule_b_id"])
    diffs = []
    for row in store.list_results(batch_id):
        decision = effective_decision(store, batch_id, row["request_id"],
                                      batch["revision"], clock)
        diffs.append({
            "request_id": row["request_id"],
            "category": row["category"],
            "a": json.loads(row["a_result"]),
            "b": json.loads(row["b_result"]),
            "decision": _decision_view(decision),
        })
    return {
        "batch_id": batch["id"],
        "revision": batch["revision"],
        "input_digest": batch["input_digest"],
        "rule_a": {"id": rule_a["id"], "name": rule_a["name"],
                   "source_digest": rule_a["source_digest"],
                   "normalized": json.loads(rule_a["normalized"])},
        "rule_b": {"id": rule_b["id"], "name": rule_b["name"],
                   "source_digest": rule_b["source_digest"],
                   "normalized": json.loads(rule_b["normalized"])},
        "diffs": diffs,
        "summary": json.loads(batch["summary"]) if batch["summary"] else None,
        "exported_at": clock().isoformat(),
    }


def _decision_view(decision):
    if decision is None:
        return None
    return {
        "action": decision["action"],
        "reason": decision["reason"],
        "version": decision["version"],
        "expires_at": decision["expires_at"],
        "updated_at": decision["updated_at"],
    }


def submit_decision(store: Store, batch_id: str, request_id: str, action: str,
                    reason: str, expected_version: int, ttl_seconds, clock):
    """Optimistic-concurrency decision write.

    Returns (decision, None) on success or (None, conflict) when the
    version does not match; the conflict carries both reasons.
    """
    batch = store.get_batch(batch_id)
    if batch is None:
        raise KeyError("unknown batch")
    if not store.has_result(batch_id, request_id):
        raise KeyError("unknown diff")
    revision = batch["revision"]
    existing = store.get_decision(batch_id, request_id, revision)
    current_version = existing["version"] if existing else 0
    if current_version != expected_version:
        conflict = {
            "conflict": True,
            "current": _decision_view(existing),
            "current_reason": existing["reason"] if existing else None,
            "submitted_reason": reason,
        }
        return None, conflict
    expires_at = None
    if action == "exception":
        if not ttl_seconds:
            raise ValueError("exception requires ttl_seconds")
        from datetime import timedelta
        expires_at = (clock() + timedelta(seconds=ttl_seconds)).isoformat()
    decision = store.put_decision(batch_id, request_id, revision, action,
                                  reason, current_version + 1, expires_at,
                                  clock)
    return decision, None
