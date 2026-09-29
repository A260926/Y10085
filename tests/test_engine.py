"""Idempotency, crash recovery, decision versioning and expiry."""
import json
from datetime import timedelta

from shadow_rules import engine
from shadow_rules.store import Store

from conftest import make_batch


def test_idempotent_replay_returns_same_batch(client):
    first = make_batch(client, key="replay-1")
    assert first.status_code == 201
    second = make_batch(client, key="replay-1")
    assert second.status_code == 200
    assert second.json()["id"] == first.json()["id"]
    # no duplicate evaluation happened
    assert client.get(f"/api/batches/{first.json()['id']}").json()[
        "summary"]["total"] == 3


def test_idempotency_conflict_on_different_inputs(client):
    first = make_batch(client, key="conflict-1")
    assert first.status_code == 201
    conflict = make_batch(client, key="conflict-1", rule_b=1)
    assert conflict.status_code == 409
    body = conflict.json()
    assert body["error"] == "idempotency_conflict"
    assert body["existing_batch_id"] == first.json()["id"]


def test_crash_recovery_only_writes_missing_summary(db_path, clock):
    store = Store(db_path)
    engine.recover(store, clock)
    from shadow_rules.seed import seed
    seed(store, clock)
    batch = store.get_batch_by_key("seed:baseline-vs-candidate")
    before = store.count_results(batch["id"])

    # simulate a crash: results computed, summary never written
    store.execute("UPDATE batches SET status='running', summary=NULL WHERE id=?",
                  (batch["id"],))
    store.conn.close()

    # restart: recovery fills in only the missing summary
    store2 = Store(db_path)
    recovered = engine.recover(store2, clock)
    assert batch["id"] in recovered
    after = store2.get_batch(batch["id"])
    assert after["status"] == "done"
    assert after["summary"] is not None
    assert store2.count_results(batch["id"]) == before  # no duplicate results


def test_partial_results_are_not_duplicated_on_recovery(db_path, clock):
    store = Store(db_path)
    engine.recover(store, clock)
    from shadow_rules.seed import seed
    seed(store, clock)
    batch = store.get_batch_by_key("seed:baseline-vs-candidate")
    # drop one result and unfinish the batch, then recover
    store.execute("DELETE FROM results WHERE batch_id=? AND request_id='req-003'",
                  (batch["id"],))
    store.execute("UPDATE batches SET status='running', summary=NULL WHERE id=?",
                  (batch["id"],))
    engine.recover(store, clock)
    assert store.count_results(batch["id"]) == 3
    assert store.get_batch(batch["id"])["status"] == "done"


def test_decision_conflict_returns_both_reasons(client):
    batch_id = make_batch(client, key="dec-1").json()["id"]
    ok = client.post(f"/api/batches/{batch_id}/diffs/req-001/decision", json={
        "action": "accept", "reason": "页面A: 可接受", "expected_version": 0})
    assert ok.status_code == 200
    # second page still holds version 0 and loses the race
    conflict = client.post(f"/api/batches/{batch_id}/diffs/req-001/decision",
                           json={"action": "block", "reason": "页面B: 应阻止",
                                 "expected_version": 0})
    assert conflict.status_code == 409
    body = conflict.json()
    assert body["current_reason"] == "页面A: 可接受"
    assert body["submitted_reason"] == "页面B: 应阻止"
    # retrying with the fresh version succeeds
    retry = client.post(f"/api/batches/{batch_id}/diffs/req-001/decision",
                        json={"action": "block", "reason": "页面B: 应阻止",
                              "expected_version": 1})
    assert retry.status_code == 200
    assert retry.json()["decision"]["version"] == 2


def test_exception_expires_with_injected_clock(client, clock):
    batch_id = make_batch(client, key="dec-exp").json()["id"]
    created = client.post(f"/api/batches/{batch_id}/diffs/req-001/decision",
                          json={"action": "exception", "reason": "灰度期放行",
                                "expected_version": 0, "ttl_seconds": 3600})
    assert created.status_code == 200
    detail = client.get(f"/api/batches/{batch_id}").json()
    assert detail["diffs"][0]["decision"]["action"] == "exception"

    clock.advance(3601)  # exception lapses
    detail = client.get(f"/api/batches/{batch_id}").json()
    assert detail["diffs"][0]["decision"] is None


def test_decisions_bound_to_batch_revision(client):
    batch_id = make_batch(client, key="dec-rev").json()["id"]
    client.post(f"/api/batches/{batch_id}/diffs/req-001/decision",
                json={"action": "accept", "reason": "旧决议",
                      "expected_version": 0})
    # rule re-upload creates a new version, not a silent inheritance
    rules = client.get("/api/rules").json()["rules"]
    candidate = [r for r in rules if r["name"] == "candidate-v2"][0]
    reupload = client.post("/api/rules", json={
        "name": "candidate-v3", "rule": candidate["normalized"],
        "parent_id": candidate["id"]})
    assert reupload.status_code == 201
    assert reupload.json()["parent_id"] == candidate["id"]
    new_batch = client.post("/api/batches", json={
        "idempotency_key": "dec-rev-2", "rule_a_id": 1,
        "rule_b_id": reupload.json()["id"],
        "request_ids": ["req-001", "req-002", "req-003"]})
    detail = client.get(f"/api/batches/{new_batch.json()['id']}").json()
    assert all(d["decision"] is None for d in detail["diffs"])
