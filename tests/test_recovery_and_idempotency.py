import sqlite3

import pytest

from shadow_rules.clock import FakeClock
from shadow_rules.seed import CURRENT_RULE, CANDIDATE_RULE
from shadow_rules.service import Service


def _setup(db_path, clock):
    svc = Service(db_path, clock=clock)
    cur = svc.upload_rule("cur", CURRENT_RULE, None)
    cand = svc.upload_rule("cand", CANDIDATE_RULE, cur["id"])
    requests = [
        {"request": {"profile": {"vip": True}, "risk": {"score": 1},
                     "auth": {"token": "t"}}},
        {"request": {"profile": {"vip": False, "age": 20}, "risk": {"score": 1},
                     "auth": {"token": "t"}}},
        {"request": {"profile": {"vip": False, "age": 50}, "risk": {"score": 99},
                     "auth": {}}},
    ]
    return svc, cur["id"], cand["id"], requests


class Boom(Exception):
    pass


def test_crash_after_results_before_summary_only_fills_summary(tmp_path):
    db = tmp_path / "crash.db"
    clock = FakeClock()
    svc, cur_id, cand_id, requests = _setup(db, clock)

    # 让 finalize 在首次（全部结果写完时）崩溃
    original_finalize = svc.finalize_batch
    calls = {"n": 0}

    def crashing_finalize(batch_id):
        calls["n"] += 1
        if calls["n"] == 1:
            raise Boom("simulated exit before summary")
        return original_finalize(batch_id)

    svc.finalize_batch = crashing_finalize
    with pytest.raises(Boom):
        svc.create_batch("k", cur_id, cand_id, ["auth.token"], requests)
    svc.close()

    # 磁盘状态：结果全在，批次仍 pending，无汇总
    raw = sqlite3.connect(db)
    raw.row_factory = sqlite3.Row
    batch = raw.execute("SELECT * FROM batches WHERE idempotency_key='k'").fetchone()
    assert batch["status"] == "pending"
    assert batch["summary"] is None
    n_requests = raw.execute("SELECT COUNT(*) FROM batch_requests").fetchone()[0]
    n_results = raw.execute("SELECT COUNT(*) FROM request_results").fetchone()[0]
    assert n_results == n_requests == 3
    raw.close()

    # 重启恢复：只补汇总
    clock.advance(seconds=10)
    svc2 = Service(db, clock=clock)
    recovered = svc2.recover_pending()
    assert len(recovered) == 1
    batch_view = svc2.get_batch(recovered[0])
    assert batch_view["status"] == "done"
    assert batch_view["summary"]["total"] == 3
    assert batch_view["summary"]["differences"] >= 1

    # 再恢复一次：无重复追加、无重复汇总
    assert svc2.recover_pending() == []
    with sqlite3.connect(db) as check:
        assert check.execute("SELECT COUNT(*) FROM request_results").fetchone()[0] == 3
        assert check.execute("SELECT COUNT(*) FROM batches").fetchone()[0] == 1
    svc2.close()


def test_crash_midway_through_requests_resumes_without_duplicates(tmp_path):
    db = tmp_path / "mid.db"
    clock = FakeClock()
    svc, cur_id, cand_id, requests = _setup(db, clock)

    def run_partial(batch_id, expr_cur, expr_cand, secret_paths):
        rows = svc.conn.execute(
            "SELECT id FROM batch_requests WHERE batch_id=? ORDER BY position",
            (batch_id,),
        ).fetchall()
        from shadow_rules.engine import evaluate
        from shadow_rules.service import _explain, classify_diff
        from shadow_rules.store import dumps, loads

        row = rows[0]  # 只处理第一条就“退出”
        full = svc.conn.execute(
            "SELECT redacted_json FROM batch_requests WHERE id=?", (row["id"],)
        ).fetchone()
        request = loads(full["redacted_json"])
        a = evaluate(expr_cur, request, secret_paths).as_dict()
        b = evaluate(expr_cand, request, secret_paths).as_dict()
        svc.conn.execute(
            "INSERT OR IGNORE INTO request_results "
            "(request_id, current_json, candidate_json, diff_category, "
            "explanations_json) VALUES (?,?,?,?,?)",
            (row["id"], dumps(a), dumps(b), classify_diff(a, b),
             dumps({"current": _explain("当前版本", a),
                    "candidate": _explain("候选版本", b)})),
        )
        svc.conn.commit()

    svc._run_requests = run_partial
    # finalize 发现结果不全 -> 返回 False，批次留在 pending，模拟进程退出
    svc.create_batch("k2", cur_id, cand_id, ["auth.token"], requests)
    svc.close()

    with sqlite3.connect(db) as raw:
        assert raw.execute(
            "SELECT COUNT(*) FROM request_results").fetchone()[0] == 1

    svc2 = Service(db, clock=clock)
    recovered = svc2.recover_pending()
    assert len(recovered) == 1
    view = svc2.get_batch(recovered[0])
    assert view["status"] == "done"
    assert len(view["requests"]) == 3
    assert all("current" in r for r in view["requests"])
    with sqlite3.connect(db) as raw:
        assert raw.execute(
            "SELECT COUNT(*) FROM request_results").fetchone()[0] == 3
        assert raw.execute("SELECT COUNT(*) FROM batches").fetchone()[0] == 1
    svc2.close()


def test_idempotent_key_returns_same_batch(client):
    r1 = client.post("/api/rules", json={"name": "a", "rule": CURRENT_RULE}).json()
    r2 = client.post("/api/rules", json={"name": "b", "rule": CANDIDATE_RULE}).json()
    body = {
        "idempotency_key": "same-key",
        "current_rule_id": r1["id"],
        "candidate_rule_id": r2["id"],
        "secret_paths": [],
        "requests": [{"request": {"profile": {"vip": True}, "risk": {"score": 1}}}],
    }
    first = client.post("/api/batches", json=body)
    assert first.status_code == 201
    second = client.post("/api/batches", json=body)
    assert second.status_code == 200
    assert second.json()["id"] == first.json()["id"]
    assert second.json()["reused"] is True


def test_same_key_different_input_digest_conflicts(client):
    r1 = client.post("/api/rules", json={"name": "a", "rule": CURRENT_RULE}).json()
    r2 = client.post("/api/rules", json={"name": "b", "rule": CANDIDATE_RULE}).json()
    base = {
        "idempotency_key": "dup-key",
        "current_rule_id": r1["id"],
        "candidate_rule_id": r2["id"],
        "secret_paths": [],
        "requests": [{"request": {"profile": {"vip": True}, "risk": {"score": 1}}}],
    }
    assert client.post("/api/batches", json=base).status_code == 201

    changed = dict(base)
    changed["requests"] = [
        {"request": {"profile": {"vip": False}, "risk": {"score": 99}}}
    ]
    resp = client.post("/api/batches", json=changed)
    assert resp.status_code == 409
    payload = resp.json()
    assert payload["code"] == "idempotency_input_mismatch"
    assert payload["existing_input_digest"] != payload["submitted_input_digest"]
    # 冲突不产生第二个批次
    assert len(client.get("/api/batches").json()) == 1
