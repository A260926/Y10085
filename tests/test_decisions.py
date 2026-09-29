from shadow_rules.seed import CURRENT_RULE, CANDIDATE_RULE


def _batch(client):
    r1 = client.post("/api/rules", json={"name": "a", "rule": CURRENT_RULE}).json()
    r2 = client.post("/api/rules", json={"name": "b", "rule": CANDIDATE_RULE}).json()
    body = {
        "idempotency_key": "dec",
        "current_rule_id": r1["id"],
        "candidate_rule_id": r2["id"],
        "secret_paths": ["auth.token"],
        "requests": [
            {"request": {"profile": {"vip": False, "age": 17}, "risk": {"score": 90},
                         "auth": {"token": "secret-token-xyz"}}},
        ],
    }
    batch = client.post("/api/batches", json=body).json()
    return batch, r1, r2


def _put(client, batch, verdict, reason, version, expires=None):
    rid = batch["requests"][0]["request_id"]
    return client.put(
        f"/api/batches/{batch['id']}/requests/{rid}/decision",
        json={"verdict": verdict, "reason": reason, "expires_at": expires,
              "version": version},
    )


def test_concurrent_decisions_conflict_with_both_reasons(client):
    batch, _, _ = _batch(client)
    # 页面 A 先提交 v0
    first = _put(client, batch, "accept", "A 方：候选行为可接受", 0)
    assert first.status_code == 200
    assert first.json()["version"] == 1

    # 页面 B 仍拿着 v0 提交 -> 冲突，返回双方理由
    clash = _put(client, batch, "block", "B 方：风险过高必须阻止", 0)
    assert clash.status_code == 409
    payload = clash.json()
    assert payload["code"] == "decision_version_conflict"
    assert payload["required_version"] == 1
    assert payload["existing_decision"]["reason"] == "A 方：候选行为可接受"
    assert payload["submitted_reason"] == "B 方：风险过高必须阻止"

    # B 刷新后用 v1 提交 -> 成功，版本递增
    retry = _put(client, batch, "block", "B 方：复核后坚持阻止", 1)
    assert retry.status_code == 200
    assert retry.json()["version"] == 2
    assert retry.json()["verdict"] == "block"


def test_timed_exception_expiry_with_injected_clock(client):
    batch, _, _ = _batch(client)
    resp = _put(client, batch, "exception", "灰度窗口内放行", 0,
                expires="2026-03-08T00:00:00+00:00")
    assert resp.status_code == 200
    assert resp.json()["active"] is True

    client.clock.advance(days=8)
    rid = batch["requests"][0]["request_id"]
    view = client.get(f"/api/batches/{batch['id']}").json()
    decision = view["requests"][0]["decision"]
    assert decision["active"] is False


def test_exception_requires_future_expiry(client):
    batch, _, _ = _batch(client)
    assert _put(client, batch, "exception", "缺到期时间", 0).status_code == 400
    past = _put(client, batch, "exception", "已过期", 0,
                expires="2026-02-01T00:00:00+00:00")
    assert past.status_code == 400


def test_decision_bound_to_batch_revision_not_carried_by_rule_reupload(client):
    batch, r1, _ = _batch(client)
    assert _put(client, batch, "accept", "本批次接受", 0).status_code == 200

    # 规则重传生成新版本与新批次（同输入），旧决议不自动沿用
    r3 = client.post("/api/rules", json={
        "name": "cand-v3", "rule": CANDIDATE_RULE, "parent_id": r1["id"],
    }).json()
    body = {
        "idempotency_key": "dec-reupload",
        "current_rule_id": r1["id"],
        "candidate_rule_id": r3["id"],
        "secret_paths": ["auth.token"],
        "requests": [
            {"request": {"profile": {"vip": False, "age": 17}, "risk": {"score": 90},
                         "auth": {"token": "secret-token-xyz"}}},
        ],
    }
    new_batch = client.post("/api/batches", json=body).json()
    assert "decision" not in new_batch["requests"][0]

    export = client.get(f"/api/batches/{batch['id']}/export").json()
    diff = export["differences"][0]
    assert diff["decision"]["verdict"] == "accept"
    assert diff["decision"]["batch_revision"] == batch["revision"]


def test_invalid_verdict_rejected(client):
    batch, _, _ = _batch(client)
    assert _put(client, batch, "nuke", "x", 0).status_code == 400
