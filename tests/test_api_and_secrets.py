from pathlib import Path

from shadow_rules.seed import CURRENT_RULE, CANDIDATE_RULE


SECRET = "TOP-SECRET-VALUE-9f3k"


def _two_rules(client):
    r1 = client.post("/api/rules", json={"name": "cur", "rule": CURRENT_RULE}).json()
    r2 = client.post("/api/rules", json={
        "name": "cand", "rule": CANDIDATE_RULE, "parent_id": r1["id"],
    }).json()
    return r1, r2


def _batch_body(r1, r2, key="k1", with_secret=True):
    requests = [
        {"request": {"profile": {"vip": False, "age": 17}, "risk": {"score": 90},
                     "auth": {"token": SECRET if with_secret else "x"}}},
        {"request": {"profile": {"vip": False, "age": 15}, "risk": {"score": 90},
                     "auth": {}}},
    ]
    return {
        "idempotency_key": key,
        "current_rule_id": r1["id"],
        "candidate_rule_id": r2["id"],
        "secret_paths": ["auth.token"],
        "requests": requests,
    }


def test_rule_upload_stores_raw_summary_normalized_and_parent(client):
    r1, r2 = _two_rules(client)
    assert r2["parent_id"] == r1["id"]
    assert len(r2["digest"]) == 64
    got = client.get(f"/api/rules/{r2['id']}").json()
    assert got["normalized"] == CANDIDATE_RULE


def test_batch_computes_both_sides_and_diff_categories(client):
    r1, r2 = _two_rules(client)
    resp = client.post("/api/batches", json=_batch_body(r1, r2))
    assert resp.status_code == 201
    batch = resp.json()
    assert batch["status"] == "done"
    categories = {r["diff_category"] for r in batch["requests"]}
    assert "decision_difference" in categories
    non_identical = [c for c in categories if c != "identical"]
    assert non_identical


def test_secret_never_leaks_to_api_pages_export_or_db(client, capsys):
    r1, r2 = _two_rules(client)
    resp = client.post("/api/batches", json=_batch_body(r1, r2))
    batch_id = resp.json()["id"]

    surfaces = [
        resp.text,
        client.get(f"/api/batches/{batch_id}").text,
        client.get(f"/api/batches/{batch_id}/export").text,
        client.get("/api/batches").text,
        client.get("/").text,
        client.get("/static/app.js").text,
        Path(client.db_path).read_bytes(),
    ]
    captured = capsys.readouterr()
    surfaces.append(captured.out.encode("utf-8", "ignore"))
    surfaces.append(captured.err.encode("utf-8", "ignore"))

    for surface in surfaces:
        if isinstance(surface, str):
            surface = surface.encode("utf-8")
        assert SECRET.encode() not in surface

    # 导出含规则摘要与输入摘要，且记录 secret 存在性访问
    export = client.get(f"/api/batches/{batch_id}/export").json()
    assert export["rules"]["current"]["digest"]
    assert export["input"]["input_digest"]
    assert export["input"]["secret_paths"] == ["auth.token"]
    assert any(
        "auth.token" in d["candidate"].get("secret_access", [])
        for d in export["differences"]
    )


def test_seed_batch_presented_in_page(tmp_path, clock):
    from fastapi.testclient import TestClient
    from shadow_rules.web import create_app

    app = create_app(str(tmp_path / "seed.db"), clock=clock, seed=True)
    with TestClient(app) as c:
        html = c.get("/").text
        assert "配置影子演算室" in html
        batches = c.get("/api/batches").json()
        assert batches
        detail = c.get(f"/api/batches/{batches[0]['id']}").json()
        cats = {r["diff_category"] for r in detail["requests"]}
        # 预置批次同时覆盖：同结果不同路径 + 不同结果
        assert "decision_difference" in cats
        assert any(
            c in ("short_circuit_difference", "access_trace_difference")
            for c in cats
        )


def test_invalid_rule_rejected(client):
    resp = client.post("/api/rules", json={"name": "bad", "rule": {"eval": "x"}})
    assert resp.status_code == 400
