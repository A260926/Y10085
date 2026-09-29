"""API surface: seed batch categories, secret-leak scan, export."""
import json

from conftest import make_batch

SECRET = "123-45-6789"


def test_seed_batch_shows_both_diff_categories(client):
    batches = client.get("/api/batches").json()["batches"]
    seed = [b for b in batches if b["idempotency_key"] == "seed:baseline-vs-candidate"]
    assert seed, "preset batch missing"
    detail = client.get(f"/api/batches/{seed[0]['id']}").json()
    categories = {d["request_id"]: d["category"] for d in detail["diffs"]}
    assert categories["req-001"] == "outcome"   # 不同结果
    assert categories["req-002"] == "path"      # 同结果不同路径
    # req-001: baseline True vs candidate False
    diff1 = [d for d in detail["diffs"] if d["request_id"] == "req-001"][0]
    assert diff1["a"]["outcome"] is True
    assert diff1["b"]["outcome"] is False
    # req-002: same outcome, different accessed fields / path
    diff2 = [d for d in detail["diffs"] if d["request_id"] == "req-002"][0]
    assert diff2["a"]["outcome"] == diff2["b"]["outcome"]
    assert diff2["a"]["accessed_fields"] != diff2["b"]["accessed_fields"]


def test_index_page_renders_title(client):
    html = client.get("/").text
    assert "配置影子演算室" in html


def test_rule_upload_stores_digest_normalized_and_parent(client):
    parent = client.post("/api/rules", json={
        "name": "p", "rule": {"op": "eq", "left": {"field": "a"}, "right": 1}})
    assert parent.status_code == 201
    child = client.post("/api/rules", json={
        "name": "c", "rule": {"op": "ne", "left": {"field": "a"}, "right": 1},
        "parent_id": parent.json()["id"]})
    assert child.json()["parent_id"] == parent.json()["id"]
    assert len(child.json()["source_digest"]) == 64
    assert child.json()["normalized"]["op"] == "ne"


def test_secret_never_leaks_to_pages_or_export(client):
    upload = client.post("/api/requests", json={"requests": [
        {"id": "sec-1", "body": {"age": 40, "score": 100, "ssn": SECRET,
                                 "profile": {"token": "tok-abc-123"}}}]})
    assert upload.status_code == 201
    batch = client.post("/api/batches", json={
        "idempotency_key": "sec-batch", "rule_a_id": 1, "rule_b_id": 2,
        "request_ids": ["sec-1"]})
    assert batch.status_code == 201
    batch_id = batch.json()["id"]

    surfaces = [
        client.get("/").text,
        client.get("/api/requests").text,
        client.get(f"/api/batches/{batch_id}").text,
        client.get(f"/api/batches/{batch_id}/export").text,
        client.get("/api/batches").text,
    ]
    for surface in surfaces:
        assert SECRET not in surface
        assert "tok-abc-123" not in surface

    # export still carries rule digests, input digest, diffs and decisions
    export = client.get(f"/api/batches/{batch_id}/export").json()
    assert export["rule_a"]["source_digest"]
    assert export["input_digest"]
    assert export["diffs"][0]["request_id"] == "sec-1"
    # stored body keeps the field present but redacted
    stored = client.get("/api/requests").json()["requests"]
    sec = [r for r in stored if r["id"] == "sec-1"][0]
    assert sec["body"]["ssn"] == {"__redacted__": True}
    assert sec["body"]["profile"]["token"] == {"__redacted__": True}


def test_export_includes_decisions(client):
    batch_id = make_batch(client, key="exp-1").json()["id"]
    client.post(f"/api/batches/{batch_id}/diffs/req-001/decision",
                json={"action": "accept", "reason": "风险可控",
                      "expected_version": 0})
    export = client.get(f"/api/batches/{batch_id}/export").json()
    decision = [d for d in export["diffs"]
                if d["request_id"] == "req-001"][0]["decision"]
    assert decision["action"] == "accept"
    assert decision["reason"] == "风险可控"
