"""FastAPI application for the shadow rules workbench."""
from __future__ import annotations

import inspect
import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from . import engine
from .redact import DEFAULT_SECRET_FIELDS, sanitize
from .rules import digest_rule, digest_text, normalize
from .seed import seed
from .store import Store

STATIC_DIR = Path(__file__).parent / "static"


def system_clock():
    return datetime.now(timezone.utc)


class RuleUpload(BaseModel):
    name: str
    rule: dict | str
    parent_id: int | None = None


class RequestsUpload(BaseModel):
    requests: list[dict]


class BatchCreate(BaseModel):
    idempotency_key: str
    rule_a_id: int
    rule_b_id: int
    request_ids: list[str]


class DecisionSubmit(BaseModel):
    action: str  # accept | block | exception
    reason: str
    expected_version: int = 0
    ttl_seconds: int | None = None


class SchemaUpdate(BaseModel):
    secret_fields: list[str]


def create_app(db_path: str = "shadow_rules.db", clock=None,
               seed_data: bool = True) -> FastAPI:
    clock = clock or system_clock
    store = Store(db_path)
    engine.recover(store, clock)
    fastapi_kwargs = {}
    if "telemetry" in inspect.signature(FastAPI.__init__).parameters:
        fastapi_kwargs["telemetry"] = {"auto_configure": False}
    app = FastAPI(title="配置影子演算室", **fastapi_kwargs)
    app.state.store = store
    app.state.clock = clock
    app.state.secret_fields = list(DEFAULT_SECRET_FIELDS)
    if seed_data:
        seed(store, clock, app.state.secret_fields)

    # -- pages ----------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    def index():
        return (STATIC_DIR / "index.html").read_text(encoding="utf-8")

    # -- schema ---------------------------------------------------------
    @app.get("/api/schema")
    def get_schema():
        return {"secret_fields": app.state.secret_fields}

    @app.post("/api/schema")
    def put_schema(update: SchemaUpdate):
        app.state.secret_fields = list(update.secret_fields)
        return {"secret_fields": app.state.secret_fields}

    # -- rules ----------------------------------------------------------
    @app.post("/api/rules", status_code=201)
    def upload_rule(upload: RuleUpload):
        source_text = (upload.rule if isinstance(upload.rule, str)
                       else json.dumps(upload.rule, ensure_ascii=False))
        try:
            parsed = json.loads(source_text)
        except json.JSONDecodeError as exc:
            return JSONResponse({"error": f"invalid JSON: {exc}"}, 400)
        parent_id = upload.parent_id
        if parent_id is not None and store.get_rule(parent_id) is None:
            return JSONResponse({"error": "unknown parent_id"}, 400)
        row = store.add_rule(upload.name, source_text, digest_text(source_text),
                             normalize(parsed), digest_rule(parsed),
                             parent_id, clock)
        return _rule_view(row)

    @app.get("/api/rules")
    def list_rules():
        return {"rules": [_rule_view(r) for r in store.list_rules()]}

    # -- requests ---------------------------------------------------------
    @app.post("/api/requests", status_code=201)
    def upload_requests(upload: RequestsUpload):
        saved = []
        for item in upload.requests:
            body = item.get("body")
            request_id = item.get("id")
            if not request_id or not isinstance(body, dict):
                return JSONResponse(
                    {"error": "each request needs id and object body"}, 400)
            clean = sanitize(body, app.state.secret_fields)
            row = store.add_request(
                request_id, clean,
                digest_text(json.dumps(clean, sort_keys=True)), clock)
            saved.append({"id": row["id"], "digest": row["digest"]})
        return {"requests": saved}

    @app.get("/api/requests")
    def list_requests():
        return {"requests": [
            {"id": r["id"], "digest": r["digest"],
             "body": json.loads(r["body"])}
            for r in store.list_requests()
        ]}

    # -- batches ----------------------------------------------------------
    @app.post("/api/batches")
    def create_batch(create: BatchCreate, request: Request):
        try:
            batch, created = engine.create_batch(
                store, create.idempotency_key, create.rule_a_id,
                create.rule_b_id, create.request_ids, clock)
        except engine.BatchConflict as exc:
            return JSONResponse({
                "error": "idempotency_conflict",
                "existing_batch_id": exc.batch["id"],
                "existing_input_digest": exc.batch["input_digest"],
            }, 409)
        except KeyError as exc:
            return JSONResponse({"error": str(exc)}, 404)
        return JSONResponse(_batch_view(batch), 201 if created else 200)

    @app.get("/api/batches")
    def list_batches():
        return {"batches": [_batch_view(b) for b in store.list_batches()]}

    @app.get("/api/batches/{batch_id}")
    def get_batch(batch_id: str):
        batch = store.get_batch(batch_id)
        if batch is None:
            return JSONResponse({"error": "unknown batch"}, 404)
        view = _batch_view(batch)
        view["diffs"] = []
        for row in store.list_results(batch_id):
            decision = engine.effective_decision(
                store, batch_id, row["request_id"], batch["revision"], clock)
            stored = store.get_decision(batch_id, row["request_id"],
                                        batch["revision"])
            view["diffs"].append({
                "request_id": row["request_id"],
                "category": row["category"],
                "a": json.loads(row["a_result"]),
                "b": json.loads(row["b_result"]),
                "decision": engine._decision_view(decision),
                "decision_version": stored["version"] if stored else 0,
            })
        return view

    @app.post("/api/batches/{batch_id}/diffs/{request_id}/decision")
    def decide(batch_id: str, request_id: str, submit: DecisionSubmit):
        if submit.action not in ("accept", "block", "exception"):
            return JSONResponse({"error": "action must be accept/block/exception"}, 400)
        try:
            decision, conflict = engine.submit_decision(
                store, batch_id, request_id, submit.action, submit.reason,
                submit.expected_version, submit.ttl_seconds, clock)
        except KeyError as exc:
            return JSONResponse({"error": str(exc)}, 404)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, 400)
        if conflict is not None:
            return JSONResponse(conflict, 409)
        return {"decision": engine._decision_view(decision)}

    @app.get("/api/batches/{batch_id}/export")
    def export(batch_id: str):
        if store.get_batch(batch_id) is None:
            return JSONResponse({"error": "unknown batch"}, 404)
        return engine.export_batch(store, batch_id, clock)

    return app


def _rule_view(row):
    return {
        "id": row["id"],
        "name": row["name"],
        "source_digest": row["source_digest"],
        "normalized": json.loads(row["normalized"]),
        "normalized_digest": row["normalized_digest"],
        "parent_id": row["parent_id"],
        "created_at": row["created_at"],
    }


def _batch_view(row):
    return {
        "id": row["id"],
        "idempotency_key": row["idempotency_key"],
        "input_digest": row["input_digest"],
        "rule_a_id": row["rule_a_id"],
        "rule_b_id": row["rule_b_id"],
        "request_ids": json.loads(row["request_ids"]),
        "revision": row["revision"],
        "status": row["status"],
        "summary": json.loads(row["summary"]) if row["summary"] else None,
        "created_at": row["created_at"],
    }
