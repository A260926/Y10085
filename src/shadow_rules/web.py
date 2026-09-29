"""FastAPI 应用与路由。"""
from __future__ import annotations

import argparse
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .clock import Clock
from .models import BatchCreate, DecisionInput, RuleUpload
from .seed import seed_if_empty
from .service import ConflictError, NotFoundError, Service, ValidationError

STATIC_DIR = Path(__file__).parent / "static"


def create_app(db_path: str = "shadow_rules.db", clock: Clock | None = None,
               seed: bool = True) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        service.recover_pending()
        if seed:
            seed_if_empty(service)
        yield
        service.close()

    app = FastAPI(title="配置影子演算室", version="0.1.0", lifespan=lifespan)
    service = Service(db_path, clock=clock)
    app.state.service = service

    def fail(exc: Exception, status: int) -> HTTPException:
        return HTTPException(status_code=status, detail=str(exc))

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/rules")
    def list_rules() -> list[dict[str, Any]]:
        return service.list_rules()

    @app.post("/api/rules", status_code=201)
    def upload_rule(body: RuleUpload) -> dict[str, Any]:
        try:
            return service.upload_rule(body.name, body.rule, body.parent_id)
        except ValidationError as exc:
            raise fail(exc, 400)

    @app.get("/api/rules/{rule_id}")
    def get_rule(rule_id: str) -> dict[str, Any]:
        try:
            return service.get_rule(rule_id)
        except NotFoundError as exc:
            raise fail(exc, 404)

    @app.get("/api/batches")
    def list_batches() -> list[dict[str, Any]]:
        return service.list_batches()

    @app.post("/api/batches", status_code=201)
    def create_batch(body: BatchCreate) -> JSONResponse:
        try:
            batch = service.create_batch(
                body.idempotency_key,
                body.current_rule_id,
                body.candidate_rule_id,
                body.secret_paths,
                [item.model_dump() for item in body.requests],
            )
        except ConflictError as exc:
            return JSONResponse(status_code=409, content=exc.payload)
        except ValidationError as exc:
            raise fail(exc, 400)
        status = 200 if batch.get("reused") else 201
        return JSONResponse(status_code=status, content=batch)

    @app.get("/api/batches/{batch_id}")
    def get_batch(batch_id: str) -> dict[str, Any]:
        try:
            return service.get_batch(batch_id)
        except NotFoundError as exc:
            raise fail(exc, 404)

    @app.get("/api/batches/{batch_id}/export")
    def export_batch(batch_id: str) -> dict[str, Any]:
        try:
            return service.export_batch(batch_id)
        except NotFoundError as exc:
            raise fail(exc, 404)

    @app.put("/api/batches/{batch_id}/requests/{request_id}/decision")
    def put_decision(batch_id: str, request_id: str, body: DecisionInput) -> Any:
        try:
            return service.put_decision(
                batch_id, request_id, body.verdict, body.reason,
                body.expires_at, body.version,
            )
        except ConflictError as exc:
            return JSONResponse(status_code=409, content=exc.payload)
        except (ValidationError, NotFoundError) as exc:
            code = 404 if isinstance(exc, NotFoundError) else 400
            raise fail(exc, code)

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    return app


def main(argv: list[str] | None = None) -> None:
    import uvicorn

    parser = argparse.ArgumentParser(description="配置影子演算室")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5215)
    parser.add_argument("--db", default="shadow_rules.db")
    args = parser.parse_args(argv)
    uvicorn.run(create_app(args.db), host=args.host, port=args.port)
