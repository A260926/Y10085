"""HTTP 入参模型。"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class RuleUpload(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    rule: Any
    parent_id: str | None = None


class BatchRequestItem(BaseModel):
    request: Any


class BatchCreate(BaseModel):
    idempotency_key: str | None = None
    current_rule_id: str
    candidate_rule_id: str
    secret_paths: list[str] = []
    requests: list[BatchRequestItem] = Field(min_length=1)


class DecisionInput(BaseModel):
    verdict: str
    reason: str = Field(min_length=1, max_length=2000)
    expires_at: str | None = None
    version: int
