from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from shadow_rules.app import create_app


class FakeClock:
    def __init__(self):
        self.moment = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self):
        return self.moment

    def advance(self, seconds):
        self.moment += timedelta(seconds=seconds)


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test.db")


@pytest.fixture
def client(db_path, clock):
    return TestClient(create_app(db_path=db_path, clock=clock))


def make_batch(client, key="k1", rule_a=1, rule_b=2,
               request_ids=("req-001", "req-002", "req-003")):
    return client.post("/api/batches", json={
        "idempotency_key": key,
        "rule_a_id": rule_a,
        "rule_b_id": rule_b,
        "request_ids": list(request_ids),
    })
