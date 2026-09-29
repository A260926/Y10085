import pytest
from fastapi.testclient import TestClient

from shadow_rules.clock import FakeClock
from shadow_rules.web import create_app


@pytest.fixture
def clock():
    return FakeClock("2026-03-01T00:00:00+00:00")


@pytest.fixture
def client(tmp_path, clock):
    app = create_app(str(tmp_path / "test.db"), clock=clock, seed=False)
    with TestClient(app) as c:
        c.clock = clock
        c.db_path = str(tmp_path / "test.db")
        yield c
