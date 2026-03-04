from __future__ import annotations

import importlib
from pathlib import Path
import os

import pytest
from fastapi.testclient import TestClient
os.environ.setdefault(
    "ASM_DATABASE_URL", "postgresql+psycopg://user:pass@localhost:5432/testdb"
)
from asm_notebook.security import Principal

@pytest.fixture()
def authed_client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> TestClient:
    monkeypatch.setenv(
        "ASM_DATABASE_URL", "postgresql+psycopg://user:pass@localhost:5432/testdb"
    )
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("ASM_TEST_MODE", "1")

    import asm_notebook.db as db
    import asm_notebook.models as models
    import asm_notebook.init_db as init_db
    import asm_notebook.api_main as api_main

    importlib.reload(db)
    importlib.reload(models)
    importlib.reload(init_db)
    api_main = importlib.reload(api_main)
    monkeypatch.setattr(api_main, "init_db", lambda: None)
    import asm_notebook.security as security
    api_main.app.dependency_overrides[security.get_principal] = (
        lambda: Principal(
            role="admin",
            email="admin@example.com",
            sub="1",
            authenticated=True,
            group_id=None,
        )
    )
    class _DummyResult:
        def scalars(self):
            return self

        def all(self):
            return []

        def first(self):
            return None

    class _DummySession:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, *args, **kwargs):
            return _DummyResult()

    monkeypatch.setattr(api_main, "SessionLocal", lambda: _DummySession())

    with TestClient(api_main.app) as test_client:
        yield test_client
    api_main.app.dependency_overrides.clear()


def test_health_stays_open_with_auth_enabled(authed_client: TestClient) -> None:
    resp = authed_client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_api_routes_stay_open_with_auth_env_set(authed_client: TestClient) -> None:
    resp = authed_client.get("/api/v1/companies")
    assert resp.status_code == 200
    assert resp.json() == []
