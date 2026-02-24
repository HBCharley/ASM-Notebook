from __future__ import annotations

import importlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

@pytest.fixture()
def authed_client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> TestClient:
    db_path = tmp_path / "test-auth.sqlite3"
    monkeypatch.setenv("ASM_DB_PATH", str(db_path))
    monkeypatch.setenv("ASM_TEST_MODE", "1")
    monkeypatch.setenv("ASM_BASIC_AUTH_USER", "admin")
    monkeypatch.setenv("ASM_BASIC_AUTH_PASS", "secret")

    import asm_notebook.db as db
    import asm_notebook.models as models
    import asm_notebook.init_db as init_db
    import asm_notebook.api_main as api_main

    importlib.reload(db)
    importlib.reload(models)
    importlib.reload(init_db)
    api_main = importlib.reload(api_main)

    with TestClient(api_main.app) as test_client:
        yield test_client


def test_health_stays_open_with_auth_enabled(authed_client: TestClient) -> None:
    resp = authed_client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_api_routes_stay_open_with_auth_env_set(authed_client: TestClient) -> None:
    resp = authed_client.get("/companies")
    assert resp.status_code == 200
    assert resp.json() == []
