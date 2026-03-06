from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient


def _reload_api_main(monkeypatch: pytest.MonkeyPatch):
    import asm_notebook.api_main as api_main
    import asm_notebook.db as db
    import asm_notebook.models as models
    import asm_notebook.init_db as init_db

    importlib.reload(db)
    importlib.reload(models)
    importlib.reload(init_db)
    api_main = importlib.reload(api_main)
    monkeypatch.setattr(api_main, "init_db", lambda: None)
    monkeypatch.setattr(api_main.group_service, "ensure_default_groups", lambda: None)
    return api_main


def test_startup_requires_google_client_id_when_not_demo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GOOGLE_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.setenv("DEMO_MODE", "false")
    monkeypatch.setenv("ENABLE_TASKS", "false")
    api_main = _reload_api_main(monkeypatch)
    with pytest.raises(RuntimeError, match="GOOGLE_OAUTH_CLIENT_ID must be set"):
        api_main._validate_startup_config()


def test_startup_requires_task_secret_when_tasks_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("ENABLE_TASKS", "true")
    monkeypatch.delenv("ASM_TASKS_SECRET", raising=False)
    api_main = _reload_api_main(monkeypatch)
    with pytest.raises(RuntimeError, match="ASM_TASKS_SECRET must be set"):
        api_main._validate_startup_config()


def test_tasks_run_scan_requires_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("ASM_TASKS_SECRET", "topsecret")
    monkeypatch.setenv("ENABLE_TASKS", "true")
    api_main = _reload_api_main(monkeypatch)
    monkeypatch.setattr(api_main.scan_service, "run_scan_task", lambda scan_id: None)

    with TestClient(api_main.app) as client:
        missing = client.post("/api/v1/tasks/run_scan", json={"scan_id": 1})
        assert missing.status_code == 403

        wrong = client.post(
            "/api/v1/tasks/run_scan",
            json={"scan_id": 1},
            headers={"X-Tasks-Secret": "wrong"},
        )
        assert wrong.status_code == 403

        ok = client.post(
            "/api/v1/tasks/run_scan",
            json={"scan_id": 1},
            headers={"X-Tasks-Secret": "topsecret"},
        )
        assert ok.status_code == 200
