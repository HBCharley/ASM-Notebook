from __future__ import annotations

import importlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> TestClient:
    db_path = tmp_path / "test.sqlite3"
    monkeypatch.setenv("ASM_DB_PATH", str(db_path))
    monkeypatch.setenv("ASM_TEST_MODE", "1")

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


def test_create_company(client: TestClient) -> None:
    resp = client.post(
        "/companies",
        json={"slug": "acme", "name": "Acme Inc", "domains": ["example.com"]},
    )
    assert resp.status_code == 201
    payload = resp.json()
    assert payload["slug"] == "acme"
    assert payload["name"] == "Acme Inc"
    assert payload["domains"] == ["example.com"]


def test_trigger_scan_and_stable_numbering(client: TestClient) -> None:
    create = client.post(
        "/companies",
        json={"slug": "acme", "name": "Acme Inc", "domains": ["example.com"]},
    )
    assert create.status_code == 201

    first = client.post("/companies/acme/scans")
    second = client.post("/companies/acme/scans")
    assert first.status_code == 201
    assert second.status_code == 201

    first_payload = first.json()
    second_payload = second.json()
    assert first_payload["company_scan_number"] == 1
    assert second_payload["company_scan_number"] == 2

    scans = client.get("/companies/acme/scans")
    assert scans.status_code == 200
    scan_list = scans.json()
    assert [s["company_scan_number"] for s in scan_list] == [2, 1]

    by_num_1 = client.get("/companies/acme/scans/by-number/1")
    by_num_2 = client.get("/companies/acme/scans/by-number/2")
    assert by_num_1.status_code == 200
    assert by_num_2.status_code == 200
    assert by_num_1.json()["id"] == first_payload["scan_id"]
    assert by_num_2.json()["id"] == second_payload["scan_id"]


def test_cross_company_scan_access_returns_404(client: TestClient) -> None:
    a = client.post("/companies", json={"slug": "a", "name": "A", "domains": ["a.com"]})
    b = client.post("/companies", json={"slug": "b", "name": "B", "domains": ["b.com"]})
    assert a.status_code == 201
    assert b.status_code == 201

    scan_resp = client.post("/companies/a/scans")
    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()["scan_id"]
    scan_num = scan_resp.json()["company_scan_number"]

    assert client.get(f"/companies/b/scans/{scan_id}").status_code == 404
    assert client.get(f"/companies/b/scans/{scan_id}/artifacts").status_code == 404
    assert client.get(f"/companies/b/scans/by-number/{scan_num}").status_code == 404

    # Global endpoint removed: only company-scoped artifacts are allowed.
    assert client.get(f"/scans/{scan_id}/artifacts").status_code == 404
