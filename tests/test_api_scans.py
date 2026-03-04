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
def client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> TestClient:
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
    class _DummyCompany:
        def __init__(self, slug: str, cid: int = 1):
            self.id = cid
            self.slug = slug
            self.name = slug
            self.domains = []
            self.owner_email = "admin@example.com"
            self.visibility = "private"

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

    def _enforce_company_access(session, principal, slug, write=False, scan=False):
        if slug in {"b"}:
            from fastapi import HTTPException

            raise HTTPException(status_code=404, detail="Company not found")
        return _DummyCompany(slug)

    monkeypatch.setattr(api_main, "_enforce_company_access", _enforce_company_access)

    created: dict[str, dict[str, object]] = {}
    scans: list[dict[str, object]] = []
    next_scan_number = {"value": 1}

    def _create_company(
        slug,
        name,
        domains,
        owner_email=None,
        visibility="private",
        group_names=None,
    ):
        created[slug] = {
            "id": len(created) + 1,
            "slug": slug,
            "name": name,
            "domains": domains,
            "owner_email": owner_email,
            "visibility": visibility,
        }
        return created[slug]

    def _trigger_scan(slug, background_tasks, deep_scan=False, principal=None):
        num = next_scan_number["value"]
        next_scan_number["value"] += 1
        scan = {
            "company_slug": slug,
            "scan_id": num,
            "company_scan_number": num,
            "status": "queued",
        }
        scans.insert(0, scan)
        return scan

    def _list_scans(slug):
        return scans

    def _get_scan_by_number(slug, company_scan_number):
        for scan in scans:
            if scan["company_scan_number"] == company_scan_number:
                return {
                    "id": scan["scan_id"],
                    "company_scan_number": scan["company_scan_number"],
                }
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Scan not found for company")

    monkeypatch.setattr(api_main.company_service, "create_company", _create_company)
    monkeypatch.setattr(api_main.scan_service, "trigger_scan", _trigger_scan)
    monkeypatch.setattr(api_main.scan_service, "list_scans", _list_scans)
    monkeypatch.setattr(api_main.scan_service, "get_company_scan_by_number", _get_scan_by_number)

    with TestClient(api_main.app) as test_client:
        yield test_client
    api_main.app.dependency_overrides.clear()


def test_create_company(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/companies",
        json={"slug": "acme", "name": "Acme Inc", "domains": ["example.com"]},
    )
    assert resp.status_code == 201
    payload = resp.json()
    assert payload["slug"] == "acme"
    assert payload["name"] == "Acme Inc"
    assert payload["domains"] == ["example.com"]


def test_trigger_scan_and_stable_numbering(client: TestClient) -> None:
    create = client.post(
        "/api/v1/companies",
        json={"slug": "acme", "name": "Acme Inc", "domains": ["example.com"]},
    )
    assert create.status_code == 201

    first = client.post("/api/v1/companies/acme/scans")
    second = client.post("/api/v1/companies/acme/scans")
    assert first.status_code == 201
    assert second.status_code == 201

    first_payload = first.json()
    second_payload = second.json()
    assert first_payload["company_scan_number"] == 1
    assert second_payload["company_scan_number"] == 2

    scans = client.get("/api/v1/companies/acme/scans")
    assert scans.status_code == 200
    scan_list = scans.json()
    assert [s["company_scan_number"] for s in scan_list] == [2, 1]

    by_num_1 = client.get("/api/v1/companies/acme/scans/by-number/1")
    by_num_2 = client.get("/api/v1/companies/acme/scans/by-number/2")
    assert by_num_1.status_code == 200
    assert by_num_2.status_code == 200
    assert by_num_1.json()["id"] == first_payload["scan_id"]
    assert by_num_2.json()["id"] == second_payload["scan_id"]


def test_cross_company_scan_access_returns_404(client: TestClient) -> None:
    a = client.post(
        "/api/v1/companies", json={"slug": "a", "name": "A", "domains": ["a.com"]}
    )
    b = client.post(
        "/api/v1/companies", json={"slug": "b", "name": "B", "domains": ["b.com"]}
    )
    assert a.status_code == 201
    assert b.status_code == 201

    scan_resp = client.post("/api/v1/companies/a/scans")
    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()["scan_id"]
    scan_num = scan_resp.json()["company_scan_number"]

    assert client.get(f"/api/v1/companies/b/scans/{scan_id}").status_code == 404
    assert (
        client.get(f"/api/v1/companies/b/scans/{scan_id}/artifacts").status_code == 404
    )
    assert (
        client.get(f"/api/v1/companies/b/scans/by-number/{scan_num}").status_code == 404
    )

    # Global endpoint removed: only company-scoped artifacts are allowed.
    assert client.get(f"/api/v1/scans/{scan_id}/artifacts").status_code == 404
