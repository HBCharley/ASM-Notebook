from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

os.environ.setdefault(
    "ASM_DATABASE_URL", "postgresql+psycopg://user:pass@localhost:5432/testdb"
)

from asm_notebook.db import Base
from asm_notebook.models import Company, ScanArtifact, ScanRun, User
from asm_notebook.services import finding_service, preference_service, soc_service


@pytest.fixture()
def mem_session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, future=True, autoflush=False, autocommit=False)
    with SessionLocal() as session:
        yield session


def _mk_scan(session: Session, company: Company, number: int) -> ScanRun:
    scan = ScanRun(
        company_id=company.id,
        company_scan_number=number,
        status="success",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        notes="seed",
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def test_finding_generation_rules_cover_key_cases() -> None:
    company_id = uuid.uuid4()
    scan_id = 123
    intel_rows = [
        {
            "domain": "takeover.example.com",
            "root": "example.com",
            "resolves": False,
            "takeover_risk": True,
            "takeover_targets": ["foo.herokudns.com"],
            "has_cname": True,
            "ip_count": 0,
            "web": {"reachable": False, "error": "request_failed"},
        },
        {
            "domain": "www.example.com",
            "root": "example.com",
            "resolves": True,
            "ip_count": 1,
            "web": {
                "reachable": True,
                "scheme": "https",
                "final_url": "https://www.example.com/",
                "status_code": 200,
                "title": "Home",
                "security_headers": {},
                "hsts": {},
                "tls": {"not_after": (datetime.now(timezone.utc)).isoformat()},
                "deep_scan": {
                    "enabled": True,
                    "robots": {"present": False, "status_code": 404, "final_url": "https://www.example.com/robots.txt"},
                    "sitemap": {"present": False, "status_code": 404, "final_url": "https://www.example.com/sitemap.xml"},
                },
            },
        },
    ]
    findings = finding_service.generate_findings(
        company_id=company_id, scan_id=scan_id, intel_rows=intel_rows, prev_intel_rows=[]
    )
    keys = {(f.asset_hostname, f.rule_key) for f in findings}
    assert ("takeover.example.com", "takeover.dangling_cname") in keys
    assert ("takeover.example.com", "dns.unresolved") in keys
    assert ("www.example.com", "web.missing_security_headers") in keys
    assert ("www.example.com", "web.missing_hsts") in keys
    assert ("www.example.com", "web.robots_missing") in keys
    assert ("www.example.com", "web.sitemap_missing") in keys


def test_findings_persisted_per_scan(mem_session: Session) -> None:
    company = Company(slug="acme", name="Acme")
    mem_session.add(company)
    mem_session.commit()
    mem_session.refresh(company)
    scan = _mk_scan(mem_session, company, 1)

    intel_rows = [
        {
            "domain": "a.acme.test",
            "root": "acme.test",
            "resolves": False,
            "ip_count": 0,
            "web": {"reachable": False},
        }
    ]
    finding_service.persist_findings_for_scan(
        mem_session,
        company_id=company.id,
        scan_id=scan.id,
        intel_rows=intel_rows,
        prev_intel_rows=[],
    )
    mem_session.commit()
    rows = finding_service.list_findings_for_scan(mem_session, scan_id=scan.id)
    assert len(rows) >= 1
    assert any(r.rule_key == "dns.unresolved" for r in rows)


def test_user_preference_round_trip(mem_session: Session) -> None:
    user = User(email="user@example.com", is_admin=False, group_id=None)
    mem_session.add(user)
    mem_session.commit()
    mem_session.refresh(user)

    preference_service.set_preference(
        mem_session, user_id=user.id, key="soc.filters.v1", value={"showUnresolved": True}
    )
    loaded = preference_service.get_preference(
        mem_session, user_id=user.id, key="soc.filters.v1"
    )
    assert loaded == {"showUnresolved": True}


def test_soc_overview_shapes_assets_and_removed(mem_session: Session) -> None:
    company = Company(slug="soc", name="SOC Co")
    mem_session.add(company)
    mem_session.commit()
    mem_session.refresh(company)

    scan1 = _mk_scan(mem_session, company, 1)
    scan2 = _mk_scan(mem_session, company, 2)

    intel1 = {
        "domains": [
            {
                "domain": "gone.example.com",
                "root": "example.com",
                "is_apex": False,
                "resolves": True,
                "ip_count": 1,
                "has_ipv6": False,
                "web": {"reachable": True, "final_url": "https://gone.example.com", "status_code": 200, "title": "Gone"},
            }
        ],
        "summary": {},
    }
    intel2 = {
        "domains": [
            {
                "domain": "live.example.com",
                "root": "example.com",
                "is_apex": False,
                "resolves": True,
                "ip_count": 1,
                "has_ipv6": True,
                "web": {"reachable": True, "final_url": "https://live.example.com", "status_code": 200, "title": "Live"},
            }
        ],
        "summary": {},
    }
    mem_session.add_all(
        [
            ScanArtifact(scan_id=scan1.id, artifact_type="dns_intel", json_text=json.dumps(intel1)),
            ScanArtifact(scan_id=scan1.id, artifact_type="dns", json_text=json.dumps({"records": [{"domain": "gone.example.com", "ips": ["1.2.3.4"]}]})),
            ScanArtifact(scan_id=scan2.id, artifact_type="dns_intel", json_text=json.dumps(intel2)),
            ScanArtifact(scan_id=scan2.id, artifact_type="dns", json_text=json.dumps({"records": [{"domain": "live.example.com", "ips": ["1.2.3.4", "::1"]}]})),
        ]
    )
    mem_session.commit()

    # Seed findings for scan2 so overview can aggregate.
    finding_service.persist_findings_for_scan(
        mem_session,
        company_id=company.id,
        scan_id=scan2.id,
        intel_rows=intel2["domains"],
        prev_intel_rows=intel1["domains"],
    )
    mem_session.commit()

    payload = soc_service.get_soc_overview(mem_session, company=company, scan_id=scan2.id)
    assert payload["scan"]["id"] == scan2.id
    assert payload["previous_scan"]["id"] == scan1.id
    assert payload["summary"]["removed_assets"] == 1
    assert payload["removed_assets"][0]["hostname"] == "gone.example.com"
    assert any(a["hostname"] == "live.example.com" for a in payload["assets"])
