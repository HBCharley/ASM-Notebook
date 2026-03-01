# ASM Notebook

ASM Notebook is a passive, multi-company Attack Surface Management (ASM) backend.
It performs non-intrusive OSINT-based asset discovery (Certificate Transparency + passive DNS)
and stores structured historical scan data per company.

This project intentionally avoids invasive probing and focuses on publicly available signals only.

## Stack

- Python 3.13
- FastAPI API
- Typer CLI
- SQLAlchemy ORM
- PostgreSQL (required at runtime)
- Poetry or pip/venv for dependency management
- Uvicorn for development server
- React + Vite frontend (`frontend/`)

## Project Layout

- Canonical backend implementation lives in `asm_notebook/`.
- Root-level files (`api_main.py`, `models.py`, `db.py`, `init_db.py`, `cli.py`) are compatibility shims that re-export from `asm_notebook/*`.
- API routing/validation lives in `asm_notebook/api_main.py` under `/v1`.
- Service-layer logic lives in `asm_notebook/services/` (`scan_service.py`, `company_service.py`).

## Core Principles

- Passive-only discovery (no active scanning)
- Multi-company isolation
- Historical scan tracking
- Local-first architecture
- Structured JSON artifacts
- Hardened company-scoped access

## CVE Data

- CVE enrichment uses NVD JSON feeds (last 2 years by default) cached under `asm_notebook/data/nvd/`.
- Configure with environment variables:
- `ASM_NVD_YEARS` (default `2`)
- `ASM_NVD_REFRESH=1` to force re-download
- `ASM_NVD_DISABLE=1` to skip CVE lookups
- Cache warm-up: run any scan once (or hit any scan endpoint that returns artifacts) to trigger the initial NVD download.

## ASN Lookups

- ASN lookups use RDAP via `ipwhois`. You can cap socket wait time with:
- `ASM_ASN_TIMEOUT_SECONDS` (default `5`)

## HTTP Metadata Timeouts

- HTTP metadata collection timeout (seconds):
- `ASM_HTTP_TIMEOUT_SECONDS` (default `5`)

## Scan Timings

- Each scan stores a `timings` artifact with per-step durations (seconds).

## Data Model

- `Company`
- `CompanyDomain`
- `ScanRun`
- `ScanArtifact`

`ScanRun` includes a per-company scan number:

- `id` (global primary key)
- `company_id` (FK)
- `company_scan_number` (increments per company)

There is a unique constraint on `(company_id, company_scan_number)` for stable per-company numbering.

## Requirements

- Python 3.13+
- Poetry (optional) or pip + venv
- Node.js 18+
- Network access (for live crt.sh + DNS + HTTP metadata collection)

## Install (Poetry)

```powershell
poetry install
```

Run DB migrations:

```powershell
poetry run alembic upgrade head
```

## Install (pip + venv)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install "uvicorn[standard]"
```

Run DB migrations:

```powershell
.\.venv\Scripts\Activate.ps1
alembic upgrade head
```

## Run the API (Poetry)

```powershell
$env:ASM_DATABASE_URL = "<your PostgreSQL URL>"
poetry run uvicorn asm_notebook.api_main:app --reload
```

## Run the API (pip + venv)

```powershell
.\.venv\Scripts\Activate.ps1
$env:ASM_DATABASE_URL = "<your PostgreSQL URL>"
python -m uvicorn asm_notebook.api_main:app --reload --host 127.0.0.1 --port 8000
```

## Docker Compose (PostgreSQL + API)

Create an env file:

```powershell
Copy-Item .env.example .env
```

Build and start:

```powershell
docker compose up --build
```

Notes:

- Set `ASM_DATABASE_URL` in `.env` (no credentials are stored in the repo).

Health check:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/health"
```

Health check:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/health"
```

## Demo Runbook

Local dev (Docker):

1. `docker compose up --build`
2. Verify health:
   - `curl http://127.0.0.1:8000/health`

One-time migration flow:

1. Start PostgreSQL only:
   - `docker compose up -d db`
2. Run the migration script:
   - `python .\scripts\migrate_sqlite_to_postgres.py --sqlite sqlite:///path/to/asm_notebook.sqlite3 --postgres "<your PostgreSQL URL>" --yes-i-know-this-truncates`
3. Verify row counts (script outputs table counts and asserts equality).

API validation (curl):

- `curl http://127.0.0.1:8000/health`
- `curl http://127.0.0.1:8000/v1/companies`
- `curl -X POST http://127.0.0.1:8000/v1/companies -H "Content-Type: application/json" -d "{\"slug\":\"example\",\"name\":\"Example Company\",\"domains\":[\"example.com\"]}"`
- `curl -X POST http://127.0.0.1:8000/v1/companies/example/scans`

## Deployment Notes (GCP Demo)

Recommended: Cloud Run + Cloud SQL (PostgreSQL).

Required env vars:

- `ASM_DATABASE_URL` (PostgreSQL URL)
- `ASM_CORS_ORIGINS` (comma-separated allowed origins)
- `ASM_TEST_MODE` (optional, default `0`)

Security notes:

- Use least-privilege DB credentials.
- Do not expose the database publicly.
- If using Cloud SQL, connect via the Cloud SQL connector or private IP.

## Frontend

```powershell
cd frontend
npm install
npm run dev -- --host 127.0.0.1 --port 5173
```

Open:

- `http://127.0.0.1:5173/`

Notes:

- The frontend uses a Vite proxy to the backend for API routes (`/v1` in `vite.config.js`).
- Keep backend running on `127.0.0.1:8000` while using frontend dev mode.
- API versioning: `/v1/*` routes are available.
- Frontend can override the prefix with `VITE_API_PREFIX` (default `/v1`).

## Frontend UX

- View modes:
  - `Standard` (default) and `Executive` (KPI-focused) plus `SOC Analyst` (high-density) are available via the header switcher.
  - Mode selection persists in local storage under `asm_ui_mode`.
- Customer selection is dropdown-driven:
  - Default option is `Add Customer`
  - Creating a customer requires `Customer name` and `Domain`
  - Slug is auto-generated uniquely on create
- Customer details (rename + domains) live in a modal (`Manage details`)
- Customer and Scans sections can be minimized; state is saved in local storage
- Customer and Scans sections are vertically resizable; heights persist in local storage
- Scan execution:
  - Starting a scan shows an in-progress visualization
  - New scan starts are blocked while a scan is running
  - Scans are tagged as `Standard` or `Deep` based on the toggle
  - Deep scan toggle expands HTTP enrichment (additional paths + fingerprints)
- Artifacts visualization:
  - Interactive hub/spoke graph for scope roots and discovered domains
  - Optional `Tree view` (`Scope Browser`) to navigate roots/domains and focus graph nodes
  - Click domain labels or dots to open details (labels do not jump on hover)
  - Hover or click nodes to inspect DNS summary (`A`, `AAAA`, `CNAME`, `MX`, `NS`)
  - Clicking a node pins details; pinned view overlays the artifact panel for full detail
  - Hovering a hub/root shows a spoke list; clicking a spoke focuses that node
  - `Ctrl + Scroll` zooms graph, drag to pan, `Reset` restores view
  - Graph supports adaptive detail levels, label caps, and force layout for crowded scans
  - Root WHOIS (RDAP) shown in artifacts overlay (new scans)
  - Enriched fields shown per domain:
    - DNS posture: SPF/DMARC/MTA-STS/BIMI/DKIM/CNAME takeover checks, wildcard detection
    - Web posture: security headers, HSTS, TLS/cert details (best-effort), reported server versions
    - Fingerprints/tech: Wappalyzer-style hints + favicon hashes
    - Edge/CDN: provider signals + ASN mapping
    - Exposure scoring and change summary
    - Deep scan results (favicon/robots/sitemap response metadata)
- Artifacts tools:
  - Show source JSON per artifact and per domain detail panel
  - Export full artifacts JSON to file
- Theme:
  - Light/dark toggle in Settings with per-user persistence
- Multi-user (UI only):
  - Switch between users (no real auth)
  - Admins can manage users, groups, and company group assignments
  - Settings includes an admin-only Manage companies panel for group assignment
  - Standard users only see companies assigned to their group

## CLI

```powershell
poetry run python -m asm_notebook.cli --help
```

Examples:

```powershell
# Add a company
poetry run python -m asm_notebook.cli company add testco "Test Co" --domain example.com

# Update domains
poetry run python -m asm_notebook.cli company set-domain testco --domain example.com --domain example.org

# Run a scan
poetry run python -m asm_notebook.cli scan run testco

# List scans
poetry run python -m asm_notebook.cli scan list testco

# Export a scan to JSON
poetry run python -m asm_notebook.cli scan export 1 --out-json out.json

# Delete a scan (scoped to company)
poetry run python -m asm_notebook.cli scan delete testco 1

# Delete a company (and all scans/artifacts)
poetry run python -m asm_notebook.cli company delete testco --yes
```

## API Endpoints

Health:

- `GET /health`

Companies:

- `POST /v1/companies`
- `GET /v1/companies`
- `GET /v1/companies/{slug}`
- `PUT /v1/companies/{slug}/domains`
- `PATCH /v1/companies/{slug}`
- `DELETE /v1/companies/{slug}`

Scans (company-scoped and hardened):

- `POST /v1/companies/{slug}/scans`
- `GET /v1/companies/{slug}/scans`
- `GET /v1/companies/{slug}/scans/latest`
- `GET /v1/companies/{slug}/scans/{scan_id}`
- `GET /v1/companies/{slug}/scans/{scan_id}/artifacts`
- `GET /v1/companies/{slug}/scans/by-number/{company_scan_number}`
- `DELETE /v1/companies/{slug}/scans/{scan_id}`

### API Examples

Create a company:

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/v1/companies" -ContentType "application/json" -Body '{
  "slug": "example",
  "name": "Example Company",
  "domains": ["example.com"]
}'
```

Trigger a scan:

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/v1/companies/example/scans"
```

The scan trigger returns immediately with a running scan record, for example:

```json
{
  "company_slug": "example",
  "scan_id": 12,
  "company_scan_number": 4,
  "status": "running"
}
```

List scans:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/v1/companies/example/scans" | ConvertTo-Json -Depth 5
```

Fetch artifacts:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/v1/companies/example/scans/1/artifacts" | ConvertTo-Json -Depth 8
```

Fetch by per-company scan number:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/v1/companies/example/scans/by-number/1"
```

## Scan Execution Flow

### Standard Scan (Deep Scan off)

1. `POST /v1/companies/{slug}/scans` creates a `ScanRun` row with status `running` and schedules background work.
2. Collect subdomains via Certificate Transparency (`crt.sh`).
3. Scope-filter against root domains.
4. Passive DNS resolution (A/AAAA/CNAME/MX/NS/TXT/CAA).
5. Basic DNS intel (SPF/DMARC presence, MTA-STS, BIMI flags).
6. Basic HTTP metadata (status, redirect chain, key headers) with tight limits.
7. Edge/CDN/WAF inference from CNAME/headers/ASN (if available).
8. Persist artifacts (`domains`, `dns`, `web`, `dns_intel`, `ct_enrichment`, `wildcard`).

### Deep Scan (Deep Scan on)

1. All Standard scan steps, plus:
2. HTTP metadata expansion (body snippet, extra paths, tech fingerprinting).
3. Favicon hash + known-app mapping.
4. ASN enrichment + geo/org mapping for each IP.
5. Reverse DNS per IP.
6. Certificate parsing per host (SAN analysis).
7. NVD/CVE correlation (only when version confidence is high).
8. Change detection across scans (diff + churn metrics).
9. Exposure scoring with more features.
   - `whois` (RDAP for root domains)
   - `change_summary`
9. Update `ScanRun` progress notes during execution (e.g., `3/6 Persisting domains...`) and finalize status/timestamps (`success` or `failed`).

## Data & Storage

- The app requires PostgreSQL at runtime.
- Set `ASM_DATABASE_URL` to your PostgreSQL URL.
- Legacy Heroku-style URLs (`postgres://...`) are auto-normalized at startup.
- Local Dockerized PostgreSQL is available via `docker-compose.yml`.
- Scan artifacts are stored as JSON in the database and can be exported via `scan export`.
- The database file is intentionally excluded from Git.

## One-Time Legacy DB -> PostgreSQL Migration

Use the migration script to move data from an existing legacy DB file into PostgreSQL:

```powershell
python .\scripts\migrate_sqlite_to_postgres.py `
  --sqlite sqlite:///path/to/asm_notebook.sqlite3 `
  --postgres "<your PostgreSQL URL>" `
  --yes-i-know-this-truncates
```

The script truncates destination tables and reloads all rows in dependency order.

## POC Closeout and Cloud Migration

- POC closeout checklist: `docs/POC_CLOSEOUT_CHECKLIST.md`
- Operational handoff notes: `docs/OPERATIONAL_HANDOFF_NOTES.md`
- GCP migration plan: `docs/GCP_MIGRATION_PLAN.md`

## GCP Deployment Baseline

Container assets included:

- Backend image: `Dockerfile`
- Frontend image: `frontend/Dockerfile` (+ SPA nginx config in `frontend/nginx.conf`)
- Cloud Build pipelines:
  - `dev-api.yaml`
  - `dev-frontend.yaml`

Backend deploy via Cloud Build:

```powershell
gcloud builds submit --config dev-api.yaml
```

Frontend deploy via Cloud Build:

```powershell
gcloud builds submit --config dev-frontend.yaml
```

For frontend-to-API routing in cloud, set `_VITE_API_BASE` substitution in `dev-frontend.yaml`
to your backend URL (for example: `https://asm-api-xxxxx-uc.a.run.app`).

## Testing

Use deterministic test mode to bypass external CT/DNS/HTTP calls:

```powershell
$env:ASM_TEST_MODE = "1"
poetry run python -m pytest -q
```

## Formatting & Line Endings

- Python files are formatted with Black.
- `.gitattributes` enforces LF line endings for source files to keep GitHub raw views readable.

## Known Gaps

- Service layer lives under `asm_notebook/services/`.
- No external job queue yet (uses FastAPI background tasks; RQ/Celery would be better for concurrency/retries).

## Safety / Scope

This repository is intended for authorized security assessment and learning.
Only analyze domains you own or have explicit permission to assess.
