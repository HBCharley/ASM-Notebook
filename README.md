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
- SQLite (`asm_notebook.sqlite3`)
- Poetry or pip/venv for dependency management
- Uvicorn for development server
- React + Vite frontend (`frontend/`)

## Core Principles

- Passive-only discovery (no active scanning)
- Multi-company isolation
- Historical scan tracking
- Local-first architecture
- Structured JSON artifacts
- Hardened company-scoped access

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

## Install (pip + venv)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install "uvicorn[standard]"
```

## Run the API (Poetry)

```powershell
# Optional: enable HTTP Basic auth for all API routes except /health
$env:ASM_BASIC_AUTH_USER = "admin"
$env:ASM_BASIC_AUTH_PASS = "change-me"
poetry run uvicorn asm_notebook.api_main:app --reload
```

## Run the API (pip + venv)

```powershell
.\.venv\Scripts\Activate.ps1
# Optional: enable HTTP Basic auth for all API routes except /health
$env:ASM_BASIC_AUTH_USER = "admin"
$env:ASM_BASIC_AUTH_PASS = "change-me"
python -m uvicorn asm_notebook.api_main:app --reload --host 127.0.0.1 --port 8000
```

Health check:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/health"
```

## Frontend

```powershell
cd frontend
npm install
# Optional: pass API basic auth credentials to the web app request client
$env:VITE_BASIC_AUTH_USER = "admin"
$env:VITE_BASIC_AUTH_PASS = "change-me"
npm run dev -- --host 127.0.0.1 --port 5173
```

Open:

- `http://127.0.0.1:5173/`

Notes:

- The frontend uses a Vite proxy to the backend for API routes (`/companies`, `/scan`, `/health`).
- Keep backend running on `127.0.0.1:8000` while using frontend dev mode.
- If API basic auth is enabled, set `VITE_BASIC_AUTH_USER` and `VITE_BASIC_AUTH_PASS` for frontend requests.

## Frontend UX

- Customer selection is dropdown-driven:
  - Default option is `Add Customer`
  - Creating a customer requires `Customer name` and `Domain`
  - Slug is auto-generated uniquely on create
- When an existing customer is selected:
  - Existing domains are listed
  - `Add domain` appends and saves domain scope
- Scan execution:
  - Starting a scan shows an in-progress visualization
  - New scan starts are blocked while a scan is running
- Artifacts visualization:
  - Interactive hub/spoke graph for scope roots and discovered domains
  - Hover or click nodes to inspect DNS summary (`A`, `AAAA`, `CNAME`, `MX`, `NS`)
  - Click pins details in the side panel (`Unpin` to clear)
  - Hovering a hub/root shows a spoke list; clicking a spoke focuses that node
  - `Ctrl + Scroll` zooms graph, drag to pan, `Reset` restores view
  - Graph supports adaptive detail levels and label caps for crowded scans
- Theme:
  - Global light/dark mode toggle in the top bar

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

When `ASM_BASIC_AUTH_USER` and `ASM_BASIC_AUTH_PASS` are set, API routes require HTTP Basic auth
(except `GET /health`).

Health:

- `GET /health`

Companies:

- `POST /companies`
- `GET /companies`
- `GET /companies/{slug}`
- `PUT /companies/{slug}/domains`
- `PATCH /companies/{slug}`
- `DELETE /companies/{slug}`

Scans (company-scoped and hardened):

- `POST /companies/{slug}/scans`
- `GET /companies/{slug}/scans`
- `GET /companies/{slug}/scans/latest`
- `GET /companies/{slug}/scans/{scan_id}`
- `GET /companies/{slug}/scans/{scan_id}/artifacts`
- `GET /companies/{slug}/scans/by-number/{company_scan_number}`
- `DELETE /companies/{slug}/scans/{scan_id}`

### API Examples

Create a company:

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/companies" -ContentType "application/json" -Body '{
  "slug": "example",
  "name": "Example Company",
  "domains": ["example.com"]
}'
```

Trigger a scan:

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/companies/example/scans"
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
Invoke-RestMethod "http://127.0.0.1:8000/companies/example/scans" | ConvertTo-Json -Depth 5
```

Fetch artifacts:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/companies/example/scans/1/artifacts" | ConvertTo-Json -Depth 8
```

Fetch by per-company scan number:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/companies/example/scans/by-number/1"
```

## Scan Execution Flow

1. `POST /companies/{slug}/scans` creates a `ScanRun` row with status `running` and schedules background work.
2. Background worker collects subdomains via Certificate Transparency (`crt.sh`).
3. Scope-filter against root domains.
4. Perform passive DNS resolution (A/AAAA/CNAME/MX/NS) and HTTP metadata checks.
5. Persist artifacts:
   - `domains`
   - `dns`
   - `web`
   - `dns_intel`
6. Update `ScanRun` status/timestamps (`success` or `failed`).

## Data & Storage

- The app uses a local SQLite database (default: `asm_notebook.sqlite3` in the repo root).
- Override DB file path with `ASM_DB_PATH` (useful for tests).
- Scan artifacts are stored as JSON in the database and can be exported via `scan export`.
- The database file is intentionally excluded from Git.

## Notes on SQLite Migration

Startup includes an automatic SQLite compatibility migration for older DB files:

1. Adds `scan_runs.company_scan_number` if missing.
2. Backfills values per company using `id` order.
3. Ensures unique index on `(company_id, company_scan_number)`.

No manual migration step is required for this change.

## Testing

Use deterministic test mode to bypass external CT/DNS/HTTP calls:

```powershell
$env:ASM_TEST_MODE = "1"
poetry run python -m pytest -q
```

## Known Gaps

- No service layer yet (scan logic is in the API/CLI).
- No Alembic migrations.
- No external job queue yet (uses FastAPI background tasks; RQ/Celery would be better for concurrency/retries).

## Safety / Scope

This repository is intended for authorized security assessment and learning.
Only analyze domains you own or have explicit permission to assess.
