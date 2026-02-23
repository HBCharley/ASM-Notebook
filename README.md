# ASM Notebook

ASM Notebook is a passive, multi-company Attack Surface Management (ASM) backend.
It performs non-intrusive OSINT-based asset discovery (Certificate Transparency + passive DNS)
and stores structured historical scan data per company.

## Stack

- Python 3.13
- FastAPI API
- Typer CLI
- SQLAlchemy ORM
- SQLite (`asm_notebook.sqlite3`)
- Poetry for dependency management
- Uvicorn for development server

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

## Setup

```powershell
poetry install
```

## Run the API

```powershell
poetry run uvicorn asm_notebook.api_main:app --reload
```

Health check:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/health"
```

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

- `POST /companies`
- `GET /companies`
- `PUT /companies/{slug}/domains`
- `DELETE /companies/{slug}`

Scans (company-scoped and hardened):

- `POST /companies/{slug}/scans`
- `GET /companies/{slug}/scans`
- `GET /companies/{slug}/scans/{scan_id}`
- `GET /companies/{slug}/scans/{scan_id}/artifacts`
- `GET /companies/{slug}/scans/by-number/{company_scan_number}`
- `DELETE /companies/{slug}/scans/{scan_id}`

### API Examples

Create a company:

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/companies" -ContentType "application/json" -Body '{
  "slug": "deepgram",
  "name": "Deepgram",
  "domains": ["deepgram.com"]
}'
```

Trigger a scan:

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/companies/deepgram/scans"
```

List scans:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/companies/deepgram/scans" | ConvertTo-Json -Depth 5
```

Fetch artifacts:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/companies/deepgram/scans/1/artifacts" | ConvertTo-Json -Depth 8
```

Fetch by per-company scan number:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/companies/deepgram/scans/by-number/1"
```

## Scan Execution Flow

1. Collect subdomains via Certificate Transparency (`crt.sh`).
2. Scope-filter against root domains.
3. Perform passive DNS resolution (A/AAAA/CNAME/MX/NS).
4. Persist artifacts:
   - `domains`
   - `dns`
5. Update `ScanRun` status and timestamps.

## Notes on SQLite Migration

If you created `asm_notebook.sqlite3` before the `company_scan_number` column existed,
run a migration to add it and backfill per company. The required steps are:

1. Add the column to `scan_runs`.
2. Backfill numbers per company in `id` order.
3. Add a unique index on `(company_id, company_scan_number)`.

If you want a scripted migration, ask and it can be provided.

## Known Gaps

- No service layer yet (scan logic is in the API/CLI).
- No Alembic migrations.
- No deterministic test mode (external CT/DNS required).
- No background task queue (scan runs synchronously).
- No frontend yet.
