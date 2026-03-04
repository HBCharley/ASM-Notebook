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
- API routing/validation lives in `asm_notebook/api_main.py` under `/api/v1`.
- Service-layer logic lives in `asm_notebook/services/` (`scan_service.py`, `company_service.py`).

## Core Principles

- Passive-only discovery (no active scanning)
- Multi-company isolation
- Historical scan tracking
- Local-first architecture
- Structured JSON artifacts
- Hardened company-scoped access

## Auth & Access Control

- Google OIDC authentication (ID tokens) with optional demo mode.
- Public (unauthenticated or unlisted email) is read-only and limited to companies in the `Unauthenticated` group.
- Authenticated roles:
  - `ADMIN_EMAILS` = full access, can manage users/groups and assign companies to groups.
  - `USER_EMAILS` = limited access to companies in their assigned group.
- Admins can add authenticated users via the database-backed auth allowlist (Admin tools),
  which supplements the env allowlists above.
- Every non-admin user belongs to exactly one group.
- Default groups: `Unauthenticated`, `Default`.
- Keep at least one admin in `ADMIN_EMAILS` so you can always regain access.
- Production hardening:
  - `DEMO_MODE=false` (default) requires `GOOGLE_OAUTH_CLIENT_ID` or the app will refuse to start.
  - `DEMO_MODE=true` is intended for local demos without OAuth.

Use `GET /api/v1/me` to see the effective role and limits.

## CVE Data

- CVE enrichment uses NVD JSON feeds (last 2 years by default) cached under `asm_notebook/data/nvd/`.
- Configure with environment variables:
- `ASM_NVD_YEARS` (default `2`)
- `ASM_NVD_REFRESH=1` to force re-download
- `ASM_NVD_DISABLE=1` to skip CVE lookups
- Cache warm-up: run any scan once (or hit any scan endpoint that returns artifacts) to trigger the initial NVD download.
- Debug CVE cache status:
  - `GET /api/v1/debug/cve`
  - `poetry run python -m asm_notebook.cli cve status --keyword nginx --keyword apache --keyword wordpress`

## ASN Lookups

- ASN lookups use RDAP via `ipwhois`. You can cap socket wait time with:
- `ASM_ASN_TIMEOUT_SECONDS` (default `5`)
- `ASM_ASN_TOTAL_TIMEOUT_SECONDS` (default `12`) caps total ASN lookup time per scan

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

## Docker Compose (All-in-one Demo)

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
- If you are not configuring Google OAuth locally, set `DEMO_MODE=true` in `.env` (otherwise startup fails).
- If tasks are enabled (`ENABLE_TASKS=1` or `ASM_TASKS_ENABLED=1`), `ASM_TASKS_SECRET` is required.

Health check:

```powershell
Invoke-RestMethod "http://127.0.0.1:8080/api/v1/health"
```

UI:

- `http://127.0.0.1:8080/`

## Demo Runbook

Local dev (Docker):

1. `docker compose up --build`
2. Verify health:
   - `curl http://127.0.0.1:8080/api/v1/health`

API validation (curl):

- `curl http://127.0.0.1:8080/api/v1/health`
- `curl http://127.0.0.1:8080/api/v1/companies`
- `curl -X POST http://127.0.0.1:8080/api/v1/companies -H "Content-Type: application/json" -d "{\"slug\":\"example\",\"name\":\"Example Company\",\"domains\":[\"example.com\"]}"`
- `curl -X POST http://127.0.0.1:8080/api/v1/companies/example/scans`

## Cloud Run (All-in-one Demo)

Target: one Cloud Run service serving UI at `/` and API at `/api/v1`.

Required env vars:

- `ASM_DATABASE_URL` (PostgreSQL URL, include `sslmode=require`)
- `ASM_CORS_ORIGINS` (comma-separated allowed origins; required in production)
- `ASM_TEST_MODE` (optional, default `0`)
- `DEMO_MODE` (default `false`; keep `false` in production)
- `GOOGLE_OAUTH_CLIENT_ID` (Google OAuth client ID for ID token verification)
- `ADMIN_EMAILS` (comma-separated)
- `USER_EMAILS` (comma-separated)
- `PUBLIC_COMPANY_SLUGS` (legacy; public access is now group-based via `Unauthenticated`)
- `ADMIN_SCAN_COOLDOWN_SECONDS` / `ADMIN_SCANS_PER_HOUR`
- `USER_SCAN_COOLDOWN_SECONDS` / `USER_SCANS_PER_HOUR`
- `ENABLE_TASKS=1` (preferred) or `ASM_TASKS_ENABLED=1` (enable Cloud Tasks for scans)
- `ASM_TASKS_PROJECT` (GCP project id)
- `ASM_TASKS_LOCATION` (Cloud Tasks region)
- `ASM_TASKS_QUEUE` (queue name)
- `ASM_TASKS_TARGET_BASE` (public service URL or custom domain)
- `ASM_TASKS_SECRET` (shared secret for task calls; required when tasks are enabled)
- `ASM_TASKS_DISPATCH_DEADLINE_SECONDS` (optional, default `1800`)
- `ASM_CVE_TIMEOUT_SECONDS` (optional, default `30`)
- `ASM_CVE_DOMAIN_TIMEOUT_SECONDS` (optional, default `5`)
- `ASM_NVD_RETRY_SECONDS` (optional, default `600`)
- `ASM_NVD_YEARS` (optional, default `1` or `2`)

Choose a region close to your users (Cloud Tasks queue and Cloud Run region should match).

### Build and Deploy (Cloud Build + Artifact Registry)

```powershell
gcloud services enable run.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com cloudtasks.googleapis.com
gcloud artifacts repositories create asm-notebook --repository-format=docker --location <REGION>

# Build image with UI env baked in (required by Vite)
gcloud builds submit --config cloudbuild.yaml --substitutions `
  _VITE_GOOGLE_CLIENT_ID="<client-id>", `
  _IMAGE="<REGION>-docker.pkg.dev/$env:GOOGLE_CLOUD_PROJECT/asm-notebook/asm-notebook:latest" `
  .

# Create Cloud Tasks queue
gcloud tasks queues create scan-runner --location <REGION>

# Deploy to Cloud Run
gcloud run deploy asm-notebook `
  --image <REGION>-docker.pkg.dev/$env:GOOGLE_CLOUD_PROJECT/asm-notebook/asm-notebook:latest `
  --region <REGION> `
  --platform managed `
  --set-env-vars `
    ASM_DATABASE_URL="<postgres-url>", `
    ASM_CORS_ORIGINS="https://your-domain", `
    GOOGLE_OAUTH_CLIENT_ID="<client-id>", `
    ADMIN_EMAILS="<admin1,admin2>", `
    USER_EMAILS="<user1,user2>", `
    PUBLIC_COMPANY_SLUGS="company-a,company-b", `
    ENABLE_TASKS=1, `
    ASM_TASKS_PROJECT="$env:GOOGLE_CLOUD_PROJECT", `
    ASM_TASKS_LOCATION="<REGION>", `
    ASM_TASKS_QUEUE="scan-runner", `
    ASM_TASKS_TARGET_BASE="https://your-domain", `
    ASM_TASKS_SECRET="<generated-secret>", `
    ASM_TASKS_DISPATCH_DEADLINE_SECONDS=1800, `
    ASM_CVE_TIMEOUT_SECONDS=30, `
    ASM_CVE_DOMAIN_TIMEOUT_SECONDS=5, `
    ASM_NVD_RETRY_SECONDS=600, `
    ASM_NVD_YEARS=1
```

Grant Cloud Tasks enqueuer role to the Cloud Run service account:

```powershell
gcloud run services describe asm-notebook --region <REGION> --format "value(spec.template.spec.serviceAccountName)"
gcloud projects add-iam-policy-binding $env:GOOGLE_CLOUD_PROJECT `
  --member "serviceAccount:<SERVICE_ACCOUNT_EMAIL>" `
  --role "roles/cloudtasks.enqueuer"
```

Domain mapping (high-level):

```powershell
gcloud run domain-mappings create --service asm-notebook --domain your-domain --region <REGION>
```

Security note (production):

- Do not deploy Cloud Run with `--allow-unauthenticated`. Use authenticated invokers only.
- Keep `DEMO_MODE=false` and always set `GOOGLE_OAUTH_CLIENT_ID`, `ASM_TASKS_SECRET` (when tasks enabled),
  and explicit `ASM_CORS_ORIGINS`.

Security notes:

- Use least-privilege DB credentials.
- Do not expose the database publicly.

## Neon Postgres (Demo)

1. Create a Neon project and database.
2. Copy the connection string and ensure it includes `sslmode=require`.
3. Set `ASM_DATABASE_URL` to that value.

Note: Neon sleeps inactive databases; the first request after idle may be slower.

## Frontend

```powershell
cd frontend
npm install
npm run dev -- --host 127.0.0.1 --port 5173
```

Open:

- `http://127.0.0.1:5173/`

Notes:

- The frontend uses a Vite proxy to the backend for API routes (`/api/v1` in `vite.config.js`).
- Keep backend running on `127.0.0.1:8000` while using frontend dev mode.
- API versioning: `/api/v1/*` routes are available.
- Frontend can override the prefix with `VITE_API_PREFIX` (default `/api/v1`).
- Google login uses `VITE_GOOGLE_CLIENT_ID` (must match backend `GOOGLE_OAUTH_CLIENT_ID`).

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
- Standard and deep scans both run CT discovery; if CT is unavailable, the scanner reuses
  the most recent CT/domain cache so standard scans keep the full domain set.
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
  - Multi-user:
  - Admins can manage users, groups, and company group assignments (persisted in DB)
  - Settings includes admin-only buttons:
    - `Manage companies` opens a modal to add companies and set group assignment
    - `Manage users` opens the admin panel (including auth allowlist for Google login)
    - `Manage groups` opens a modal to create groups and assign companies
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

- `GET /api/v1/health`
- `GET /api/v1/me`

Swagger UI:

- `GET /api/v1/docs`

Companies:

- `POST /api/v1/companies`
- `GET /api/v1/companies`
- `GET /api/v1/companies/{slug}`
- `PUT /api/v1/companies/{slug}/domains`
- `PATCH /api/v1/companies/{slug}`
- `DELETE /api/v1/companies/{slug}`

Scans (company-scoped and hardened):

- `POST /api/v1/companies/{slug}/scans`
- `GET /api/v1/companies/{slug}/scans`
- `GET /api/v1/companies/{slug}/scans/latest`
- `GET /api/v1/companies/{slug}/scans/{scan_id}`
- `GET /api/v1/companies/{slug}/scans/{scan_id}/artifacts`
- `GET /api/v1/companies/{slug}/scans/by-number/{company_scan_number}`
- `DELETE /api/v1/companies/{slug}/scans/{scan_id}`

Admin (auth allowlist):

- `GET /api/v1/admin/auth-allowlist`
- `POST /api/v1/admin/auth-allowlist`
- `DELETE /api/v1/admin/auth-allowlist/{email}`

Admin (groups & assignments):

- `GET /api/v1/admin/groups`
- `POST /api/v1/admin/groups`
- `DELETE /api/v1/admin/groups/{name}`
- `PUT /api/v1/admin/companies/{slug}/groups`
- `POST /api/v1/admin/companies/{company_id}/groups`
- `DELETE /api/v1/admin/companies/{company_id}/groups/{group_id}`
- `PATCH /api/v1/admin/users/{user_id}/group`

### API Examples

Examples below assume the Docker Compose demo (`http://127.0.0.1:8080`). If you are running
`uvicorn` directly, use `http://127.0.0.1:8000` instead.

Create a company:

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8080/api/v1/companies" -ContentType "application/json" -Body '{
  "slug": "example",
  "name": "Example Company",
  "domains": ["example.com"]
}'
```

Trigger a scan:

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8080/api/v1/companies/example/scans"
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
Invoke-RestMethod "http://127.0.0.1:8080/api/v1/companies/example/scans" | ConvertTo-Json -Depth 5
```

Fetch artifacts:

```powershell
Invoke-RestMethod "http://127.0.0.1:8080/api/v1/companies/example/scans/1/artifacts" | ConvertTo-Json -Depth 8
```

Fetch by per-company scan number:

```powershell
Invoke-RestMethod "http://127.0.0.1:8080/api/v1/companies/example/scans/by-number/1"
```

## Scan Execution Flow

### Standard Scan (Deep Scan off)

1. `POST /api/v1/companies/{slug}/scans` creates a `ScanRun` row with status `queued` and enqueues a Cloud Task.
2. Cloud Task calls `POST /api/v1/tasks/run_scan` to execute the scan synchronously.
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
7. NVD/CVE correlation (only when version confidence is high), guarded by timeouts.
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

## POC Closeout and Cloud Migration

- POC closeout checklist: `docs/POC_CLOSEOUT_CHECKLIST.md`
- Operational handoff notes: `docs/OPERATIONAL_HANDOFF_NOTES.md`
- GCP migration plan: `docs/GCP_MIGRATION_PLAN.md`

## Legacy Separate Services (Optional)

If you still want separate backend/frontend services:

- Backend image: `Dockerfile` (all-in-one by default)
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

## Safety / Scope

This repository is intended for authorized security assessment and learning.
Only analyze domains you own or have explicit permission to assess.
