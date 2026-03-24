# API Reference

Base URL:

- Local Docker (all-in-one): `http://127.0.0.1:8080/api/v1`
- Production (example): `https://asm.charleyt.net/api/v1`

Interactive docs (served by FastAPI):

- Swagger UI: `/api/v1/docs`
- ReDoc: `/api/v1/redoc`
- OpenAPI JSON: `/api/v1/openapi.json`

## Authentication

Most endpoints require an `Authorization: Bearer <token>` header containing a **Google ID token** (from Google Identity Services).

Role resolution:

- `ADMIN_EMAILS` (env) → admin
- `USER_EMAILS` (env) → standard user
- DB-backed allowlist (`/admin/auth-allowlist`) → admin/user
- Otherwise → treated as public (unauthenticated)

Company access:

- Admins can access all companies.
- Non-admin users are restricted to their group’s companies.
- Public (unauthenticated) access is restricted to the `Unauthenticated` group’s companies.

Cloud Tasks access:

- `POST /tasks/run_scan` requires `X-Tasks-Secret: <ASM_TASKS_SECRET>`.

## Endpoints

### Health

- `GET /health` → `{ "ok": true }` (public)

### Session

- `GET /me` → current role/access context (public if no/invalid token)
- `GET /me/preferences/{key}` (auth required)
  - Reads a per-user JSON preference value.
- `PUT /me/preferences/{key}` (auth required)
  - Writes a per-user JSON preference value as `{ "value": { ... } }`.

### Companies

- `POST /companies` (auth required)
  - Create a company and its initial domain scope.
- `GET /companies` (public/auth)
  - Lists companies visible to the caller’s group (admins see all).
- `GET /companies/{slug}` (public/auth + company access)
- `PATCH /companies/{slug}` (auth + write access)
- `PUT /companies/{slug}/domains` (auth + write access)
  - Replace the company’s in-scope root domains.
- `DELETE /companies/{slug}` (auth + write access)

### Scans

- `POST /companies/{slug}/scans` (auth + scan access)
  - Triggers a scan for the company. Supports `{ "deep_scan": true }`.
- `GET /companies/{slug}/scans` (public/auth + company access)
  - Lists scans for the company. Supports ETag/`If-None-Match` revalidation (304).
- `GET /companies/{slug}/scans/latest` (public/auth + company access)
- `GET /companies/{slug}/scans/{scan_id}` (public/auth + company access)
- `GET /companies/{slug}/scans/by-number/{company_scan_number}` (public/auth + company access)
- `DELETE /companies/{slug}/scans/{scan_id}` (auth + scan access)

### Artifacts

- `GET /companies/{slug}/scans/{scan_id}/artifacts` (public/auth + company access)
  - Returns the full scan artifact bundle. Supports ETag/`If-None-Match` revalidation (304).

### SOC Analyst (shaped)

These endpoints shape scan artifacts into an investigation-focused model for the SOC Analyst workspace.

- `GET /companies/{slug}/soc` (public/auth + company access)
  - Returns summary tiles, shaped asset inventory rows, and persisted findings for the selected scan.
  - Optional `?scan_id=...` (defaults to latest scan).
  - Supports ETag/`If-None-Match` revalidation (304).
- `GET /companies/{slug}/soc/assets/{hostname}` (public/auth + company access)
  - Returns the selected asset’s detail payload (overview/DNS/Web/TLS/findings/history/raw).
  - Optional `?scan_id=...` (defaults to latest scan).
  - Supports ETag/`If-None-Match` revalidation (304).

### Tasks

- `GET /tasks/health` (public)
  - Returns Cloud Tasks configuration status.
- `POST /tasks/run_scan` (task-secret required)
  - Executes a queued scan (Cloud Tasks target).

### Admin

All admin endpoints require an authenticated admin.

- `GET /admin/auth-allowlist`
- `POST /admin/auth-allowlist`
- `DELETE /admin/auth-allowlist/{email}`
- `GET /admin/groups`
- `POST /admin/groups`
- `DELETE /admin/groups/{name}`
- `PUT /admin/companies/{slug}/groups`
- `POST /admin/companies/{company_id}/groups`
- `DELETE /admin/companies/{company_id}/groups/{group_id}`
- `PATCH /admin/users/{user_id}/group`
- `GET /admin/user-groups`
- `PUT /admin/user-groups`

### Debug (admin)

- `GET /debug/cve`
- `GET /debug/cve/evidence`

## Common Responses

- `401 unauthorized`: missing/invalid/expired token (for endpoints that require authentication)
- `403 forbidden`: authenticated but lacks required role or company access
- `429 rate_limited`: scan limits hit (cooldown/quota) or scan already running
