# Operational Handoff Notes

## Environment Variables in Current Use

Backend:

- `ASM_DATABASE_URL`: required DB connection URL (PostgreSQL).
- `ASM_CORS_ORIGINS`: required in production (explicit allowed origins).
- `ASM_TEST_MODE`: set to `1` for deterministic test-mode scans.
- `DEMO_MODE`: set to `true` for local demos without OAuth (default `false`).
- `GOOGLE_OAUTH_CLIENT_ID`: required when `DEMO_MODE=false` (startup fails otherwise).
- `ADMIN_EMAILS`: comma-separated admin users (always keep at least one).
- `USER_EMAILS`: comma-separated standard users.
- `ASM_TASKS_ENABLED`: enable Cloud Tasks dispatch.
- `ENABLE_TASKS`: preferred boolean flag for Cloud Tasks (takes precedence if set).
- `ASM_TASKS_PROJECT`: GCP project id.
- `ASM_TASKS_LOCATION`: Cloud Tasks region.
- `ASM_TASKS_QUEUE`: queue name.
- `ASM_TASKS_TARGET_BASE`: public service URL or custom domain.
- `ASM_TASKS_SECRET`: shared secret for task requests (required when tasks are enabled).
- `ASM_TASKS_DISPATCH_DEADLINE_SECONDS`: optional, defaults to 1800.
- `ASM_CVE_TIMEOUT_SECONDS`: optional, defaults to 30.
- `ASM_CVE_DOMAIN_TIMEOUT_SECONDS`: optional, defaults to 5.
- `ASM_NVD_RETRY_SECONDS`: optional, defaults to 600.
- `ASM_NVD_YEARS`: optional, defaults to 1 or 2.

Frontend:

- `VITE_API_BASE`: optional API base URL (empty means same-origin/proxy in dev).
- `VITE_API_PREFIX`: optional API prefix (default `/api/v1`).
- `VITE_GOOGLE_CLIENT_ID`: Google client id baked at build time (required for login).

Cloud Build substitutions:

- `cloudbuild.yaml` uses `_VITE_GOOGLE_CLIENT_ID` and `_IMAGE`.

## Accepted POC Gaps

- Runtime requires PostgreSQL; no local file-backed DB support.
- API/CLI scan logic is not yet split into a service layer.

## Dependency Lock Status

- Python lockfile present: `poetry.lock`.
- Frontend lockfile present: `frontend/package-lock.json`.

## Frontend Views

- View modes: `Standard`, `Executive`, and `SOC Analyst` via the header view switcher.
- Selection persists in local storage (`asm_ui_mode`) and does not affect backend API behavior.
