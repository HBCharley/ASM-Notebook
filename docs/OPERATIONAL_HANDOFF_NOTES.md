# Operational Handoff Notes

## Environment Variables in Current Use

Backend:

- `ASM_DATABASE_URL`: required DB connection URL (PostgreSQL).
- `ASM_TEST_MODE`: set to `1` for deterministic test-mode scans.

Frontend:

- `VITE_API_BASE`: optional API base URL (empty means same-origin/proxy in dev).
- `VITE_BASIC_AUTH_USER`: optional basic auth username for API calls.
- `VITE_BASIC_AUTH_PASS`: optional basic auth password for API calls.

Cloud Build frontend substitution:

- `_VITE_API_BASE` in `dev-frontend.yaml` maps to Docker build arg `VITE_API_BASE`.

## Accepted POC Gaps

- Scan execution remains in-process (FastAPI background task / CLI runtime), no durable queue yet.
- Runtime requires PostgreSQL; no local file-backed DB support.
- API/CLI scan logic is not yet split into a service layer.

## Dependency Lock Status

- Python lockfile present: `poetry.lock`.
- Frontend lockfile present: `frontend/package-lock.json`.

## Frontend Views

- View modes: `Standard`, `Executive`, and `SOC Analyst` via the header view switcher.
- Selection persists in local storage (`asm_ui_mode`) and does not affect backend API behavior.
