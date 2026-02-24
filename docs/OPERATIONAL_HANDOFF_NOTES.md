# Operational Handoff Notes

## Environment Variables in Current Use

Backend:

- `ASM_DB_PATH`: optional local SQLite override path.
- `ASM_DATABASE_URL`: preferred DB connection URL (overrides `ASM_DB_PATH`), supports `sqlite:///...` and PostgreSQL.
- `ASM_TEST_MODE`: set to `1` for deterministic test-mode scans.

Frontend:

- `VITE_API_BASE`: optional API base URL (empty means same-origin/proxy in dev).
- `VITE_BASIC_AUTH_USER`: optional basic auth username for API calls.
- `VITE_BASIC_AUTH_PASS`: optional basic auth password for API calls.

Cloud Build frontend substitution:

- `_VITE_API_BASE` in `dev-frontend.yaml` maps to Docker build arg `VITE_API_BASE`.

## Accepted POC Gaps

- Scan execution remains in-process (FastAPI background task / CLI runtime), no durable queue yet.
- Local-first behavior is still supported, including SQLite compatibility migration.
- API/CLI scan logic is not yet split into a service layer.

## Dependency Lock Status

- Python lockfile present: `poetry.lock`.
- Frontend lockfile present: `frontend/package-lock.json`.
