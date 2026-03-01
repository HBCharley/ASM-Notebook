# POC Closeout Checklist

Use this checklist to formally close the local/POC phase before GCP migration.

## 1) Freeze Local Baseline

- [x] Create a final local release tag (example: `v0.1.0-local-final`).
- [x] Export sample scan artifacts for reference (`scan export` outputs).
- [x] Capture DB snapshot (`asm_notebook.sqlite3`) and store in secure backup.
- [x] Confirm working tree is clean and tests pass (`poetry run python -m pytest -q`).

## 2) Operational Handoff Notes

- [x] Record current env vars in use (`ASM_DB_PATH`, `ASM_TEST_MODE`, frontend `VITE_*`).
- [x] Confirm known gaps accepted from POC phase (no job queue, SQLite local-first).
- [x] Lock dependency set (`poetry.lock` committed, Node lockfile committed if used).
- [ ] Document UI view modes and expected workflows in `README.md`.

## 3) Security and Data Hygiene

- [ ] Remove any hardcoded/demo credentials from local shells/scripts.
- [x] Verify `.gitignore` excludes DB files and local secrets.
- [ ] Classify current stored scan data (internal/test/public) and retention expectations.

## 4) Migration Readiness Gate

- [ ] Agree target cloud runtime (recommended: Cloud Run).
- [ ] Agree target database (recommended: Cloud SQL PostgreSQL).
- [ ] Agree async execution path (Cloud Tasks + worker service, or Cloud Run Jobs).
- [ ] Define initial SLO targets (availability, max scan duration, RTO/RPO).

When all boxes are checked, proceed with `docs/GCP_MIGRATION_PLAN.md`.
