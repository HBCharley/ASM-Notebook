# GCP Migration Plan (ASM Notebook)

This plan migrates the current local POC (FastAPI + React + SQLite) to a production-ready GCP baseline.

## Recommended Target Architecture

- Backend API: Cloud Run service (`asm-api`)
- Frontend: Cloud Run service (`asm-frontend`) or Firebase Hosting (optional later)
- Database: Cloud SQL for PostgreSQL
- Async scan execution: Cloud Tasks -> worker endpoint on Cloud Run (`asm-worker`)
- Secrets: Secret Manager
- Container registry: Artifact Registry
- CI/CD: Cloud Build (or GitHub Actions deploying to Cloud Run)
- Observability: Cloud Logging + Error Reporting + Cloud Monitoring alerts

## Phase 1: Platform Foundation

1. Create/confirm GCP project and billing.
2. Enable APIs: Cloud Run, Cloud Build, Artifact Registry, Cloud SQL Admin, Secret Manager, Cloud Tasks.
3. Create environments: `dev`, `staging`, `prod` (separate projects preferred).
4. Create service accounts and least-privilege IAM:
   - runtime API SA
   - runtime worker SA
   - deploy SA

## Phase 2: Containerization and Config

1. Add Dockerfiles:
   - backend image (Uvicorn/FastAPI)
   - frontend image (Vite build + static server)
2. Move all env configuration to runtime env vars + Secret Manager:
   - DB connection string
   - external API/timeouts/retry knobs
   - any auth credentials
3. Keep local dev compatibility (`.env.local` + existing commands).

## Phase 3: Database Migration (SQLite -> PostgreSQL)

1. Introduce database URL support that works for both SQLite and PostgreSQL.
2. Add migrations (Alembic recommended) for schema control.
3. Provision Cloud SQL PostgreSQL instance and DB user.
4. Run schema migration in `dev`, then data migration from local SQLite as needed.
5. Validate scan CRUD/artifact behavior parity against local baseline.

## Phase 4: Async Scan Execution Hardening

Current FastAPI background tasks are fine for local POC but not durable for cloud scale.

1. Replace in-process background execution with Cloud Tasks queue.
2. Worker endpoint:
   - receives scan job payload
   - executes scan pipeline
   - updates scan status/progress (`notes`) in DB
3. Add idempotency guard for duplicated task delivery.
4. Add retry policy and dead-letter strategy.

## Phase 5: Security Baseline

1. Put API behind authenticated access (IAP, JWT, or API gateway model).
2. Restrict ingress as needed (internal + LB or public with auth).
3. Enforce HTTPS-only endpoints.
4. Rotate secrets via Secret Manager.
5. Add audit logging for admin actions (company/scans delete operations).

## Phase 6: Delivery Pipeline

1. CI checks:
   - backend tests (`pytest`)
   - frontend build
   - lint/static checks
2. CD flow:
   - build images
   - push to Artifact Registry
   - deploy to Cloud Run
3. Add per-environment config and approval gate for `prod`.

## Phase 7: Cutover Plan

1. Freeze local writes.
2. Final SQLite export/snapshot.
3. Run final migration and smoke tests in GCP.
4. Switch users to cloud URL.
5. Monitor error rate, latency, and scan completion for 24-48 hours.

## Definition of Done

- Cloud-hosted app serves frontend + API in target environment.
- All scan endpoints return correct `status` and `notes`.
- Async jobs survive restarts and retries.
- PostgreSQL is source of truth (no local SQLite dependency in runtime).
- CI/CD can redeploy reproducibly.

## Immediate Next Actions (Recommended Order)

1. Implement backend DB URL abstraction and Alembic.
2. Add backend Dockerfile + Cloud Run deploy script.
3. Provision Cloud SQL and connect backend.
4. Replace FastAPI background task with Cloud Tasks worker path.
5. Add auth layer and observability alerts before production use.
