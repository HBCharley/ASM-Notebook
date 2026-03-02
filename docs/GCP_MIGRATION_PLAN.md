# GCP Migration Plan (ASM Notebook)

This plan migrates the current local POC (FastAPI + React) to a production-ready GCP baseline using PostgreSQL.

## Recommended Target Architecture

- Single Cloud Run service serving UI at `/` and API at `/api/v1` (all-in-one image).
- Database: PostgreSQL (Cloud SQL or managed external like Neon).
- Async scan execution: Cloud Tasks -> `/api/v1/tasks/run_scan` on the same Cloud Run service.
- Secrets: Secret Manager or Cloud Run env vars (no secrets in repo).
- Container registry: Artifact Registry.
- CI/CD: Cloud Build (cloudbuild.yaml) or GitHub Actions deploying to Cloud Run.
- Observability: Cloud Logging + Error Reporting + Cloud Monitoring alerts.

## Phase 1: Platform Foundation

1. Create/confirm GCP project and billing.
2. Enable APIs: Cloud Run, Cloud Build, Artifact Registry, Cloud SQL Admin, Secret Manager, Cloud Tasks.
3. Create environments: `dev`, `staging`, `prod` (separate projects preferred).
4. Create service accounts and least-privilege IAM:
   - runtime API SA
   - runtime worker SA
   - deploy SA

## Phase 2: Containerization and Config

1. Use the all-in-one Dockerfile (frontend build + backend runtime).
2. Move all env configuration to runtime env vars + Secret Manager:
   - DB connection string
   - Cloud Tasks settings
   - external API/timeouts/retry knobs
   - auth credentials
3. Keep local dev compatibility (`.env` + docker compose).
4. Preserve frontend view modes (Standard / Executive / SOC Analyst) across environments.

## Phase 3: Database Migration (PostgreSQL)

1. Ensure database URL support uses PostgreSQL only.
2. Add migrations (Alembic recommended) for schema control.
3. Provision Cloud SQL PostgreSQL instance and DB user.
4. Run schema migration in `dev`, then data migration from a legacy DB as needed.
5. Validate scan CRUD/artifact behavior parity against local baseline.

## Phase 4: Async Scan Execution Hardening

Cloud Tasks is now the default async scan execution path.

1. Queue: `scan-runner` in the same region as Cloud Run.
2. Worker endpoint: `POST /api/v1/tasks/run_scan`.
3. Ensure task authentication via `ASM_TASKS_SECRET`.
4. Add retry/dead-letter policy as needed for production.

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
   - build images (cloudbuild.yaml)
   - push to Artifact Registry
   - deploy to Cloud Run
3. Add per-environment config and approval gate for `prod`.

## Phase 7: Cutover Plan

1. Freeze local writes.
2. Final legacy DB export/snapshot.
3. Run final migration and smoke tests in GCP.
4. Switch users to cloud URL.
5. Monitor error rate, latency, and scan completion for 24-48 hours.

## Definition of Done

- Cloud-hosted app serves frontend + API in target environment.
- All scan endpoints return correct `status` and `notes`.
- Async jobs survive restarts and retries.
- PostgreSQL is source of truth (no local file-backed DB dependency in runtime).
- CI/CD can redeploy reproducibly.

## Immediate Next Actions (Recommended Order)

1. Implement backend DB URL abstraction and Alembic.
2. Add backend Dockerfile + Cloud Run deploy script.
3. Provision Cloud SQL and connect backend.
4. Ensure Cloud Tasks queue + `/api/v1/tasks/run_scan` are configured.
5. Add auth layer and observability alerts before production use.
