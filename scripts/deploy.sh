#!/usr/bin/env bash
# deploy.sh — build and deploy to Cloud Run, then run smoke tests
#
# Usage:
#   bash scripts/deploy.sh [OPTIONS]
#
# Options:
#   --dry-run        print commands without executing
#   --build-only     build and push image, skip deploy + smoke tests
#   --deploy-only    deploy existing :latest image, skip build
#   --skip-smoke     skip smoke tests after deploy
#   --project ID     override GCP project ID
#
# Reads config from: asm_notebook/deploy/production.rules.json

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

RULES="$REPO_ROOT/asm_notebook/deploy/production.rules.json"
if [[ ! -f "$RULES" ]]; then
  echo "ERROR: $RULES not found" >&2
  exit 1
fi

# ── Parse rules ───────────────────────────────────────────────────────────────
get() { python3 -c "import json,sys; d=json.load(open('$RULES')); print(d$1)" 2>/dev/null || echo ""; }

SERVICE="$(get "['service']")"
REGION="$(get "['region']")"
DOMAIN="$(get "['published_domain']")"
DOMAIN="${DOMAIN%/}"
ARTIFACT_REPO="$(get "['artifact_repo']")"
IMAGE_NAME="$(get "['image_name']")"
IMAGE_TAG="$(get "['image_tag']")"
VITE_CLIENT_ID="$(get "['vite_google_client_id']")"
OAUTH_CLIENT_ID="$(get "['google_oauth_client_id']")"
CORS_ORIGINS="$(get "['cors_origins']")"
ADMIN_EMAILS="$(get "['admin_emails']")"
TASKS_ENABLED="$(get "['tasks']['enabled']")"
TASKS_QUEUE="$(get "['tasks']['queue']")"
TASKS_DEADLINE="$(get "['tasks']['dispatch_deadline_seconds']")"
MEMORY="$(get "['cloud_run']['memory']")"
CPU="$(get "['cloud_run']['cpu']")"
CONCURRENCY="$(get "['cloud_run']['concurrency']")"
MIN_INSTANCES="$(get "['cloud_run']['min_instances']")"
MAX_INSTANCES="$(get "['cloud_run']['max_instances']")"
TIMEOUT="$(get "['cloud_run']['timeout_seconds']")"
SCAN_MAX="$(get "['scan']['max_seconds']")"
DB_SECRET="$(get "['secrets']['asm_database_url']")"
TASKS_SECRET="$(get "['secrets']['asm_tasks_secret']")"

# ── Parse flags ───────────────────────────────────────────────────────────────
DRY_RUN=false
BUILD_ONLY=false
DEPLOY_ONLY=false
SKIP_SMOKE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)     DRY_RUN=true ;;
    --build-only)  BUILD_ONLY=true ;;
    --deploy-only) DEPLOY_ONLY=true ;;
    --skip-smoke)  SKIP_SMOKE=true ;;
    --project)     shift; GCLOUD_PROJECT="$1" ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

# ── Resolve GCP project ───────────────────────────────────────────────────────
GCLOUD_PROJECT="${GCLOUD_PROJECT:-$(gcloud config get-value project 2>/dev/null | tr -d '[:space:]')}"
if [[ -z "$GCLOUD_PROJECT" ]]; then
  echo "ERROR: no active gcloud project. Run: gcloud config set project PROJECT_ID" >&2
  exit 1
fi

IMAGE="$REGION-docker.pkg.dev/$GCLOUD_PROJECT/$ARTIFACT_REPO/$IMAGE_NAME:$IMAGE_TAG"

step() {
  echo ""
  echo "==> $1"
  shift
  echo "    $*"
  if $DRY_RUN; then return; fi
  eval "$@"
}

echo "==> Deploy config"
echo "    Project:  $GCLOUD_PROJECT"
echo "    Service:  $SERVICE ($REGION)"
echo "    Domain:   $DOMAIN"
echo "    Image:    $IMAGE"

# ── Build ─────────────────────────────────────────────────────────────────────
if ! $DEPLOY_ONLY; then
  step "Cloud Build — build + push image" \
    "gcloud builds submit \
      --project '$GCLOUD_PROJECT' \
      --config cloudbuild.yaml \
      --substitutions '_VITE_GOOGLE_CLIENT_ID=$VITE_CLIENT_ID,_IMAGE=$IMAGE' \
      ."

  if $BUILD_ONLY; then
    echo ""
    echo "==> Build complete. Skipping deploy (--build-only)."
    exit 0
  fi
fi

# ── Deploy ────────────────────────────────────────────────────────────────────
ENV_VARS="GOOGLE_OAUTH_CLIENT_ID=$OAUTH_CLIENT_ID"
ENV_VARS+=",ASM_CORS_ORIGINS=$CORS_ORIGINS"
ENV_VARS+=",ADMIN_EMAILS=$ADMIN_EMAILS"
ENV_VARS+=",ASM_SCAN_MAX_SECONDS=$SCAN_MAX"
ENV_VARS+=",ASM_SCAN_RUNNING_STALE_SECONDS=300"
ENV_VARS+=",ASM_SCAN_HEARTBEAT_SECONDS=10"
ENV_VARS+=",ASM_SCAN_TAKEOVER_SECONDS=20"

if [[ "$TASKS_ENABLED" == "True" ]]; then
  ENV_VARS+=",ENABLE_TASKS=1"
  ENV_VARS+=",ASM_TASKS_PROJECT=$GCLOUD_PROJECT"
  ENV_VARS+=",ASM_TASKS_LOCATION=$REGION"
  ENV_VARS+=",ASM_TASKS_QUEUE=$TASKS_QUEUE"
  ENV_VARS+=",ASM_TASKS_TARGET_BASE=$DOMAIN"
  ENV_VARS+=",ASM_TASKS_DISPATCH_DEADLINE_SECONDS=$TASKS_DEADLINE"
fi

SECRETS="ASM_DATABASE_URL=${DB_SECRET}:latest"
if [[ "$TASKS_ENABLED" == "True" ]]; then
  SECRETS+=",ASM_TASKS_SECRET=${TASKS_SECRET}:latest"
fi

step "Cloud Run — deploy" \
  "gcloud run deploy '$SERVICE' \
    --project '$GCLOUD_PROJECT' \
    --image '$IMAGE' \
    --region '$REGION' \
    --platform managed \
    --quiet \
    --timeout '$TIMEOUT' \
    --memory '$MEMORY' \
    --cpu '$CPU' \
    --concurrency '$CONCURRENCY' \
    --min-instances '$MIN_INSTANCES' \
    --max-instances '$MAX_INSTANCES' \
    --set-env-vars '$ENV_VARS' \
    --set-secrets '$SECRETS'"

# ── Smoke tests ───────────────────────────────────────────────────────────────
if ! $SKIP_SMOKE && ! $DRY_RUN; then
  echo ""
  echo "==> Waiting 5s for new revision to warm up..."
  sleep 5
  bash "$REPO_ROOT/scripts/smoke_test.sh" "$DOMAIN"
fi

echo ""
echo "==> Done. UI: $DOMAIN/"
