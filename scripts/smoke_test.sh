#!/usr/bin/env bash
# smoke_test.sh — run post-deploy smoke tests against a live URL
#
# Usage:
#   bash scripts/smoke_test.sh [BASE_URL]
#
# If BASE_URL is omitted it is read from asm_notebook/deploy/production.rules.json
# (the "published_domain" field).  For local testing pass http://localhost:8000.
#
# Exit code: 0 = all checks passed, 1 = one or more checks failed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# ── Resolve base URL ──────────────────────────────────────────────────────────
if [[ -n "${1:-}" ]]; then
  BASE="${1%/}"
else
  RULES="$REPO_ROOT/asm_notebook/deploy/production.rules.json"
  if [[ ! -f "$RULES" ]]; then
    echo "ERROR: no BASE_URL argument and $RULES not found" >&2
    exit 1
  fi
  BASE="$(python3 -c "import json,sys; d=json.load(open('$RULES')); print(d['published_domain'].rstrip('/'))")"
fi

echo "==> Smoke testing: $BASE"
echo ""

PASS=0
FAIL=0

check() {
  local label="$1"
  local url="$2"
  local expect_status="${3:-200}"
  local expect_body="${4:-}"

  resp=$(curl -sf -o /tmp/smoke_body -w "%{http_code}" \
    -H "Accept: application/json" \
    --max-time 15 \
    "$url" 2>/dev/null) || resp="000"

  body=$(cat /tmp/smoke_body 2>/dev/null || echo "")

  if [[ "$resp" != "$expect_status" ]]; then
    echo "  FAIL  $label"
    echo "        Expected HTTP $expect_status, got $resp"
    echo "        URL: $url"
    FAIL=$((FAIL+1))
    return
  fi

  if [[ -n "$expect_body" ]] && ! echo "$body" | grep -q "$expect_body"; then
    echo "  FAIL  $label"
    echo "        Expected body to contain: $expect_body"
    echo "        Got: ${body:0:200}"
    FAIL=$((FAIL+1))
    return
  fi

  echo "  PASS  $label  (HTTP $resp)"
  PASS=$((PASS+1))
}

check_json_key() {
  local label="$1"
  local url="$2"
  local key="$3"

  body=$(curl -sf --max-time 15 -H "Accept: application/json" "$url" 2>/dev/null) || {
    echo "  FAIL  $label  (request failed)"
    FAIL=$((FAIL+1))
    return
  }

  if ! echo "$body" | python3 -c "import json,sys; d=json.load(sys.stdin); assert '$key' in d, '$key missing'" 2>/dev/null; then
    echo "  FAIL  $label  (key '$key' missing in response)"
    echo "        Body: ${body:0:200}"
    FAIL=$((FAIL+1))
    return
  fi

  echo "  PASS  $label  (key '$key' present)"
  PASS=$((PASS+1))
}

# ── Frontend ──────────────────────────────────────────────────────────────────
echo "--- Frontend"
check "index.html served"          "$BASE/"  200 "<!doctype html"
check "index references JS bundle" "$BASE/"  200 '<script'

# ── API health ────────────────────────────────────────────────────────────────
echo ""
echo "--- API"
check_json_key "GET /api/v1/health"        "$BASE/api/v1/health"        "ok"
check_json_key "GET /api/v1/tasks/health"  "$BASE/api/v1/tasks/health"  "enabled"

# ── Companies list (public endpoint) ─────────────────────────────────────────
echo ""
echo "--- Public endpoints"
check "GET /api/v1/companies returns 200" "$BASE/api/v1/companies" 200

# ── Static assets reachable ──────────────────────────────────────────────────
echo ""
echo "--- Static assets"
# Pull the hashed JS/CSS filenames from index.html using python (avoids grep -P portability issues)
index_html=$(curl -sf --max-time 10 "$BASE/" 2>/dev/null || echo "")

js_src=$(echo "$index_html" | python3 -c "
import sys, re
m = re.search(r'src=\"(/assets/[^\"]+\.js)\"', sys.stdin.read())
print(m.group(1) if m else '')
" 2>/dev/null || echo "")

css_src=$(echo "$index_html" | python3 -c "
import sys, re
m = re.search(r'href=\"(/assets/[^\"]+\.css)\"', sys.stdin.read())
print(m.group(1) if m else '')
" 2>/dev/null || echo "")

if [[ -n "$js_src" ]]; then
  check "JS bundle $js_src" "$BASE$js_src" 200
else
  echo "  WARN  Could not extract JS bundle path from index.html"
fi

if [[ -n "$css_src" ]]; then
  check "CSS bundle $css_src" "$BASE$css_src" 200
else
  echo "  WARN  Could not extract CSS bundle path from index.html"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "==> Results: $PASS passed, $FAIL failed"

if [[ $FAIL -gt 0 ]]; then
  exit 1
fi
