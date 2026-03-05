param(
  [switch]$DryRun,
  [switch]$BuildOnly,
  [switch]$DeployOnly,
  [switch]$SkipVerify
)

$ErrorActionPreference = "Stop"

function Invoke-Step([string]$Label, [string]$Command) {
  Write-Host ""
  Write-Host "==> $Label"
  Write-Host $Command
  if ($DryRun) { return }
  pwsh -NoProfile -Command $Command
}

function Read-Json([string]$Path) {
  if (-not (Test-Path $Path)) { return $null }
  return (Get-Content $Path -Raw | ConvertFrom-Json)
}

$rulesPath = Join-Path $PSScriptRoot "..\\deploy\\production.rules.json"
$examplePath = Join-Path $PSScriptRoot "..\\deploy\\production.rules.example.json"

$rules = Read-Json $rulesPath
if (-not $rules) {
  $rules = Read-Json $examplePath
  if (-not $rules) { throw "Missing deploy rules. Expected $rulesPath or $examplePath" }
  Write-Host "Using example rules (create deploy/production.rules.json for local overrides)."
} else {
  Write-Host "Using local rules: $rulesPath"
}

$project = (gcloud config get-value project 2>$null).Trim()
if (-not $project) { throw "No active gcloud project. Run: gcloud config set project <PROJECT_ID>" }

$service = $rules.service
$region = $rules.region
$domain = $rules.published_domain.TrimEnd("/")
$repo = $rules.artifact_repo
$imageName = $rules.image_name
$imageTag = $rules.image_tag
$clientId = $rules.vite_google_client_id
$oauthClientId = $rules.google_oauth_client_id
$cors = $rules.cors_origins
$adminEmails = $rules.admin_emails

$tasksEnabled = [bool]$rules.tasks.enabled
$tasksQueue = $rules.tasks.queue
$tasksDeadline = [int]$rules.tasks.dispatch_deadline_seconds
if ($tasksDeadline -gt 1800) { $tasksDeadline = 1800 }
if ($tasksDeadline -gt 0 -and $tasksDeadline -lt 15) { $tasksDeadline = 15 }

$cloudRunTimeout = 3600
if ($rules.cloud_run -and $rules.cloud_run.timeout_seconds) {
  $cloudRunTimeout = [int]$rules.cloud_run.timeout_seconds
}

$scanMaxSeconds = 3600
if ($rules.scan -and $rules.scan.max_seconds) {
  $scanMaxSeconds = [int]$rules.scan.max_seconds
}

$dbSecret = $rules.secrets.asm_database_url
$tasksSecret = $rules.secrets.asm_tasks_secret

$image = "$region-docker.pkg.dev/$project/$repo/$imageName`:$imageTag"

if (-not $DeployOnly) {
  Invoke-Step "Cloud Build (all-in-one image)" @"
gcloud builds submit --config cloudbuild.yaml --substitutions "_VITE_GOOGLE_CLIENT_ID=$clientId,_IMAGE=$image" .
"@
  if ($BuildOnly) { exit 0 }
}

if ($tasksEnabled) {
  Invoke-Step "Ensure Cloud Tasks queue exists" @"
gcloud tasks queues describe $tasksQueue --location $region --format "value(name)" 2>`$null; if (`$LASTEXITCODE -ne 0) { gcloud tasks queues create $tasksQueue --location $region | Out-Null }
"@

  Invoke-Step "Ensure Secret Manager secret exists (no rotation)" @"
gcloud secrets describe $tasksSecret --format "value(name)" 2>`$null; if (`$LASTEXITCODE -ne 0) { gcloud secrets create $tasksSecret --replication-policy="automatic" | Out-Null; `$v = [Guid]::NewGuid().ToString('N'); `$v | gcloud secrets versions add $tasksSecret --data-file=- | Out-Null }
"@

  Invoke-Step "Grant Cloud Run SA access (Cloud Tasks + Secret Accessor)" @"
`$sa = (gcloud run services describe $service --region $region --format "value(spec.template.spec.serviceAccountName)" 2>`$null).Trim(); if (-not `$sa) { throw "Could not resolve service account for $service" }
gcloud projects add-iam-policy-binding $project --member "serviceAccount:`$sa" --role "roles/cloudtasks.enqueuer" | Out-Null
gcloud secrets add-iam-policy-binding $tasksSecret --member "serviceAccount:`$sa" --role "roles/secretmanager.secretAccessor" | Out-Null
"@
}

$envVars = @(
  "GOOGLE_OAUTH_CLIENT_ID=$oauthClientId",
  "ASM_CORS_ORIGINS=$cors",
  "ADMIN_EMAILS=$adminEmails"
)

if ($tasksEnabled) {
  $envVars += @(
    "ENABLE_TASKS=1",
    "ASM_TASKS_PROJECT=$project",
    "ASM_TASKS_LOCATION=$region",
    "ASM_TASKS_QUEUE=$tasksQueue",
    "ASM_TASKS_TARGET_BASE=$domain",
    "ASM_TASKS_DISPATCH_DEADLINE_SECONDS=$tasksDeadline"
  )
}

$envVars += "ASM_SCAN_MAX_SECONDS=$scanMaxSeconds"

$envVarString = ($envVars -join ",")

$secretArgs = @("ASM_DATABASE_URL=$($dbSecret):latest")
if ($tasksEnabled) {
  $secretArgs += "ASM_TASKS_SECRET=$($tasksSecret):latest"
}
$secretString = ($secretArgs -join ",")

Invoke-Step "Deploy Cloud Run (explicit env + secrets)" @"
gcloud run deploy $service --image $image --region $region --platform managed --quiet --timeout $cloudRunTimeout --set-env-vars "$envVarString" --set-secrets "$secretString"
"@

if (-not $SkipVerify) {
  Invoke-Step "Verify API health" @"
Invoke-RestMethod "$domain/api/v1/health" | ConvertTo-Json -Compress
"@
  if ($tasksEnabled) {
    Invoke-Step "Verify tasks health" @"
Invoke-RestMethod "$domain/api/v1/tasks/health" | ConvertTo-Json -Compress
"@
  }
}

Write-Host ""
Write-Host "Done. UI: $domain/"
