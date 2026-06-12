#!/usr/bin/env bash
set -euo pipefail

# Bulk cleanup tool for Aurelian integration-test Terraform fixtures.
#
# Routine cleanup happens automatically: integration tests now destroy their
# fixtures after a successful package run (see scripts/run-integration-tests.sh
# and the AURELIAN_KEEP_FIXTURES / AURELIAN_REDEPLOY_FIXTURES env vars). This
# script is for:
#
#   * Cleaning up fixtures whose tests no longer exist (orphaned moduleDirs).
#   * Bulk cleanup after a run was killed / SIGINT'd before TestMain could fire.
#   * Cleanup after a failed run where fixtures were kept alive for debugging
#     and are no longer needed.
#
# The AWS profile gates access to the state bucket. For Azure or GCP fixtures,
# the caller must also have the corresponding provider credentials configured
# (az login / gcloud auth) — terraform destroy will fail otherwise.

STATE_REGION="us-east-1"
STATE_BUCKET_PREFIX="aurelian-integration-tests-"
STATE_PREFIX="integration-tests/"

PROFILE=""
DRY_RUN=false
ASSUME_YES=false
KEEP_S3=false
FILTER=""
ONLY_MODULE=""

usage() {
  cat <<EOF
Usage: $0 --profile PROFILE [options]

Enumerates every Terraform state under s3://${STATE_BUCKET_PREFIX}<ACCOUNT_ID>/${STATE_PREFIX}
and destroys the associated infrastructure.

Required:
  --profile PROFILE     AWS profile with access to the state bucket.

Options:
  --dry-run             List modules that would be destroyed and exit.
  --yes                 Skip the interactive confirmation prompt.
  --keep-s3             Do not delete state/artifacts from S3 after destroy.
  --filter PATTERN      Only operate on modules whose key matches this grep
                        extended-regex pattern (e.g. 'aws/recon').
  --module MODULE_DIR   Destroy a single module (exact moduleDir, e.g.
                        'aws/recon/list'). Overrides --filter.
  -h, --help            Show this help.

Examples:
  $0 --profile my-integration --dry-run
  $0 --profile my-integration --filter 'aws/recon'
  $0 --profile my-integration --module aws/recon/old-module --yes
EOF
}

log()  { printf '[destroy-fixtures] %s\n' "$*"; }
warn() { printf '[destroy-fixtures][WARN] %s\n' "$*" >&2; }
err()  { printf '[destroy-fixtures][ERROR] %s\n' "$*" >&2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)        PROFILE="$2"; shift 2 ;;
    --profile=*)      PROFILE="${1#*=}"; shift ;;
    --dry-run)        DRY_RUN=true; shift ;;
    --yes|-y)         ASSUME_YES=true; shift ;;
    --keep-s3)        KEEP_S3=true; shift ;;
    --filter)         FILTER="$2"; shift 2 ;;
    --filter=*)       FILTER="${1#*=}"; shift ;;
    --module)         ONLY_MODULE="$2"; shift 2 ;;
    --module=*)       ONLY_MODULE="${1#*=}"; shift ;;
    -h|--help)        usage; exit 0 ;;
    *)                err "Unknown argument: $1"; usage >&2; exit 1 ;;
  esac
done

if [[ -z "$PROFILE" ]]; then
  err "--profile is required"
  usage >&2
  exit 1
fi

for tool in aws terraform; do
  if ! command -v "$tool" &>/dev/null; then
    err "$tool not found in PATH"
    exit 1
  fi
done

export AWS_PROFILE="$PROFILE"

log "Validating AWS profile '$PROFILE'..."
if ! ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)"; then
  err "Unable to authenticate with AWS profile '$PROFILE'."
  exit 1
fi
BUCKET="${STATE_BUCKET_PREFIX}${ACCOUNT_ID}"
log "Account: $ACCOUNT_ID"
log "Bucket:  s3://${BUCKET}"

if ! aws s3api head-bucket --bucket "$BUCKET" --region "$STATE_REGION" &>/dev/null; then
  err "State bucket ${BUCKET} not found or not accessible in ${STATE_REGION}."
  exit 1
fi

# Collect state keys (terraform.tfstate objects under integration-tests/).
log "Listing state keys under s3://${BUCKET}/${STATE_PREFIX} ..."
STATE_KEYS=()
while IFS= read -r key; do
  [[ -n "$key" ]] && STATE_KEYS+=("$key")
done < <(
  aws s3api list-objects-v2 \
    --bucket "$BUCKET" \
    --prefix "$STATE_PREFIX" \
    --query 'Contents[?ends_with(Key, `terraform.tfstate`)].Key' \
    --output text 2>/dev/null | tr '\t' '\n' | sort
)

if [[ ${#STATE_KEYS[@]} -eq 0 ]]; then
  log "No Terraform state files found. Nothing to do."
  exit 0
fi

# Derive moduleDir (everything between STATE_PREFIX and /terraform.tfstate).
declare -a MODULES=()
for key in "${STATE_KEYS[@]}"; do
  module="${key#${STATE_PREFIX}}"
  module="${module%/terraform.tfstate}"
  MODULES+=("$module")
done

# Apply filters.
declare -a SELECTED=()
for module in "${MODULES[@]}"; do
  if [[ -n "$ONLY_MODULE" ]]; then
    [[ "$module" == "$ONLY_MODULE" ]] && SELECTED+=("$module")
    continue
  fi
  if [[ -n "$FILTER" ]]; then
    if printf '%s\n' "$module" | grep -Eq "$FILTER"; then
      SELECTED+=("$module")
    fi
    continue
  fi
  SELECTED+=("$module")
done

if [[ ${#SELECTED[@]} -eq 0 ]]; then
  log "No modules matched filter. Nothing to do."
  exit 0
fi

log "Modules targeted for destruction (${#SELECTED[@]}):"
for module in "${SELECTED[@]}"; do
  printf '  - %s\n' "$module"
done

if $DRY_RUN; then
  log "--dry-run set; exiting without changes."
  exit 0
fi

if ! $ASSUME_YES; then
  printf '\n'
  read -rp "Destroy these ${#SELECTED[@]} fixture(s) in account ${ACCOUNT_ID}? [type 'yes' to continue] " REPLY
  if [[ "$REPLY" != "yes" ]]; then
    log "Aborted."
    exit 1
  fi
fi

WORK_ROOT="$(mktemp -d -t aurelian-destroy.XXXXXX)"
trap 'rm -rf "$WORK_ROOT"' EXIT

declare -a FAILURES=()
declare -a SUCCEEDED=()

destroy_module() {
  local module="$1"
  local state_key="${STATE_PREFIX}${module}/terraform.tfstate"
  local artifacts_uri="s3://${BUCKET}/${STATE_PREFIX}${module}/artifacts/"
  local work_dir="${WORK_ROOT}/${module//\//_}"

  log "=== ${module} ==="
  log "state:     s3://${BUCKET}/${state_key}"
  log "artifacts: ${artifacts_uri}"

  mkdir -p "$work_dir"

  if ! aws s3 sync "$artifacts_uri" "$work_dir/" --only-show-errors; then
    warn "failed to sync artifacts for ${module}; skipping"
    return 1
  fi

  if [[ -z "$(ls -A "$work_dir" 2>/dev/null)" ]]; then
    warn "no artifacts found for ${module}; skipping (state exists but no terraform snapshot)"
    return 1
  fi

  (
    cd "$work_dir"
    terraform init -reconfigure -input=false \
      -backend-config="bucket=${BUCKET}" \
      -backend-config="region=${STATE_REGION}" \
      -backend-config="key=${state_key}"
    terraform destroy -auto-approve -input=false
  ) || return 1

  if ! $KEEP_S3; then
    log "Removing S3 state/artifacts for ${module}"
    aws s3 rm "s3://${BUCKET}/${STATE_PREFIX}${module}/" --recursive --only-show-errors || \
      warn "s3 cleanup had errors for ${module}"
  fi

  return 0
}

for module in "${SELECTED[@]}"; do
  if destroy_module "$module"; then
    SUCCEEDED+=("$module")
  else
    FAILURES+=("$module")
  fi
done

printf '\n'
log "Summary:"
log "  succeeded: ${#SUCCEEDED[@]}"
log "  failed:    ${#FAILURES[@]}"

if [[ ${#FAILURES[@]} -gt 0 ]]; then
  err "Failed modules:"
  for module in "${FAILURES[@]}"; do
    printf '  - %s\n' "$module" >&2
  done
  exit 1
fi
