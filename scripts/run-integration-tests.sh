#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$PROJECT_DIR/.env.integration"

GO_FLAGS=""
TARGET="./..."
DESTROY_FIXTURES=false

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --go-flags)
      GO_FLAGS="$2"
      shift 2
      ;;
    --go-flags=*)
      GO_FLAGS="${1#*=}"
      shift
      ;;
    --destroy)
      DESTROY_FIXTURES=true
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [TARGET] [--go-flags '<additional go test flags>']"
      echo ""
      echo "Runs Aurelian integration tests."
      echo ""
      echo "Arguments:"
      echo "  TARGET        Go test target pattern (default: ./...)"
      echo ""
      echo "Options:"
      echo "  --go-flags    Additional flags to pass to 'go test' (e.g. '--go-flags \"-v -timeout 30m\"')"
      echo "  --destroy     Destroy and redeploy Terraform fixtures before running tests"
      echo ""
      echo "Examples:"
      echo "  $0                              # run all integration tests"
      echo "  $0 ./pkg/azure/...              # run just azure component tests"
      echo "  $0 ./pkg/modules/aws/recon/...  # run just aws recon module tests"
      echo "  $0 ./pkg/modules/gcp/recon/...  # run just gcp recon module tests"
      exit 0
      ;;
    -*)
      echo "Unknown argument: $1"
      echo "Run $0 --help for usage."
      exit 1
      ;;
    *)
      TARGET="$1"
      shift
      ;;
  esac
done

# Load existing env file if present
AZURE_SUBSCRIPTION_ID=""
AWS_PROFILE=""
GCP_PROJECT_ID=""
GCP_ACCOUNT=""

if [[ -f "$ENV_FILE" ]]; then
  # Source the file to pick up existing values
  set +u
  source "$ENV_FILE"
  set -u
fi

# Determine which platforms are needed based on target path.
# AWS is always required (S3 remote state for Terraform fixtures).
NEED_AZURE=false
NEED_GCP=false
case "$TARGET" in
  *azure*) NEED_AZURE=true ;;
  *gcp*)   NEED_GCP=true ;;
  *aws*)   ;; # AWS is already always required
  *)       NEED_AZURE=true; NEED_GCP=true ;; # ./... or unrecognized — require all
esac

# Prompt for missing values
if $NEED_AZURE && [[ -z "$AZURE_SUBSCRIPTION_ID" ]]; then
  read -rp "Enter AZURE_SUBSCRIPTION_ID: " AZURE_SUBSCRIPTION_ID
  if [[ -z "$AZURE_SUBSCRIPTION_ID" ]]; then
    echo "ERROR: AZURE_SUBSCRIPTION_ID is required." >&2
    exit 1
  fi
fi

if [[ -z "$AWS_PROFILE" ]]; then
  read -rp "Enter AWS_PROFILE: " AWS_PROFILE
  if [[ -z "$AWS_PROFILE" ]]; then
    echo "ERROR: AWS_PROFILE is required." >&2
    exit 1
  fi
fi

if $NEED_GCP && [[ -z "$GCP_PROJECT_ID" ]]; then
  read -rp "Enter GCP_PROJECT_ID: " GCP_PROJECT_ID
  if [[ -z "$GCP_PROJECT_ID" ]]; then
    echo "ERROR: GCP_PROJECT_ID is required." >&2
    exit 1
  fi
fi

if $NEED_GCP && [[ -z "$GCP_ACCOUNT" ]]; then
  read -rp "Enter GCP_ACCOUNT (gcloud account email): " GCP_ACCOUNT
  if [[ -z "$GCP_ACCOUNT" ]]; then
    echo "ERROR: GCP_ACCOUNT is required." >&2
    exit 1
  fi
fi

# Save back to .env.integration
cat > "$ENV_FILE" <<EOF
AZURE_SUBSCRIPTION_ID=$AZURE_SUBSCRIPTION_ID
AWS_PROFILE=$AWS_PROFILE
GCP_PROJECT_ID=$GCP_PROJECT_ID
GCP_ACCOUNT=$GCP_ACCOUNT
EOF
echo "Saved credentials to $ENV_FILE"

# Validate Azure subscription
if $NEED_AZURE; then
  echo "Validating Azure subscription $AZURE_SUBSCRIPTION_ID..."
  if ! az account show --subscription "$AZURE_SUBSCRIPTION_ID" &>/dev/null; then
    echo "ERROR: Unable to access Azure subscription $AZURE_SUBSCRIPTION_ID with current 'az' credentials." >&2
    echo "Run 'az login' and try again." >&2
    exit 1
  fi
  echo "Azure subscription OK."
fi

# Validate AWS profile
echo "Validating AWS profile $AWS_PROFILE..."
if ! AWS_PROFILE="$AWS_PROFILE" aws sts get-caller-identity &>/dev/null; then
  echo "ERROR: Unable to authenticate with AWS profile '$AWS_PROFILE'." >&2
  echo "Check your AWS credentials and try again." >&2
  exit 1
fi
echo "AWS profile OK."

# Configure and validate GCP
if $NEED_GCP; then
  echo "Setting gcloud account to $GCP_ACCOUNT..."
  if ! gcloud config set account "$GCP_ACCOUNT" &>/dev/null; then
    echo "ERROR: Unable to set gcloud account to '$GCP_ACCOUNT'." >&2
    echo "Run 'gcloud auth login' and try again." >&2
    exit 1
  fi

  echo "Setting gcloud project to $GCP_PROJECT_ID..."
  if ! gcloud config set project "$GCP_PROJECT_ID" &>/dev/null; then
    echo "ERROR: Unable to set gcloud project to '$GCP_PROJECT_ID'." >&2
    exit 1
  fi

  echo "Validating GCP project $GCP_PROJECT_ID..."
  if ! gcloud projects describe "$GCP_PROJECT_ID" &>/dev/null; then
    echo "ERROR: Unable to access GCP project '$GCP_PROJECT_ID' with account '$GCP_ACCOUNT'." >&2
    echo "Run 'gcloud auth login' and try again." >&2
    exit 1
  fi
  echo "GCP project OK."
fi

# Run tests
echo ""
echo "Running integration tests..."
cd "$PROJECT_DIR"
if $NEED_AZURE; then
  export AZURE_SUBSCRIPTION_ID
fi
export AWS_PROFILE
if $NEED_GCP; then
  export GCP_PROJECT_ID
fi

if $DESTROY_FIXTURES; then
  export AURELIAN_DESTROY_FIXTURES=1
fi

set -x
go test -tags compute,integration -p=1 $GO_FLAGS "$TARGET"
