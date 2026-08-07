#!/bin/bash
# Phase one of two-step KMS provisioning: create the key under a bootstrap policy and
# pin the ARN into the image source before the AMI build. Encrypt lets 03 wrap the DEK;
# 02b then strips PutKeyPolicy + Encrypt. ListGrants/RevokeGrant let 02b detect and clear
# any grant planted in this window (grants bypass the PCR policy) and persist for audit.
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_DIR="$( cd "$SCRIPT_DIR/../.." &> /dev/null && pwd )"

# shellcheck source-path=SCRIPTDIR/../lib
# shellcheck source=../lib/kms.sh
. "$SCRIPT_DIR/../lib/kms.sh"

usage() {
  echo "Usage: $0 -a ADMIN_ROLE [-o ARN_FILE] | --admin-role ADMIN_ROLE [--arn-file ARN_FILE]"
  echo "  -a, --admin-role          ARN of the provisioning (admin) principal"
  echo "  -o, --arn-file            Where to pin the key ARN (default: <example>/kms-key-arn.txt)"
  exit 1
}

ADMIN_ROLE=""
ARN_FILE="$PROJECT_DIR/kms-key-arn.txt"

while [[ "$#" -gt 0 ]]; do
  case $1 in
    -a|--admin-role) ADMIN_ROLE="$2"; shift ;;
    -o|--arn-file) ARN_FILE="$2"; shift ;;
    *) usage ;;
  esac
  shift
done

if [ -z "$ADMIN_ROLE" ]; then
  echo "Error: Admin role ARN is required."
  usage
fi

# Check git tracking before creating the key: an untracked ARN file is invisible to git+file:// flake refs, leaving an orphaned key.
if git -C "$PROJECT_DIR" rev-parse --git-dir >/dev/null 2>&1; then
  if ! git -C "$PROJECT_DIR" ls-files --error-unmatch "$ARN_FILE" >/dev/null 2>&1; then
    echo "Error: '$ARN_FILE' is not tracked by git, so the build will not see it." >&2
    echo "       A git+file:// flake ref only includes tracked paths." >&2
    echo "       Fix with: git add '$ARN_FILE'" >&2
    exit 1
  fi
fi

if ! ADMIN_PRINCIPAL=$(normalize_admin_principal "$ADMIN_ROLE"); then
  echo "Error: Failed to resolve admin principal '$ADMIN_ROLE'."
  exit 1
fi

# No IAM delegation statement, so --bypass-policy-lockout-safety-check is required (same as the final policy).
BOOTSTRAP_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Allow provisioning to wrap the DEK, install the final key policy, and audit grants",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${ADMIN_PRINCIPAL}"
      },
      "Action": [
        "kms:PutKeyPolicy",
        "kms:Encrypt",
        "kms:ScheduleKeyDeletion",
        "kms:ListGrants",
        "kms:RevokeGrant"
      ],
      "Resource": "*"
    }
  ]
}
EOF
)

POLICY_FILE=$(mktemp -t kms_bootstrap_policy.XXXXXX.json)
trap 'rm -f "$POLICY_FILE"' EXIT
echo "$BOOTSTRAP_POLICY" > "$POLICY_FILE"
echo "Bootstrap KMS policy written to $POLICY_FILE"

echo "Creating KMS key with bootstrap policy (Encrypt + PutKeyPolicy, no Decrypt)..."
if ! KEY_OUTPUT=$(kms_call_with_retry "KMS key creation" create-key \
      --description "NitroTPM attestation example key" \
      --bypass-policy-lockout-safety-check \
      --policy file://"$POLICY_FILE"); then
  exit 1
fi

KEY_ARN=$(echo "$KEY_OUTPUT" | jq -r '.KeyMetadata.Arn')
if [ -z "$KEY_ARN" ] || [ "$KEY_ARN" = "null" ]; then
  echo "Error: Could not read KeyMetadata.Arn from the create-key response." >&2
  echo "$KEY_OUTPUT" >&2
  exit 1
fi

printf '%s\n' "$KEY_ARN" > "$ARN_FILE"
echo "Pinned KMS key ARN into $ARN_FILE"

echo "KMS key created with ARN: $KEY_ARN"
