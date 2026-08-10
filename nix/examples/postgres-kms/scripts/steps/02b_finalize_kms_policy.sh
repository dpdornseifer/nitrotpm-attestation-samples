#!/bin/bash
# Phase two: replace the bootstrap policy with the PCR-gated final policy. Drops
# PutKeyPolicy + Encrypt; admin keeps ScheduleKeyDeletion + ListGrants/RevokeGrant so
# grants stay auditable. Fails closed if a grant was planted in the bootstrap window
# (grants bypass the PCR condition and outlive the swap). Runs after 03 wrapped the DEK.
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# shellcheck source-path=SCRIPTDIR/../lib
# shellcheck source=../lib/kms.sh
. "$SCRIPT_DIR/../lib/kms.sh"

usage() {
  echo "Usage: $0 -k KEY_ARN -r INSTANCE_ROLE -a ADMIN_ROLE [-m MEASUREMENTS]"
  echo "  -k, --key-arn             ARN (or id) of the key created by 02a"
  echo "  -r, --instance-role       ARN of the instance role allowed to decrypt"
  echo "  -a, --admin-role          ARN of the provisioning (admin) principal"
  echo "  -m, --measurements        Folder containing tpm_pcr.json (default: result)"
  exit 1
}

KEY_ARN=""
INSTANCE_ROLE=""
ADMIN_ROLE=""
MEASUREMENTS="result"

while [[ "$#" -gt 0 ]]; do
  case $1 in
    -k|--key-arn) KEY_ARN="$2"; shift ;;
    -r|--instance-role) INSTANCE_ROLE="$2"; shift ;;
    -a|--admin-role) ADMIN_ROLE="$2"; shift ;;
    -m|--measurements) MEASUREMENTS="$2"; shift ;;
    *) usage ;;
  esac
  shift
done

if [ -z "$KEY_ARN" ] || [ -z "$INSTANCE_ROLE" ] || [ -z "$ADMIN_ROLE" ]; then
  echo "Error: Key ARN, instance role ARN and admin role ARN are required."
  usage
fi

if [ ! -d "$MEASUREMENTS" ]; then
  echo "Error: Measurements folder '$MEASUREMENTS' does not exist."
  exit 1
fi

if ! PCR_VALUES=$(extract_pcr_values "$MEASUREMENTS/tpm_pcr.json"); then
  echo "Error: Failed to extract PCR values from measurements file."
  exit 1
fi

if [ -z "$PCR_VALUES" ]; then
  echo "Error: No PCR values were extracted."
  exit 1
fi

if ! ADMIN_PRINCIPAL=$(normalize_admin_principal "$ADMIN_ROLE"); then
  echo "Error: Failed to resolve admin principal '$ADMIN_ROLE'."
  exit 1
fi

# Admin retains ScheduleKeyDeletion (for clean.sh) only; Encrypt was used under the
# bootstrap policy before finalize, and Decrypt requires the PCR attestation condition.
KEY_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Allow provisioning to schedule key deletion and keep grants auditable",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${ADMIN_PRINCIPAL}"
      },
      "Action": [
        "kms:ScheduleKeyDeletion",
        "kms:ListGrants",
        "kms:RevokeGrant"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Allow decryption for the Instance role",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${INSTANCE_ROLE}"
      },
      "Action": [
        "kms:Decrypt"
      ],
      "Resource": "*",
      "Condition": {
        "StringEqualsIgnoreCase": {
${PCR_VALUES}
        }
      }
    },
    {
      "Sid": "Deny grant creation to everyone; grants bypass the PCR condition",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "kms:CreateGrant",
      "Resource": "*"
    }
  ]
}
EOF
)

KEY_POLICY_FILE=$(mktemp -t kms_policy.XXXXXX.json)
trap 'rm -f "$KEY_POLICY_FILE"' EXIT
echo "$KEY_POLICY" > "$KEY_POLICY_FILE"
echo "Final KMS policy written to $KEY_POLICY_FILE"

echo "Installing the attestation-gated key policy on $KEY_ARN..."
if ! kms_call_with_retry "KMS key policy update" put-key-policy \
      --key-id "$KEY_ARN" \
      --policy-name default \
      --bypass-policy-lockout-safety-check \
      --policy file://"$KEY_POLICY_FILE" >/dev/null; then
  exit 1
fi

# Check grants AFTER finalize: a pre-check races the plant, but the final policy denies
# CreateGrant + drops PutKeyPolicy, closing the window. Poll for CreateGrant's eventual
# consistency. Catches accidental/third-party/tooling grants; a malicious operator who
# single-steps this script is out of scope (see README: separation of duties).
echo "Verifying no grants were planted during the bootstrap window..."
GRANTS=""
for _ in 1 2 3 4 5 6; do
  if ! GRANTS=$(aws kms list-grants --key-id "$KEY_ARN" --query 'Grants[].GrantId' --output text); then
    echo "Error: failed to list grants on $KEY_ARN; cannot confirm the key is clean." >&2
    exit 1
  fi
  [ -n "$GRANTS" ] && break
  sleep 5
done
if [ -n "$GRANTS" ]; then
  echo "Error: grant(s) present on $KEY_ARN after finalize: $GRANTS" >&2
  echo "       A grant bypasses the PCR-gated policy. Revoke and investigate:" >&2
  echo "       aws kms revoke-grant --key-id $KEY_ARN --grant-id <id>" >&2
  exit 1
fi

echo "KMS key policy finalized for $KEY_ARN (PutKeyPolicy + Encrypt dropped; no grants present)"
