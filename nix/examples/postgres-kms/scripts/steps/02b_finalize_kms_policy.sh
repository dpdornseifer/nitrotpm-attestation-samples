#!/bin/bash
# Phase two: replace the bootstrap policy with the PCR-gated final policy.
# One-way ratchet: drops kms:PutKeyPolicy AND kms:Encrypt in this call; admin keeps
# only ScheduleKeyDeletion. Runs after 03 has wrapped the DEK under the bootstrap grant.
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
      "Sid": "Allow provisioning to schedule key deletion",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${ADMIN_PRINCIPAL}"
      },
      "Action": [
        "kms:ScheduleKeyDeletion"
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

echo "KMS key policy finalized for $KEY_ARN (kms:PutKeyPolicy revoked)"
