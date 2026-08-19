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
  echo "Usage: $0 -k KEY_ARN -r INSTANCE_ROLE -a ADMIN_ROLE -m MEASUREMENTS -p REQUIRE_PCRS"
  echo "  -k, --key-arn             ARN (or id) of the key created by 02a"
  echo "  -r, --instance-role       ARN of the instance role allowed to decrypt"
  echo "  -a, --admin-role          ARN of the provisioning (admin) principal"
  echo "  -m, --measurements        Folder containing tpm_pcr.json (required)"
  echo "  -p, --require-pcrs        PCRs that MUST be gated, e.g. \"PCR4 PCR7\" (required)"
  exit 1
}

KEY_ARN=""
INSTANCE_ROLE=""
ADMIN_ROLE=""
# No defaults: the old MEASUREMENTS="result" silently produced a PCR4-only gate.
# finalize-key.sh decides both and explains the PCR4/PCR7 split.
MEASUREMENTS=""
REQUIRE_PCRS=""

while [[ "$#" -gt 0 ]]; do
  case $1 in
    -k|--key-arn) KEY_ARN="$2"; shift ;;
    -r|--instance-role) INSTANCE_ROLE="$2"; shift ;;
    -a|--admin-role) ADMIN_ROLE="$2"; shift ;;
    -m|--measurements) MEASUREMENTS="$2"; shift ;;
    -p|--require-pcrs) REQUIRE_PCRS="$2"; shift ;;
    *) usage ;;
  esac
  shift
done

if [ -z "$KEY_ARN" ] || [ -z "$INSTANCE_ROLE" ] || [ -z "$ADMIN_ROLE" ] \
   || [ -z "$MEASUREMENTS" ] || [ -z "$REQUIRE_PCRS" ]; then
  echo "Error: key ARN, instance role ARN, admin role ARN, measurements folder and required PCRs are all required."
  usage
fi

if [ ! -d "$MEASUREMENTS" ]; then
  echo "Error: Measurements folder '$MEASUREMENTS' does not exist."
  exit 1
fi

if ! PCR_VALUES=$(extract_pcr_values "$MEASUREMENTS/tpm_pcr.json" "$REQUIRE_PCRS"); then
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

# One canonical condition object for both the document and its read-back check: when the two
# were built separately, the verification could disagree with what was installed.
PCR_CONDITION="{$PCR_VALUES}"

if ! KEY_POLICY=$(build_final_policy "$ADMIN_PRINCIPAL" "$INSTANCE_ROLE" "$PCR_CONDITION"); then
  echo "Error: could not build the final key policy from the extracted PCR values." >&2
  exit 1
fi

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

# put-key-policy returning 200 proves the call was accepted, not that our document is the
# one in force — a racing PutKeyPolicy in the bootstrap window would go unnoticed.
echo "Verifying the policy in force gates Decrypt on the measured PCRs..."
if ! INSTALLED_POLICY=$(aws kms get-key-policy --key-id "$KEY_ARN" \
      --policy-name default --query Policy --output text); then
  echo "Error: cannot read back the key policy on $KEY_ARN; cannot confirm the swap." >&2
  exit 1
fi

if ! POLICY_FAULTS=$(kms_policy_faults "$INSTALLED_POLICY" "$INSTANCE_ROLE" "$PCR_CONDITION"); then
  echo "Error: cannot evaluate the key policy in force on $KEY_ARN." >&2
  exit 1
fi

if [ -n "$POLICY_FAULTS" ]; then
  echo "Error: the policy in force on $KEY_ARN is not the one just installed:" >&2
  printf '%s\n' "$POLICY_FAULTS" | sed 's/^/       - /' >&2
  echo "       Someone else wrote this key policy. Treat the key as compromised." >&2
  echo "       Policy in force:" >&2
  printf '%s' "$INSTALLED_POLICY" | jq -S . >&2
  exit 1
fi
echo "Installed policy verified: Decrypt is PCR-gated to the instance role; PutKeyPolicy, Encrypt and CreateGrant are gone."

# Check grants AFTER finalize: a pre-check races the plant, whereas the final policy has
# already denied CreateGrant. Polled because CreateGrant is eventually consistent.
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
