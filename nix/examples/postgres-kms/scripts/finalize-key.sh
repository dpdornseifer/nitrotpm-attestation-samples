#!/bin/bash
# Stage 5 of 6 — KEY CUSTODIAN.
#
# Installs the final key policy: Decrypt gated on the instance role AND the PCR
# values, kms:Encrypt and kms:PutKeyPolicy revoked, kms:CreateGrant denied to
# everyone, then audits for a grant planted during the bootstrap window.
#
# This is the cross-role gate. The PCRs come from the Deployer (stage 3) and the
# instance role from the Operator (stage 1), and only the Custodian can install the
# policy — so no single party both decides what code runs and decides which
# measurements release the key.
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/roles.sh
. "$SCRIPT_DIR/lib/roles.sh"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/aws-creds.sh
. "$SCRIPT_DIR/lib/aws-creds.sh"

usage() {
  echo "Usage: $0 --key-id ARN --instance-role-arn ARN --pcr-dir PATH [--custodian-role-arn ARN]" >&2
  echo "          [--allow-pcr4-only]" >&2
  echo "  --key-id                KMS key to finalize (required)" >&2
  echo "  --instance-role-arn     Instance role from stage 1 (required)" >&2
  echo "  --pcr-dir               Directory holding tpm_pcr.json from stage 3 (required)" >&2
  echo "  --custodian-role-arn    Assume this role for the work (default: ambient credentials)" >&2
  echo "  --allow-pcr4-only       Gate on PCR4 alone when the image is unsigned. Accepts a" >&2
  echo "                          policy that does NOT attest secure boot state." >&2
  exit 1
}

KEY_ID=""
INSTANCE_ROLE_ARN=""
PCR_DIR=""
CUSTODIAN_ROLE_ARN=""
ALLOW_PCR4_ONLY=false

while [[ "$#" -gt 0 ]]; do
  case $1 in
    --key-id) KEY_ID="${2:?--key-id requires a value}"; shift ;;
    --instance-role-arn) INSTANCE_ROLE_ARN="${2:?--instance-role-arn requires a value}"; shift ;;
    --pcr-dir) PCR_DIR="${2:?--pcr-dir requires a value}"; shift ;;
    --custodian-role-arn) CUSTODIAN_ROLE_ARN="${2:?--custodian-role-arn requires a value}"; shift ;;
    --allow-pcr4-only) ALLOW_PCR4_ONLY=true ;;
    *) usage ;;
  esac
  shift
done

# Fail closed on every missing input. A finalize that proceeds without PCRs would
# install a policy gated on nothing — weaker than not finalizing, and it would look
# like success.
for REQUIRED in KEY_ID INSTANCE_ROLE_ARN PCR_DIR; do
  if [ -z "${!REQUIRED}" ]; then
    echo "Error: --${REQUIRED//_/-} is required." >&2
    usage
  fi
done

if [ ! -f "$PCR_DIR/tpm_pcr.json" ]; then
  echo "Error: no tpm_pcr.json in '$PCR_DIR'; stage 3 must run first." >&2
  exit 1
fi

# A PCR4-only gate must be a choice, not a side effect of which directory was passed:
# result/ carries PCR4 alone (lib.nix strips PCR7, since signing happens after the build)
# while signed-image/ carries both, and either one used to report success.
if jq -e '.Measurements.PCR7 | type == "string"' "$PCR_DIR/tpm_pcr.json" >/dev/null 2>&1; then
  REQUIRE_PCRS="PCR4 PCR7"
elif [ "$ALLOW_PCR4_ONLY" = true ]; then
  REQUIRE_PCRS="PCR4"
  echo -e "\033[33m⚠️  WARNING: gating on PCR4 only — no PCR7 in $PCR_DIR/tpm_pcr.json.\033[0m" >&2
  echo -e "\033[33m   The key policy will NOT attest secure boot state, so an unsigned or\033[0m" >&2
  echo -e "\033[33m   differently-signed UKI with the same store contents still satisfies it.\033[0m" >&2
else
  echo "Error: no PCR7 in '$PCR_DIR/tpm_pcr.json'; refusing to install a PCR4-only policy." >&2
  echo "       A PCR4-only gate does not attest secure boot state." >&2
  echo "       Either sign the image first (stage 3 runs .#sign-efi-image, which writes" >&2
  echo "       PCR4+PCR7 to signed-image/tpm_pcr.json) and point --pcr-dir there," >&2
  echo "       or pass --allow-pcr4-only to accept the weaker gate deliberately." >&2
  exit 1
fi

resolve_aws_credentials || exit 1

CUSTODIAN_PRINCIPAL=$(resolve_policy_principal "$CUSTODIAN_ROLE_ARN")

echo "Stage 5/6 (Custodian): gating Decrypt on the instance role and PCRs, revoking Encrypt..." >&2

# Print the PCR values about to be committed to the irreversible policy so the
# Custodian can verify they match the intended AMI before the ratchet closes.
echo "PCR values that will be gated in the final KMS policy (verify against your AMI):" >&2
jq -r '.Measurements | to_entries | map(select(.key | test("^PCR[0-9]+"))) | .[] | "  \(.key): \(.value)"' \
  "$PCR_DIR/tpm_pcr.json" >&2
echo "WARNING: the next step is IRREVERSIBLE — once installed, this policy cannot be widened." >&2
echo "Confirm these PCR values match the AMI you intend to launch before proceeding." >&2

if ! assume_role_exec "$CUSTODIAN_ROLE_ARN" -- \
      "$SCRIPT_DIR/steps/02b_finalize_kms_policy.sh" \
      -k "$KEY_ID" -r "$INSTANCE_ROLE_ARN" -a "$CUSTODIAN_PRINCIPAL" -m "$PCR_DIR" \
      -p "$REQUIRE_PCRS" >&2; then
  echo "Error: KMS key policy finalization failed." >&2
  exit 1
fi

echo "KMS_POLICY: finalized"
echo "The bootstrap window is closed: Encrypt and PutKeyPolicy are gone." >&2
echo "Next (Operator): ./scripts/deploy.sh --ami-id <AMI_ID> --instance-profile <PROFILE>" >&2
