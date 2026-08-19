#!/bin/bash
# Stage 4 of 6 — SECRETS / PKI PROVISIONER.
#
# Mints and wraps the DEK, then issues the CA, server and client certificates and
# encrypts the server bundle with that same DEK.
#
# Both steps consume the PLAINTEXT DEK, so both live in this one stage: the plaintext
# dies when this process exits and never crosses a stage boundary. Only ciphertext
# (artifacts/user_data.json) and the client-bundle secret ARN travel onward.
#
# The Provisioner holds kms:Encrypt but no kms:PutKeyPolicy, so it can wrap a DEK but
# cannot rewrite the key policy — it cannot plant a grant. The Custodian is the
# reverse. That is the split.
#
# No `set -x`: xtrace would echo the plaintext DEK.
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_DIR="$( cd "$SCRIPT_DIR/.." &> /dev/null && pwd )"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/roles.sh
. "$SCRIPT_DIR/lib/roles.sh"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/aws-creds.sh
. "$SCRIPT_DIR/lib/aws-creds.sh"

usage() {
  echo "Usage: $0 --key-id ARN [--provisioner-role-arn ARN]" >&2
  echo "  --key-id                  KMS key ARN whose bootstrap policy grants Encrypt (required)" >&2
  echo "  --provisioner-role-arn    Assume this role for the work (default: ambient credentials)" >&2
  exit 1
}

KEY_ID=""
PROVISIONER_ROLE_ARN=""

while [[ "$#" -gt 0 ]]; do
  case $1 in
    --key-id) KEY_ID="${2:?--key-id requires a value}"; shift ;;
    --provisioner-role-arn) PROVISIONER_ROLE_ARN="${2:?--provisioner-role-arn requires a value}"; shift ;;
    *) usage ;;
  esac
  shift
done

[ -n "$KEY_ID" ] || { echo "Error: --key-id is required." >&2; usage; }

resolve_aws_credentials || exit 1

# 0700 dir plus an EXIT trap: the trap is the part that matters, because a set -e
# abort or a signal between mktemp and an explicit rm would otherwise leave the
# plaintext DEK on disk.
KEY_TMPDIR=$(mktemp -d)
trap 'rm -rf "$KEY_TMPDIR"' EXIT INT TERM
# mktemp -d already yields 0700; this is defence in depth against a permissive umask.
chmod 700 "$KEY_TMPDIR"
KEY_FILE="$KEY_TMPDIR/symmetric_key"

echo "Stage 4/6 (Provisioner): minting and wrapping the DEK..." >&2
if ! assume_role_exec "$PROVISIONER_ROLE_ARN" -- \
      "$SCRIPT_DIR/steps/03_create_symmetric_key.sh" \
      -k "$KEY_ID" --plaintext-key-out "$KEY_FILE" >&2; then
  echo "Error: symmetric key creation failed." >&2
  exit 1
fi

echo "Stage 4/6 (Provisioner): issuing certificates and encrypting the server bundle..." >&2
if ! CERT_OUTPUT=$(assume_role_exec "$PROVISIONER_ROLE_ARN" -- \
      "$SCRIPT_DIR/steps/05a_create_certificates.sh" --symmetric-key "$KEY_FILE"); then
  echo "Error: certificate creation failed." >&2
  echo "$CERT_OUTPUT" >&2
  exit 1
fi

# Destroy the plaintext as soon as the last consumer is done, rather than waiting
# for the trap. The trap remains as the abort-path guarantee.
rm -f "$KEY_FILE"

SECRET_ARN=$(printf '%s' "$CERT_OUTPUT" | grep -oP 'SECRET_ARN: \K.*' | head -n1)
if [ -z "$SECRET_ARN" ]; then
  echo "Error: could not extract SECRET_ARN from the certificate step output." >&2
  echo "$CERT_OUTPUT" >&2
  exit 1
fi

echo "SECRET_ARN: $SECRET_ARN"

echo "" >&2
echo "Wrapped DEK and encrypted server bundle are in $PROJECT_DIR/artifacts/user_data.json." >&2
echo "The plaintext DEK has been destroyed and never left this stage." >&2
echo "Next (Custodian): ./scripts/finalize-key.sh --key-id $KEY_ID \\" >&2
echo "  --instance-role-arn <INSTANCE_ROLE_ARN> --pcr-dir <PCR_DIR>" >&2
