#!/bin/bash
#
# Shared helpers for 02a_create_kms_key.sh and 02b_finalize_kms_policy.sh.
# Two-step flow exists because the KMS key ARN must be pinned into the image (measured
# into PCR4) before the build, but PCR-gated policy needs post-build PCRs — so 02a
# bootstraps under PutKeyPolicy-only and 02b finalizes in one irreversible call.

# Assumed-role session ARNs (sts::…:assumed-role/…) are not valid KMS principals; resolve to the IAM role ARN.
normalize_admin_principal() {
  local principal="$1"

  if [[ "$principal" =~ ^arn:aws[a-zA-Z-]*:sts::[0-9]{12}:assumed-role/([^/]+)/.+$ ]]; then
    local role_name="${BASH_REMATCH[1]}"
    aws iam get-role --role-name "$role_name" --query 'Role.Arn' --output text
    return
  fi

  echo "$principal"
}

# Convert tpm_pcr.json into "kms:RecipientAttestation:NitroTPMPCR<n>": "<sha384>" pairs for the key policy condition. Args: <measurements-file>.
extract_pcr_values() {
  local measurements_file="$1"

  if [ ! -f "$measurements_file" ]; then
    echo "Error: Measurements file '$measurements_file' does not exist." >&2
    return 1
  fi

  if ! jq empty "$measurements_file" 2>/dev/null; then
    echo "Error: Invalid JSON in measurements file '$measurements_file'." >&2
    return 1
  fi
  if ! jq -e '.Measurements' "$measurements_file" >/dev/null 2>&1; then
    echo "Error: No 'Measurements' object found in '$measurements_file'." >&2
    return 1
  fi

  # Inline `if ! pcr_output=$(...)` because `set -e` is active: a bare assignment suppresses errexit.
  local pcr_output
  if ! pcr_output=$(jq -r '
    .Measurements
    | to_entries
    | map(select(.key | test("^PCR([0-9]|1[0-9]|2[0-3])$")) | select(.value | type == "string" and test("^[0-9a-fA-F]{96}$")))
    | if length == 0 then
        error("No valid PCR entries found. PCR keys must be PCR0-PCR23 with SHA384 hash values (96 hex characters).")
      else
        map("\"kms:RecipientAttestation:NitroTPM" + .key + "\": \"" + .value + "\"")
        | join(", ")
      end
  ' "$measurements_file" 2>&1); then
    if echo "$pcr_output" | grep -q "No valid PCR entries found"; then
      echo "Error: $pcr_output" >&2
    else
      echo "Error: Failed to process PCR values from '$measurements_file'. Invalid PCR format detected." >&2
      echo "Expected: PCR keys (PCR0-PCR23) with SHA384 hash values (96 hex characters)." >&2
    fi
    return 1
  fi

  if [ -z "$pcr_output" ]; then
    echo "Error: No valid PCR values extracted from '$measurements_file'." >&2
    return 1
  fi

  echo "$pcr_output"
  return 0
}

# Retry only IAM-propagation "invalid principals" errors (newly-created role not yet visible to KMS); all others fail immediately. Args: <what-for-messages> <aws-kms-args...>.
kms_call_with_retry() {
  local what=$1
  shift
  local max_attempts=30
  local attempt=1
  local sleep_interval=2
  local output="" exit_code

  while [ $attempt -le $max_attempts ]; do
    set +e
    output=$(aws kms "$@" 2>&1)
    exit_code=$?
    set -e

    if echo "$output" | grep -q "An error occurred"; then
      if echo "$output" | grep -q "invalid principals"; then
        sleep $sleep_interval
        attempt=$((attempt + 1))
        continue
      fi

      echo "Error: $what failed with a non-retryable error: $output" >&2
      return 1
    fi

    if [ $exit_code -ne 0 ]; then
      echo "Error: $what failed: $output" >&2
      return 1
    fi

    echo "$output"
    return 0
  done

  echo "Error: $what did not succeed after $max_attempts attempts" >&2
  echo "Last output: $output" >&2
  return 1
}
