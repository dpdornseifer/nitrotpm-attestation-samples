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

# Emit the bootstrap key policy on stdout. The Custodian gets policy control,
# lifecycle and grant audit; the Provisioner gets Encrypt only. Splitting them means
# no single party can both rewrite the policy (grant-plant) and mint ciphertext
# (DEK substitution) during the bootstrap window.
#
# Collapses to the original single statement when the provisioner is absent or is
# the same principal, so the zero-config path is byte-identical to the pre-split
# policy. Args: <custodian_principal> [provisioner_principal].
build_bootstrap_policy() {
  local custodian="$1" provisioner="${2:-}"

  if [ -z "$provisioner" ] || [ "$provisioner" = "$custodian" ]; then
    cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Allow provisioning to wrap the DEK, install the final key policy, and audit grants",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${custodian}"
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
    return
  fi

  cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Custodian installs the final key policy and audits grants",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${custodian}"
      },
      "Action": [
        "kms:PutKeyPolicy",
        "kms:ScheduleKeyDeletion",
        "kms:ListGrants",
        "kms:RevokeGrant"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Provisioner wraps the DEK during the bootstrap window only",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${provisioner}"
      },
      "Action": [
        "kms:Encrypt"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

# Convert tpm_pcr.json into "kms:RecipientAttestation:NitroTPMPCR<n>": "<sha384>" pairs for
# the key policy condition. <required-pcrs> is mandatory: accepting whatever happens to be
# in the file made a weaker gate indistinguishable from success.
# Args: <measurements-file> <required-pcrs, space-separated e.g. "PCR4 PCR7">.
extract_pcr_values() {
  local measurements_file="$1" required_pcrs="${2:-}"

  if [ ! -f "$measurements_file" ]; then
    echo "Error: Measurements file '$measurements_file' does not exist." >&2
    return 1
  fi

  if [ -z "$required_pcrs" ]; then
    echo "Error: extract_pcr_values requires an explicit list of PCRs to enforce." >&2
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

  # Fail closed before building the condition block: a missing PCR is a weaker gate.
  local pcr
  for pcr in $required_pcrs; do
    if ! jq -e --arg p "$pcr" \
        '.Measurements[$p] | type == "string" and test("^[0-9a-fA-F]{96}$")' \
        "$measurements_file" >/dev/null 2>&1; then
      echo "Error: required $pcr is missing or not a SHA384 hex value in '$measurements_file'." >&2
      echo "       Refusing to install a key policy that does not gate on $pcr." >&2
      echo "       Present: $(jq -r '.Measurements | keys | join(", ")' "$measurements_file" 2>/dev/null)" >&2
      return 1
    fi
  done

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

# Emit the final, PCR-gated key policy on stdout. Admin keeps ScheduleKeyDeletion (clean.sh),
# grant audit and GetKeyPolicy (the read-back below); Encrypt and PutKeyPolicy are gone for
# good and Decrypt requires the attestation condition.
# Built with jq -n so a malformed PCR condition fails here rather than installing a policy
# whose condition does not parse the way it reads.
# Args: <admin-principal> <instance-role-arn> <pcr-condition-object>.
build_final_policy() {
  local admin="$1" instance_role="$2" pcr_condition="$3"

  jq -n --arg admin "$admin" --arg role "$instance_role" --argjson pcrs "$pcr_condition" '{
    Version: "2012-10-17",
    Statement: [
      { Sid: "Allow provisioning to schedule key deletion and keep grants auditable",
        Effect: "Allow",
        Principal: {AWS: $admin},
        Action: ["kms:ScheduleKeyDeletion","kms:ListGrants","kms:RevokeGrant","kms:GetKeyPolicy"],
        Resource: "*" },
      { Sid: "Allow decryption for the Instance role",
        Effect: "Allow",
        Principal: {AWS: $role},
        Action: ["kms:Decrypt"],
        Resource: "*",
        Condition: {StringEqualsIgnoreCase: $pcrs} },
      { Sid: "Deny grant creation to everyone; grants bypass the PCR condition",
        Effect: "Deny",
        Principal: "*",
        Action: "kms:CreateGrant",
        Resource: "*" }
    ]}'
}

# Assert the security properties of the key policy actually in force after put-key-policy.
# Diffing the document against the one just sent does not work: KMS re-serializes what it
# stores (whitespace, and a bare "Principal": "*" returns as {"AWS": "*"}), so normalization
# is indistinguishable from a racing PutKeyPolicy. Check the properties that make the policy
# ours instead — only the instance role may Decrypt, only under exactly these PCRs,
# CreateGrant is denied to everyone, and no Allow keeps the ratcheted actions.
# Prints one line per fault; empty output means the policy in force is ours.
# Args: <policy-json> <instance-role-arn> <pcr-condition-object>.
kms_policy_faults() {
  local policy="$1" instance_role="$2" pcr_condition="$3"

  printf '%s' "$policy" | jq -r \
    --arg role "$instance_role" --argjson pcrs "$pcr_condition" '
    def as_list: if type == "array" then . else [.] end;
    def actions: [.Action // [] | as_list | .[] | ascii_downcase];
    def principals: [ if (.Principal | type) == "string" then .Principal
                      else (.Principal.AWS // empty) | as_list | .[] end ];

    [ .Statement[] | select(.Effect == "Allow") ] as $allow
    # NotAction, or a Decrypt buried in kms:*, both land here or nowhere — either way the
    # count check below fails closed rather than passing an unrecognised shape.
    | [ $allow[] | select(actions | any(. == "kms:decrypt" or . == "kms:*")) ] as $decrypt
    | [ .Statement[] | select(.Effect == "Deny")
        | select(actions | any(. == "kms:creategrant" or . == "kms:*")) ] as $deny
    | [ if ($decrypt | length) != 1 then
          "kms:Decrypt is granted by \($decrypt | length) Allow statement(s), expected exactly 1"
        else
          ( if ($decrypt[0] | principals) != [$role] then
              "kms:Decrypt principal is [\($decrypt[0] | principals | join(", "))], expected [\($role)]"
            else empty end ),
          ( if (($decrypt[0].Condition // {}).StringEqualsIgnoreCase // {}) != $pcrs then
              "kms:Decrypt is not gated on exactly the PCR values just measured"
            else empty end )
        end,
        ( if ([$allow[] | actions] | flatten
              | any(. == "kms:putkeypolicy" or . == "kms:encrypt" or . == "kms:*")) then
            "an Allow statement still grants kms:PutKeyPolicy, kms:Encrypt or kms:*"
          else empty end ),
        ( if ([$deny[] | principals] | flatten | any(. == "*")) then empty
          else "kms:CreateGrant is not denied to all principals" end )
      ] | .[]'
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
