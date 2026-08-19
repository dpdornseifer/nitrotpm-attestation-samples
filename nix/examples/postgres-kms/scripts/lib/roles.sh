#!/bin/bash
#
# Per-stage credential scoping for the role-separated ceremony. Each stage owns
# exactly one role; this is how it adopts it.
#
# An empty role ARN is a passthrough. That is deliberately both the zero-config
# path (no flags supplied, everything runs as the caller) and the production path:
# in a real ceremony the Custodian's shell already holds Custodian credentials, so
# a script assuming a role would be backwards.
#
# All diagnostics go to stderr: callers parse step-script stdout with grep -oP, so a
# single stray stdout line breaks the parse silently.

# Run a command under <role_arn>'s temporary credentials, or ambient credentials
# when the ARN is empty. Args: <role_arn> [--] <cmd> [args...].
assume_role_exec() {
  local role_arn="${1:-}"
  shift || true
  [ "${1:-}" = "--" ] && shift

  if [ $# -eq 0 ]; then
    echo "Error: assume_role_exec called without a command." >&2
    return 2
  fi

  if [ -z "$role_arn" ]; then
    "$@"
    return
  fi

  local creds
  if ! creds=$(aws sts assume-role \
        --role-arn "$role_arn" \
        --role-session-name "nitrotpm-$$" \
        --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
        --output text 2>&1); then
    echo "Error: could not assume '$role_arn': $creds" >&2
    return 1
  fi

  echo "Assumed role: $role_arn" >&2

  # Subshell so the exported credentials die with the command; the caller's
  # ambient credentials are never mutated.
  (
    AWS_ACCESS_KEY_ID=$(printf '%s' "$creds" | cut -f1)
    AWS_SECRET_ACCESS_KEY=$(printf '%s' "$creds" | cut -f2)
    AWS_SESSION_TOKEN=$(printf '%s' "$creds" | cut -f3)
    export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
    "$@"
  )
}

# The principal to name in a key policy: the explicit role ARN, or the caller when
# no flag was supplied (zero-config, where the caller IS that role).
# Args: <role_arn_or_empty>.
resolve_policy_principal() {
  local arn="${1:-}"
  if [ -n "$arn" ]; then
    printf '%s\n' "$arn"
  else
    aws sts get-caller-identity --query 'Arn' --output text
  fi
}
