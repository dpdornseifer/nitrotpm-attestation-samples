#!/bin/bash
#
# Credential resolution shared by every ceremony stage. Ported from the former
# postgres-kms start.sh (deleted in the six-stage refactor), which resolved these
# before running any step. It lives in a library
# because each stage runs standalone under its own operator's shell, so no single
# orchestrator can do it on everyone's behalf.
#
# Why export rather than rely on the SDK's default chain: assume_role_exec runs the
# command in a subshell with explicit credential variables, and stage scripts invoke
# other scripts, so the region in particular must be present in the environment
# rather than only in ~/.aws/config.

# Resolve one variable from the environment, else from `aws configure get <key>`.
# Args: <var_name> <aws_config_key>. Returns 1 if neither yields a value.
_resolve_one() {
  local var_name="$1" config_key="$2" current value
  current="${!var_name:-}"
  if [ -n "$current" ]; then
    return 0
  fi

  value=$(aws configure get "$config_key" 2>/dev/null) || value=""
  if [ -n "$value" ]; then
    # shellcheck disable=SC2163  # indirect export is the point of this helper
    export "$var_name=$value"
    echo "$var_name resolved from 'aws configure get $config_key'." >&2
    return 0
  fi

  return 1
}

# Ensure the three required AWS variables are exported, plus the session token when
# one is available. Returns 1 naming the first variable that cannot be resolved.
resolve_aws_credentials() {
  local pairs=(
    "AWS_ACCESS_KEY_ID aws_access_key_id"
    "AWS_SECRET_ACCESS_KEY aws_secret_access_key"
    "AWS_DEFAULT_REGION region"
  )
  local pair var key

  for pair in "${pairs[@]}"; do
    read -r var key <<<"$pair"
    if ! _resolve_one "$var" "$key"; then
      echo "Error: $var is not set and not available via 'aws configure get $key'." >&2
      return 1
    fi
  done

  # Optional: only present for temporary credentials.
  _resolve_one AWS_SESSION_TOKEN aws_session_token || true
  return 0
}
