#!/bin/bash
# One-time bootstrap of the five provisioning roles, so the separation of duties is
# enforced by IAM rather than by convention. NOT part of the ceremony: this needs
# iam:CreateRole + iam:PutRolePolicy, which no provisioning role holds.
#
# Idempotent: an existing role has its inline policy refreshed rather than failing.
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# shellcheck source-path=SCRIPTDIR/../lib
# shellcheck source=../lib/kms.sh
. "$SCRIPT_DIR/../lib/kms.sh"
# shellcheck source-path=SCRIPTDIR/../lib
# shellcheck source=../lib/role-policies.sh
. "$SCRIPT_DIR/../lib/role-policies.sh"

usage() {
  echo "Usage: $0 [-r INSTANCE_ROLE_NAME] [-p INSTANCE_PROFILE_NAME] [--prefix PREFIX]" >&2
  echo "  -r, --instance-role       Workload role the Operator may manage (default: TpmAttestationRole)" >&2
  echo "  -p, --instance-profile    Workload profile the Operator may manage (default: TpmAttestationProfile)" >&2
  echo "      --prefix              Role name prefix (default: NitroTpm)" >&2
  exit 1
}

INSTANCE_ROLE_NAME="TpmAttestationRole"
INSTANCE_PROFILE_NAME="TpmAttestationProfile"
PREFIX="NitroTpm"

while [[ "$#" -gt 0 ]]; do
  case $1 in
    -r|--instance-role) INSTANCE_ROLE_NAME="$2"; shift ;;
    -p|--instance-profile) INSTANCE_PROFILE_NAME="$2"; shift ;;
    --prefix) PREFIX="$2"; shift ;;
    *) usage ;;
  esac
  shift
done

# One STS call: both fields come from the same response.
CALLER_IDENTITY=$(aws sts get-caller-identity --output json)
CALLER_ARN=$(jq -r '.Arn' <<<"$CALLER_IDENTITY")
ACCOUNT_ID=$(jq -r '.Account' <<<"$CALLER_IDENTITY")

# The caller must be able to assume each role it creates. An assumed-role session
# ARN is not a valid trust-policy principal, so resolve it to the IAM role ARN.
if ! TRUST_PRINCIPAL=$(normalize_admin_principal "$CALLER_ARN"); then
  echo "Error: could not resolve the caller principal '$CALLER_ARN'." >&2
  exit 1
fi

# Build with jq so no inline policy literal appears in this file (the tests enforce
# that all IAM permission policies come from lib/role-policies.sh).
TRUST_POLICY=$(jq -n --arg p "$TRUST_PRINCIPAL" \
  '{Version:"2012-10-17",Statement:[{Effect:"Allow",Principal:{AWS:$p},Action:"sts:AssumeRole"}]}')

# Create (or refresh) one role with a single inline policy read from stdin.
# Args: <role_name> <policy_name> <description>.
create_role_with_policy() {
  local role_name="$1" policy_name="$2" description="$3" policy_doc
  policy_doc=$(cat)

  local probe_err
  if probe_err=$(aws iam get-role --role-name "$role_name" 2>&1 >/dev/null); then
    echo "Role $role_name already exists; refreshing its inline policy." >&2
  elif printf '%s' "$probe_err" | grep -q 'NoSuchEntity'; then
    aws iam create-role \
      --role-name "$role_name" \
      --description "$description" \
      --assume-role-policy-document "$TRUST_POLICY" >/dev/null
    echo "Created role $role_name." >&2
  else
    echo "Error: could not probe role '$role_name': $probe_err" >&2
    return 1
  fi

  aws iam put-role-policy \
    --role-name "$role_name" \
    --policy-name "$policy_name" \
    --policy-document "$policy_doc" >/dev/null
  echo "Attached inline policy $policy_name to $role_name." >&2

  aws iam get-role --role-name "$role_name" --query 'Role.Arn' --output text
}

CUSTODIAN_ARN=$(build_custodian_policy | create_role_with_policy \
  "${PREFIX}CustodianRole" "KeyCustodian" "NitroTPM key custodian: creates and finalizes the KMS key")
PROVISIONER_ARN=$(build_provisioner_policy | create_role_with_policy \
  "${PREFIX}ProvisionerRole" "SecretsProvisioner" "NitroTPM secrets/PKI provisioner: wraps the DEK and issues certs")
DEPLOYER_ARN=$(build_deployer_policy | create_role_with_policy \
  "${PREFIX}DeployerRole" "ReleaseEngineer" "NitroTPM deployer: builds, signs and registers the AMI")
OPERATOR_ARN=$(build_operator_policy "$ACCOUNT_ID" "$INSTANCE_ROLE_NAME" "$INSTANCE_PROFILE_NAME" \
  | create_role_with_policy \
  "${PREFIX}OperatorRole" "PlatformOperator" "NitroTPM platform operator: infrastructure and teardown, blind to the data")
TEST_CLIENT_ARN=$(build_test_client_policy "$ACCOUNT_ID" | create_role_with_policy \
  "${PREFIX}TestClientRole" "TestClient" "NitroTPM test client: reads the client cert bundle only")

echo "CUSTODIAN_ROLE_ARN: $CUSTODIAN_ARN"
echo "PROVISIONER_ROLE_ARN: $PROVISIONER_ARN"
echo "DEPLOYER_ROLE_ARN: $DEPLOYER_ARN"
echo "OPERATOR_ROLE_ARN: $OPERATOR_ARN"
echo "TEST_CLIENT_ROLE_ARN: $TEST_CLIENT_ARN"
