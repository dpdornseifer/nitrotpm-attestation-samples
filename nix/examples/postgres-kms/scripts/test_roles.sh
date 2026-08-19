#!/bin/bash
#
# AWS-free unit tests for the role-separation machinery: credential scoping,
# the two-statement bootstrap policy, the signing-identity resource policy,
# the five provisioning-role policies, and structural assertions that each
# ceremony stage adopts exactly its own role.
#
# Pure bash + jq. No AWS calls, no network, no fixtures.

set -u

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/roles.sh
. "$SCRIPT_DIR/lib/roles.sh"

GREEN="\033[32m"
RED="\033[31m"
RESET="\033[0m"

PASS_COUNT=0
FAIL_COUNT=0

pass() { PASS_COUNT=$((PASS_COUNT + 1)); printf "${GREEN}PASS${RESET} %s\n" "$1"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); printf "${RED}FAIL${RESET} %s\n" "$1"; }

assert_eq() {
  local name=$1 want=$2 got=$3
  if [ "$want" = "$got" ]; then
    pass "$name"
  else
    fail "$name -- want '$want', got '$got'"
  fi
}

# --- assume_role_exec: passthrough ------------------------------------------
# An empty role ARN must run the command with ambient credentials and must not
# emit anything of its own on stdout: eight call sites parse step-script stdout
# with grep -oP, so one stray line breaks the parse silently.

OUT=$(assume_role_exec "" -- printf 'hello')
assert_eq "passthrough runs the command" "hello" "$OUT"

OUT=$(assume_role_exec "" -- true)
assert_eq "passthrough emits nothing extra on stdout" "" "$OUT"

OUT=$(assume_role_exec "" -- printf 'a\nb')
assert_eq "passthrough does not mangle multiline stdout" "a
b" "$OUT"

assume_role_exec "" -- false
assert_eq "passthrough propagates a non-zero exit status" "1" "$?"

assume_role_exec "" -- true
assert_eq "passthrough propagates a zero exit status" "0" "$?"

# The `--` separator is conventional but optional; both forms must work.
OUT=$(assume_role_exec "" printf 'nodash')
assert_eq "passthrough works without the -- separator" "nodash" "$OUT"

# --- build_bootstrap_policy -------------------------------------------------
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/kms.sh
. "$SCRIPT_DIR/lib/kms.sh"

CUSTODIAN="arn:aws:iam::123456789012:role/NitroTpmCustodianRole"
PROVISIONER="arn:aws:iam::123456789012:role/NitroTpmProvisionerRole"

# Zero-config equivalence: with no provisioner the document must stay exactly the
# single-statement policy shipped before the split, so the default path is
# provably unchanged.
SINGLE=$(build_bootstrap_policy "$CUSTODIAN")
assert_eq "single-identity policy has one statement" "1" \
  "$(printf '%s' "$SINGLE" | jq '.Statement | length')"
assert_eq "single-identity policy keeps all five actions" \
  "kms:Encrypt kms:ListGrants kms:PutKeyPolicy kms:RevokeGrant kms:ScheduleKeyDeletion" \
  "$(printf '%s' "$SINGLE" | jq -r '[.Statement[0].Action[]] | sort | join(" ")')"
assert_eq "single-identity policy names the custodian" "$CUSTODIAN" \
  "$(printf '%s' "$SINGLE" | jq -r '.Statement[0].Principal.AWS')"
assert_eq "single-identity policy effect is Allow" "Allow" \
  "$(printf '%s' "$SINGLE" | jq -r '.Statement[0].Effect')"
assert_eq "single-identity policy resource is wildcard" "*" \
  "$(printf '%s' "$SINGLE" | jq -r '.Statement[0].Resource')"
assert_eq "single-identity policy declares the 2012-10-17 version" "2012-10-17" \
  "$(printf '%s' "$SINGLE" | jq -r '.Version')"

SAME=$(build_bootstrap_policy "$CUSTODIAN" "$CUSTODIAN")
assert_eq "identical principals collapse to the single-statement policy" \
  "$(printf '%s' "$SINGLE" | jq -S .)" "$(printf '%s' "$SAME" | jq -S .)"

# Split path: no single party may hold both PutKeyPolicy (grant-plant) and
# Encrypt (DEK substitution).
SPLIT=$(build_bootstrap_policy "$CUSTODIAN" "$PROVISIONER")
assert_eq "split policy has two statements" "2" \
  "$(printf '%s' "$SPLIT" | jq '.Statement | length')"
assert_eq "custodian statement holds PutKeyPolicy" "true" \
  "$(printf '%s' "$SPLIT" | jq --arg p "$CUSTODIAN" \
     '[.Statement[] | select(.Principal.AWS == $p) | .Action] | flatten | index("kms:PutKeyPolicy") != null')"
assert_eq "custodian statement does NOT hold Encrypt" "true" \
  "$(printf '%s' "$SPLIT" | jq --arg p "$CUSTODIAN" \
     '[.Statement[] | select(.Principal.AWS == $p) | .Action] | flatten | index("kms:Encrypt") == null')"
assert_eq "provisioner statement holds Encrypt" "true" \
  "$(printf '%s' "$SPLIT" | jq --arg p "$PROVISIONER" \
     '[.Statement[] | select(.Principal.AWS == $p) | .Action] | flatten | index("kms:Encrypt") != null')"
assert_eq "provisioner statement does NOT hold PutKeyPolicy" "true" \
  "$(printf '%s' "$SPLIT" | jq --arg p "$PROVISIONER" \
     '[.Statement[] | select(.Principal.AWS == $p) | .Action] | flatten | index("kms:PutKeyPolicy") == null')"
assert_eq "split policy grants Decrypt to nobody" "true" \
  "$(printf '%s' "$SPLIT" | jq '[.Statement[].Action] | flatten | index("kms:Decrypt") == null')"

# Source assertion: 02a must call the shared builder, not carry its own heredoc,
# or the tested document and the shipped document can drift.
if grep -q 'build_bootstrap_policy' "$SCRIPT_DIR/steps/02a_create_kms_key.sh"; then
  pass "source: 02a uses build_bootstrap_policy"
else
  fail "source: 02a must call build_bootstrap_policy from lib/kms.sh"
fi
if grep -q '"kms:PutKeyPolicy"' "$SCRIPT_DIR/steps/02a_create_kms_key.sh"; then
  fail "source: 02a still contains an inline policy heredoc"
else
  pass "source: 02a no longer inlines the policy document"
fi

# --- kms_policy_faults ------------------------------------------------------
# 02b reads the key policy back after put-key-policy. It must accept KMS's own
# re-serialization of the document it was sent and reject any document that
# actually widens access, since the finalize ratchet is irreversible.

INSTANCE_ROLE_T="arn:aws:iam::123456789012:role/NitroTpmInstanceRole"
PCR4_T="aa$(printf '4%.0s' {1..94})"
PCR7_T="bb$(printf '7%.0s' {1..94})"
PCRS_T=$(jq -nc --arg p4 "$PCR4_T" --arg p7 "$PCR7_T" \
  '{"kms:RecipientAttestation:NitroTPMPCR4": $p4, "kms:RecipientAttestation:NitroTPMPCR7": $p7}')

# The document as KMS returns it: 02b sends a bare "Principal": "*" on the Deny,
# and KMS hands it back as {"AWS": "*"}. Diffing the two reported that as compromise.
INSTALLED_T=$(jq -nc --arg admin "$CUSTODIAN" --arg role "$INSTANCE_ROLE_T" --argjson pcrs "$PCRS_T" '{
  Version: "2012-10-17",
  Statement: [
    { Sid: "admin", Effect: "Allow", Principal: {AWS: $admin},
      Action: ["kms:ScheduleKeyDeletion","kms:ListGrants","kms:RevokeGrant","kms:GetKeyPolicy"],
      Resource: "*" },
    { Sid: "decrypt", Effect: "Allow", Principal: {AWS: $role},
      Action: ["kms:Decrypt"], Resource: "*",
      Condition: {StringEqualsIgnoreCase: $pcrs} },
    { Sid: "nogrants", Effect: "Deny", Principal: {AWS: "*"},
      Action: "kms:CreateGrant", Resource: "*" }
  ]}')

assert_policy_ok() {
  local name=$1 policy=$2 faults
  faults=$(kms_policy_faults "$policy" "$INSTANCE_ROLE_T" "$PCRS_T")
  if [ -z "$faults" ]; then pass "$name"; else fail "$name -- expected no faults, got: $faults"; fi
}

assert_policy_fault() {
  local name=$1 policy=$2 faults
  faults=$(kms_policy_faults "$policy" "$INSTANCE_ROLE_T" "$PCRS_T")
  if [ -n "$faults" ]; then pass "$name"; else fail "$name -- expected a fault, got none"; fi
}

# The round trip that failed in production: the document 02b sends must satisfy the check
# 02b runs on it, both verbatim and after KMS expands the bare Deny principal.
SENT_T=$(build_final_policy "$CUSTODIAN" "$INSTANCE_ROLE_T" "$PCRS_T")
assert_policy_ok "policy: the document build_final_policy sends passes its own check" "$SENT_T"
assert_policy_ok "policy: the sent document still passes once KMS expands Principal \"*\"" \
  "$(printf '%s' "$SENT_T" | jq -c '.Statement[2].Principal = {AWS: "*"}')"
assert_eq "policy: the final document gates Decrypt on exactly the measured PCRs" \
  "$(printf '%s' "$PCRS_T" | jq -S .)" \
  "$(printf '%s' "$SENT_T" | jq -S '.Statement[] | select(.Sid | test("decryption")) | .Condition.StringEqualsIgnoreCase')"

assert_policy_ok "policy: accepts the document KMS returns" "$INSTALLED_T"
assert_policy_ok "policy: accepts a bare \"Principal\": \"*\" on the Deny" \
  "$(printf '%s' "$INSTALLED_T" | jq -c '.Statement[2].Principal = "*"')"
assert_policy_ok "policy: accepts pretty-printed, reordered keys" \
  "$(printf '%s' "$INSTALLED_T" | jq -S .)"
assert_policy_ok "policy: accepts a scalar Action in place of a one-item array" \
  "$(printf '%s' "$INSTALLED_T" | jq -c '.Statement[1].Action = "kms:Decrypt"')"
assert_policy_ok "policy: accepts a one-item Principal.AWS array" \
  "$(printf '%s' "$INSTALLED_T" | jq -c '.Statement[1].Principal.AWS = [.Statement[1].Principal.AWS]')"
assert_policy_ok "policy: accepts CreateGrant denied via a kms:* Deny" \
  "$(printf '%s' "$INSTALLED_T" | jq -c '.Statement[2].Action = "kms:*"')"

assert_policy_fault "policy: rejects Decrypt handed to another principal" \
  "$(printf '%s' "$INSTALLED_T" | jq -c '.Statement[1].Principal.AWS = "arn:aws:iam::999999999999:role/Attacker"')"
assert_policy_fault "policy: rejects a second principal on the Decrypt statement" \
  "$(printf '%s' "$INSTALLED_T" | jq -c '.Statement[1].Principal.AWS = [.Statement[1].Principal.AWS, "arn:aws:iam::999999999999:role/Attacker"]')"
assert_policy_fault "policy: rejects a second statement granting Decrypt" \
  "$(printf '%s' "$INSTALLED_T" | jq -c '.Statement += [{Effect: "Allow", Principal: {AWS: "arn:aws:iam::999999999999:role/Attacker"}, Action: ["kms:Decrypt"], Resource: "*"}]')"
assert_policy_fault "policy: rejects an altered PCR value" \
  "$(printf '%s' "$INSTALLED_T" | jq -c '.Statement[1].Condition.StringEqualsIgnoreCase["kms:RecipientAttestation:NitroTPMPCR4"] = "deadbeef"')"
assert_policy_fault "policy: rejects a dropped PCR" \
  "$(printf '%s' "$INSTALLED_T" | jq -c 'del(.Statement[1].Condition.StringEqualsIgnoreCase["kms:RecipientAttestation:NitroTPMPCR7"])')"
assert_policy_fault "policy: rejects an extra PCR nobody measured" \
  "$(printf '%s' "$INSTALLED_T" | jq -c '.Statement[1].Condition.StringEqualsIgnoreCase["kms:RecipientAttestation:NitroTPMPCR0"] = "00"')"
assert_policy_fault "policy: rejects Decrypt with no Condition at all" \
  "$(printf '%s' "$INSTALLED_T" | jq -c 'del(.Statement[1].Condition)')"
assert_policy_fault "policy: rejects a condition moved to a weaker operator" \
  "$(printf '%s' "$INSTALLED_T" | jq -c '.Statement[1].Condition = {StringLike: .Statement[1].Condition.StringEqualsIgnoreCase}')"
assert_policy_fault "policy: rejects a re-added Allow of kms:PutKeyPolicy" \
  "$(printf '%s' "$INSTALLED_T" | jq -c '.Statement[0].Action += ["kms:PutKeyPolicy"]')"
assert_policy_fault "policy: rejects a re-added Allow of kms:Encrypt" \
  "$(printf '%s' "$INSTALLED_T" | jq -c '.Statement[0].Action += ["kms:Encrypt"]')"
assert_policy_fault "policy: rejects an Allow of kms:*" \
  "$(printf '%s' "$INSTALLED_T" | jq -c '.Statement[0].Action = ["kms:*"]')"
assert_policy_fault "policy: rejects a removed CreateGrant Deny" \
  "$(printf '%s' "$INSTALLED_T" | jq -c 'del(.Statement[2])')"
assert_policy_fault "policy: rejects a CreateGrant Deny narrowed to one principal" \
  "$(printf '%s' "$INSTALLED_T" | jq -c '.Statement[2].Principal.AWS = $ENV.CUSTODIAN' --arg CUSTODIAN "$CUSTODIAN")"
assert_policy_fault "policy: rejects a wholly unrelated policy" \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"kms:*","Resource":"*"}]}'

# Source assertion: 02b must verify through the shared function, not a document diff.
if grep -q 'kms_policy_faults' "$SCRIPT_DIR/steps/02b_finalize_kms_policy.sh"; then
  pass "source: 02b verifies the installed policy via kms_policy_faults"
else
  fail "source: 02b must call kms_policy_faults from lib/kms.sh"
fi
if grep -qE 'diff <\(jq -S \. "\$KEY_POLICY_FILE"\)' "$SCRIPT_DIR/steps/02b_finalize_kms_policy.sh"; then
  fail "source: 02b still diffs the policy document against the one sent"
else
  pass "source: 02b no longer diffs the policy document"
fi

# --- build_identity_resource_policy -----------------------------------------
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/identity.sh
. "$SCRIPT_DIR/lib/identity.sh"

DEPLOYER="arn:aws:iam::123456789012:role/NitroTpmDeployerRole"
RP=$(build_identity_resource_policy "$DEPLOYER")

# Deny, not Allow: Secrets Manager allows if either the identity or the resource
# policy allows, so an Allow-only policy grants nothing exclusive.
assert_eq "resource policy uses Deny" "Deny" \
  "$(printf '%s' "$RP" | jq -r '.Statement[0].Effect')"
assert_eq "resource policy applies to every principal" "*" \
  "$(printf '%s' "$RP" | jq -r '.Statement[0].Principal')"

# Scoped to GetSecretValue only: a blanket secretsmanager:* Deny would also block
# DeleteSecret and break clean.sh teardown (clean.sh:58-61 deletes this secret).
assert_eq "resource policy denies GetSecretValue only" "secretsmanager:GetSecretValue" \
  "$(printf '%s' "$RP" | jq -r '.Statement[0].Action')"
assert_eq "resource policy does not use a wildcard action" "true" \
  "$(printf '%s' "$RP" | jq '[.Statement[].Action] | flatten | any(. == "secretsmanager:*") | not')"

# ArnNotEquals per AWS guidance for ARN comparison; aws:PrincipalArn evaluates to
# the IAM role ARN, never the assumed-role session ARN.
assert_eq "resource policy carves out the deployer with ArnNotEquals" "$DEPLOYER" \
  "$(printf '%s' "$RP" | jq -r '.Statement[0].Condition.ArnNotEquals["aws:PrincipalArn"]')"
assert_eq "resource policy does not use StringNotEquals" "true" \
  "$(printf '%s' "$RP" | jq '.Statement[0].Condition.StringNotEquals == null')"
assert_eq "resource policy carve-out is not a session ARN" "true" \
  "$(printf '%s' "$RP" | jq -r '.Statement[0].Condition.ArnNotEquals["aws:PrincipalArn"] | startswith("arn:aws:iam::")')"

# Zero-config: no deployer means no meaningful lockdown, so warn on stderr and
# succeed rather than failing the run or attaching a policy that denies everyone.
WARN=$(lock_secret_to_deployer "arn:aws:secretsmanager:us-east-1:123456789012:secret:x" "" 2>&1 >/dev/null); RC=$?
assert_eq "lock_secret_to_deployer succeeds with no deployer ARN" "0" "$RC"
case "$WARN" in
  *"readable by any principal"*) pass "lock_secret_to_deployer warns when unlocked" ;;
  *) fail "lock_secret_to_deployer must warn on stderr when no deployer ARN is given, got: $WARN" ;;
esac

# --- role policies ----------------------------------------------------------
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/role-policies.sh
. "$SCRIPT_DIR/lib/role-policies.sh"

ACCT="123456789012"
OP=$(build_operator_policy "$ACCT" "TpmAttestationRole" "TpmAttestationProfile")
CUST=$(build_custodian_policy)
DEPL=$(build_deployer_policy)
PROV=$(build_provisioner_policy)
CLIENT=$(build_test_client_policy "$ACCT")

# Helper: does any statement grant <action>?
grants() {
  printf '%s' "$1" | jq --arg a "$2" '[.Statement[].Action] | flatten | index($a) != null'
}
# Helper: does any statement pair <action> with Resource "*"?
grants_on_star() {
  printf '%s' "$1" | jq --arg a "$2" \
    '[.Statement[] | select(([.Action] | flatten | index($a)) != null)
      | (if (.Resource | type) == "array" then .Resource else [.Resource] end)]
     | flatten | index("*") != null'
}

# The escalation guard: CreateRole/PassRole must never be unscoped.
assert_eq "operator iam:PassRole is resource-scoped" "false" "$(grants_on_star "$OP" "iam:PassRole")"
assert_eq "operator iam:CreateRole is resource-scoped" "false" "$(grants_on_star "$OP" "iam:CreateRole")"
assert_eq "operator iam:AttachRolePolicy is resource-scoped" "false" "$(grants_on_star "$OP" "iam:AttachRolePolicy")"
assert_eq "operator iam:AddRoleToInstanceProfile is resource-scoped" "false" \
  "$(grants_on_star "$OP" "iam:AddRoleToInstanceProfile")"

# Operator must be blind to the data.
assert_eq "operator has no kms:Decrypt" "false" "$(grants "$OP" "kms:Decrypt")"
assert_eq "operator has no kms:Encrypt" "false" "$(grants "$OP" "kms:Encrypt")"
assert_eq "operator has no kms:PutKeyPolicy" "false" "$(grants "$OP" "kms:PutKeyPolicy")"
assert_eq "operator cannot read any secret" "false" "$(grants "$OP" "secretsmanager:GetSecretValue")"
# clean.sh:85 deletes AMI backing snapshots; the documented monolith omitted this.
assert_eq "operator can delete AMI snapshots" "true" "$(grants "$OP" "ec2:DeleteSnapshot")"

# Custodian controls policy, never ciphertext.
assert_eq "custodian has no kms:Encrypt" "false" "$(grants "$CUST" "kms:Encrypt")"
assert_eq "custodian has no kms:Decrypt" "false" "$(grants "$CUST" "kms:Decrypt")"
assert_eq "custodian holds kms:PutKeyPolicy" "true" "$(grants "$CUST" "kms:PutKeyPolicy")"
# normalize_admin_principal runs inside the assumed session.
assert_eq "custodian holds iam:GetRole" "true" "$(grants "$CUST" "iam:GetRole")"

# Deployer controls the measurements, never the policy or the secrets.
assert_eq "deployer has no kms:PutKeyPolicy" "false" "$(grants "$DEPL" "kms:PutKeyPolicy")"
assert_eq "deployer has no kms:Encrypt" "false" "$(grants "$DEPL" "kms:Encrypt")"
assert_eq "deployer holds ec2:RegisterImage" "true" "$(grants "$DEPL" "ec2:RegisterImage")"
# Needed to attach and verify the signing-identity resource policy (Task 3).
assert_eq "deployer holds secretsmanager:PutResourcePolicy" "true" \
  "$(grants "$DEPL" "secretsmanager:PutResourcePolicy")"
assert_eq "deployer holds secretsmanager:GetResourcePolicy" "true" \
  "$(grants "$DEPL" "secretsmanager:GetResourcePolicy")"

# Provisioner mints ciphertext, never rewrites policy.
assert_eq "provisioner holds kms:Encrypt" "true" "$(grants "$PROV" "kms:Encrypt")"
assert_eq "provisioner has no kms:PutKeyPolicy" "false" "$(grants "$PROV" "kms:PutKeyPolicy")"
assert_eq "provisioner has no kms:Decrypt" "false" "$(grants "$PROV" "kms:Decrypt")"

# Test Client reads only the client bundle — never the signing identity.
assert_eq "test client holds GetSecretValue" "true" "$(grants "$CLIENT" "secretsmanager:GetSecretValue")"
assert_eq "test client GetSecretValue is resource-scoped" "false" \
  "$(grants_on_star "$CLIENT" "secretsmanager:GetSecretValue")"
assert_eq "test client is scoped to the client-cert secret" "true" \
  "$(printf '%s' "$CLIENT" | jq '[.Statement[].Resource] | flatten | all(contains("client-cert"))')"
assert_eq "test client has no KMS access" "false" "$(grants "$CLIENT" "kms:Decrypt")"

# iam:PutRolePolicy is dead since 0307043 and must not reappear anywhere.
for POLICY_NAME in OP CUST DEPL PROV CLIENT; do
  assert_eq "no iam:PutRolePolicy in $POLICY_NAME" "false" "$(grants "${!POLICY_NAME}" "iam:PutRolePolicy")"
done

# Every policy must be valid JSON with a Version and at least one statement.
for POLICY_NAME in OP CUST DEPL PROV CLIENT; do
  assert_eq "$POLICY_NAME is well-formed" "2012-10-17" \
    "$(printf '%s' "${!POLICY_NAME}" | jq -r '.Version')"
done

# --- 00_create_roles.sh structure -------------------------------------------
CREATE_ROLES="$SCRIPT_DIR/steps/00_create_roles.sh"

if [ -x "$CREATE_ROLES" ]; then
  pass "source: 00_create_roles.sh exists and is executable"
else
  fail "source: 00_create_roles.sh must exist and be executable"
fi

# It must use the shared builders, not carry its own policy JSON, or the tested
# documents and the shipped documents drift.
if grep -q 'build_operator_policy' "$CREATE_ROLES" 2>/dev/null; then
  pass "source: 00_create_roles.sh uses the shared policy builders"
else
  fail "source: 00_create_roles.sh must call build_operator_policy from lib/role-policies.sh"
fi
# This checks for inline PERMISSION policy documents only. The trust policy
# (sts:AssumeRole) is a different IAM artifact with no shared builder; it is
# legitimately constructed via jq -n in the script. Do not convert it back
# to a heredoc — doing so would re-introduce the literal this check catches.
if grep -q '"Version": "2012-10-17"' "$CREATE_ROLES" 2>/dev/null; then
  fail "source: 00_create_roles.sh inlines a policy document instead of using the builders"
else
  pass "source: 00_create_roles.sh inlines no policy documents"
fi

# Every ARN the orchestrator parses must actually be emitted on stdout.
for EMIT in CUSTODIAN_ROLE_ARN PROVISIONER_ROLE_ARN DEPLOYER_ROLE_ARN OPERATOR_ROLE_ARN TEST_CLIENT_ROLE_ARN; do
  if grep -q "$EMIT:" "$CREATE_ROLES" 2>/dev/null; then
    pass "source: 00_create_roles.sh emits $EMIT"
  else
    fail "source: 00_create_roles.sh must emit '$EMIT: <arn>' on stdout"
  fi
done

# clean.sh must route only ScheduleKeyDeletion through the Custodian.
CLEAN="$SCRIPT_DIR/clean.sh"
if grep -q 'custodian-role-arn' "$CLEAN"; then
  pass "source: clean.sh accepts --custodian-role-arn"
else
  fail "source: clean.sh must accept --custodian-role-arn"
fi
# shellcheck disable=SC2016  # single quotes are intentional: we grep for the literal string in clean.sh
if grep -q 'assume_role_exec "$CUSTODIAN_ROLE_ARN" -- aws kms schedule-key-deletion' "$CLEAN"; then
  pass "source: clean.sh schedules key deletion as the custodian"
else
  fail "source: clean.sh must run schedule-key-deletion via assume_role_exec with the custodian ARN"
fi

# --- resolve_aws_credentials -------------------------------------------------
# shellcheck source=lib/aws-creds.sh
. "$SCRIPT_DIR/lib/aws-creds.sh"

# Already-set variables must be left exactly as they are and must not invoke the
# AWS CLI at all: stub `aws` to prove no fallback lookup happens.
aws() { echo "STUB-CALLED"; }

(
  export AWS_ACCESS_KEY_ID="AKIAEXAMPLE"
  export AWS_SECRET_ACCESS_KEY="secret"
  export AWS_DEFAULT_REGION="us-east-2"
  OUT=$(resolve_aws_credentials 2>&1) || exit 3
  case "$OUT" in
    *STUB-CALLED*) exit 3 ;;
    *) exit 0 ;;
  esac
)
assert_eq "resolve_aws_credentials does not shell out when all vars are set" "0" "$?"

(
  export AWS_ACCESS_KEY_ID="AKIAEXAMPLE"
  export AWS_SECRET_ACCESS_KEY="secret"
  export AWS_DEFAULT_REGION="us-east-2"
  resolve_aws_credentials >/dev/null 2>&1 || exit 3
  [ "$AWS_DEFAULT_REGION" = "us-east-2" ]
)
assert_eq "resolve_aws_credentials preserves an already-set region" "0" "$?"

# A variable that is neither in the environment nor resolvable must fail loudly,
# not silently proceed to an AWS call that errors cryptically later.
(
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION
  aws() { return 1; }
  resolve_aws_credentials >/dev/null 2>&1
)
assert_eq "resolve_aws_credentials fails when a required var is unresolvable" "1" "$?"

(
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION
  aws() { return 1; }
  ERR=$(resolve_aws_credentials 2>&1 >/dev/null)
  case "$ERR" in
    *AWS_ACCESS_KEY_ID*) exit 0 ;;
    *) exit 3 ;;
  esac
)
assert_eq "resolve_aws_credentials names the missing variable" "0" "$?"

# The fallback must read from `aws configure get` and export the result.
(
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION AWS_SESSION_TOKEN
  aws() {
    case "$3" in
      aws_access_key_id) echo "AKIAFROMCONFIG" ;;
      aws_secret_access_key) echo "secretfromconfig" ;;
      region) echo "eu-west-1" ;;
      *) return 1 ;;
    esac
  }
  resolve_aws_credentials >/dev/null 2>&1 || exit 3
  [ "$AWS_ACCESS_KEY_ID" = "AKIAFROMCONFIG" ] && [ "$AWS_DEFAULT_REGION" = "eu-west-1" ]
)
assert_eq "resolve_aws_credentials exports values from aws configure" "0" "$?"

unset -f aws

# --- stage scripts: each adopts exactly its own role ------------------------
# A stage naming another role's flag means the ceremony's boundaries are wrong in
# a way no runtime test would catch — the run would simply succeed with too much
# privilege.

assert_stage_role() {
  local stage=$1 want_flag=$2 path="$SCRIPT_DIR/$1"
  local other found=0 bad=""

  if [ ! -x "$path" ]; then
    fail "stage $stage exists and is executable"
    return
  fi
  pass "stage $stage exists and is executable"

  if grep -q -- "$want_flag" "$path"; then
    pass "stage $stage accepts $want_flag"
  else
    fail "stage $stage must accept $want_flag"
  fi

  for other in --operator-role-arn --custodian-role-arn --deployer-role-arn --provisioner-role-arn; do
    [ "$other" = "$want_flag" ] && continue
    # create-key.sh must name the Provisioner: it writes the two-statement policy.
    [ "$stage" = "create-key.sh" ] && [ "$other" = "--provisioner-role-arn" ] && continue
    # prepare-role.sh names the next stage's flag in its "Next:" hint — documentation, not adoption.
    [ "$stage" = "prepare-role.sh" ] && [ "$other" = "--provisioner-role-arn" ] && continue
    if grep -q -- "$other" "$path"; then
      bad="$bad $other"
      found=1
    fi
  done
  if [ "$found" -eq 0 ]; then
    pass "stage $stage names no other role's flag"
  else
    fail "stage $stage must not reference:$bad"
  fi

  if grep -q 'assume_role_exec' "$path"; then
    pass "stage $stage runs its work through assume_role_exec"
  else
    fail "stage $stage must run its AWS work through assume_role_exec"
  fi

  if grep -q 'resolve_aws_credentials' "$path"; then
    pass "stage $stage resolves credentials"
  else
    fail "stage $stage must call resolve_aws_credentials"
  fi
}

assert_stage_role "prepare-role.sh" "--operator-role-arn"
assert_stage_role "create-key.sh" "--custodian-role-arn"

# create-key.sh is the one stage that names a second role: the bootstrap policy
# must grant Encrypt to the Provisioner even though the Custodian installs it.
if grep -q -- '--provisioner-role-arn' "$SCRIPT_DIR/create-key.sh"; then
  pass "create-key.sh accepts --provisioner-role-arn for the bootstrap policy"
else
  fail "create-key.sh must accept --provisioner-role-arn"
fi

assert_stage_role "build.sh" "--deployer-role-arn"

BUILD="$SCRIPT_DIR/build.sh"
# The Deployer must both write and track the pin, and must fail closed: an untracked
# file is invisible to the flake, which would silently build an unpinned image.
if grep -q 'git -C "\$PROJECT_DIR" add' "$BUILD" 2>/dev/null; then
  pass "build.sh git-adds the pinned ARN file"
else
  fail "build.sh must git add the pinned ARN file"
fi
if grep -q 'ls-files --error-unmatch' "$BUILD" 2>/dev/null; then
  pass "build.sh verifies the pin is tracked"
else
  fail "build.sh must verify the pin is tracked and fail closed"
fi

# 02a must no longer touch the ARN file: the CLI value is the single source of truth.
A2="$SCRIPT_DIR/steps/02a_create_kms_key.sh"
if grep -q 'kms-key-arn.txt' "$A2"; then
  fail "02a must no longer write or reference kms-key-arn.txt (build.sh owns the pin)"
else
  pass "source: 02a no longer owns the pinned ARN file"
fi
if grep -q 'ls-files --error-unmatch' "$A2"; then
  fail "02a must no longer carry the git-tracking guard"
else
  pass "source: 02a no longer carries the git-tracking guard"
fi

assert_stage_role "provision-secrets.sh" "--provisioner-role-arn"

PROV_STAGE="$SCRIPT_DIR/provision-secrets.sh"
# The plaintext DEK must not survive an abort. An explicit rm on the happy path is
# not enough: a set -e abort or a signal between mktemp and that rm leaves the key
# on disk (the e2e-test.sh:339-356 defect this stage replaces).
if grep -qE "trap .*(EXIT|INT|TERM)" "$PROV_STAGE" 2>/dev/null; then
  pass "provision-secrets.sh traps EXIT to destroy the plaintext DEK"
else
  fail "provision-secrets.sh must trap EXIT to remove the plaintext DEK tmpdir"
fi
if grep -q 'chmod 700' "$PROV_STAGE" 2>/dev/null; then
  pass "provision-secrets.sh restricts the DEK tmpdir to 0700"
else
  fail "provision-secrets.sh must chmod 700 the DEK tmpdir"
fi
# Both DEK consumers must be in this stage, or the plaintext would cross a boundary.
for STEP in 03_create_symmetric_key.sh 05a_create_certificates.sh; do
  if grep -q "$STEP" "$PROV_STAGE" 2>/dev/null; then
    pass "provision-secrets.sh runs $STEP"
  else
    fail "provision-secrets.sh must run $STEP so the plaintext DEK never leaves the stage"
  fi
done

assert_stage_role "finalize-key.sh" "--custodian-role-arn"
assert_stage_role "deploy.sh" "--operator-role-arn"

FIN="$SCRIPT_DIR/finalize-key.sh"
# Finalize must require the PCRs: silently finalizing without them would install a
# policy gated on nothing, which is strictly weaker and would look like success.
for REQ in --instance-role-arn --pcr-dir; do
  if grep -q -- "$REQ" "$FIN" 2>/dev/null; then
    pass "finalize-key.sh accepts $REQ"
  else
    fail "finalize-key.sh must accept $REQ"
  fi
done
if grep -q 'is required' "$FIN" 2>/dev/null; then
  pass "finalize-key.sh rejects a missing required argument"
else
  fail "finalize-key.sh must fail closed on a missing required argument"
fi

DEP="$SCRIPT_DIR/deploy.sh"
# Ported from the former postgres-kms start.sh (deleted in the six-stage refactor) —
# without these the operator has no idea how to reach the database they just launched.
if grep -q 'print_sg_authorization_notice' "$DEP" 2>/dev/null; then
  pass "deploy.sh prints the SG authorization notice"
else
  fail "deploy.sh must print the SG authorization notice"
fi
if grep -q 'sslmode=verify-ca\|connect over mTLS' "$DEP" 2>/dev/null; then
  pass "deploy.sh prints the mTLS connect hint"
else
  fail "deploy.sh must print the mTLS connect hint"
fi
# The Operator must never see plaintext or bundles — only the ciphertext user-data.
if grep -q 'symmetric-key\|plaintext-key-out\|05a_create_certificates' "$DEP" 2>/dev/null; then
  fail "deploy.sh must not touch the DEK or the certificate bundles"
else
  pass "deploy.sh touches no key material"
fi

# --- e2e-test.sh drives stages, not steps -----------------------------------
E2E="$SCRIPT_DIR/e2e-test.sh"

for STAGE in prepare-role.sh create-key.sh build.sh provision-secrets.sh finalize-key.sh deploy.sh; do
  if grep -q "/$STAGE" "$E2E"; then
    pass "e2e-test.sh drives $STAGE"
  else
    fail "e2e-test.sh must drive $STAGE"
  fi
done

# Driving a step directly would mean two orchestration paths over the same work.
for STEP in 02a_create_kms_key.sh 00_create_ami.sh 01_create_instance_profile.sh \
            03_create_symmetric_key.sh 02b_finalize_kms_policy.sh \
            05a_create_certificates.sh 04_create_ebs_volume.sh; do
  if grep -q "steps/$STEP" "$E2E"; then
    fail "e2e-test.sh must not call steps/$STEP directly; the stage owns it"
  else
    pass "e2e-test.sh no longer calls steps/$STEP directly"
  fi
done

# 05_run_instance.sh is the documented exception: phase 3's relaunch goes through
# run_instance_step, because calling deploy.sh would create a second EBS volume and
# defeat the persistence test.
if grep -q 'run_instance_step' "$E2E"; then
  pass "e2e-test.sh reuses run_instance_step for the phase 3 relaunch"
else
  fail "e2e-test.sh must reuse run_instance_step for the phase 3 relaunch"
fi

for FLAG in --custodian-role-arn --provisioner-role-arn --deployer-role-arn \
            --operator-role-arn --test-client-role-arn --create-roles; do
  if grep -q -- "$FLAG" "$E2E"; then
    pass "e2e-test.sh accepts $FLAG"
  else
    fail "e2e-test.sh must accept $FLAG"
  fi
done

# The Custodian ARN must be persisted, or clean.sh cannot schedule key deletion
# under the right role after a --no-cleanup resume.
if grep -q 'update_resource "CUSTODIAN_ROLE_ARN"' "$E2E"; then
  pass "e2e-test.sh persists the custodian ARN for clean.sh"
else
  fail "e2e-test.sh must persist CUSTODIAN_ROLE_ARN into resources.json"
fi

# --- start.sh is gone and nothing points at it ------------------------------
if [ -e "$SCRIPT_DIR/start.sh" ]; then
  fail "start.sh must be deleted; the six stages replace it"
else
  pass "start.sh is deleted"
fi

# A user-visible error naming a deleted script sends them down a dead end.
for F in "$SCRIPT_DIR/steps/00_create_ami.sh" "$SCRIPT_DIR/lib/identity.sh" \
         "$SCRIPT_DIR/clean.sh" "$SCRIPT_DIR/e2e-test.sh"; do
  if grep -q 'start\.sh' "$F" 2>/dev/null; then
    fail "$(basename "$F") still references start.sh"
  else
    pass "$(basename "$F") does not reference start.sh"
  fi
done

# Every ported capability must have landed somewhere before start.sh is removed.
if grep -q 'resolve_aws_credentials' "$SCRIPT_DIR/lib/aws-creds.sh" 2>/dev/null; then
  pass "ported: credential fallback lives in lib/aws-creds.sh"
else
  fail "ported: credential fallback is missing"
fi
if grep -q 'retained' "$SCRIPT_DIR/build.sh" 2>/dev/null; then
  pass "ported: retained-identity reuse lives in build.sh"
else
  fail "ported: retained-identity reuse is missing from build.sh"
fi
if grep -q 'NOT reproducible' "$SCRIPT_DIR/build.sh" 2>/dev/null; then
  pass "ported: the non-reproducibility banner lives in build.sh"
else
  fail "ported: the non-reproducibility banner is missing from build.sh"
fi
if grep -q 'Deployment summary' "$SCRIPT_DIR/deploy.sh" 2>/dev/null; then
  pass "ported: the deployment summary lives in deploy.sh"
else
  fail "ported: the deployment summary is missing from deploy.sh"
fi

printf '\n%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[ "$FAIL_COUNT" -eq 0 ] || exit 1
