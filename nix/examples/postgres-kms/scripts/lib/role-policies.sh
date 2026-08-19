#!/bin/bash
#
# Minimal IAM policy documents for the five provisioning roles, derived by
# partitioning README's "Minimal IAM Privileges" monolith along stage ownership.
#
# This file is the single source of truth for those policies; the README carries
# the single-identity/zero-config policy and links here for the per-role split.
#
# Three deliberate deviations from the README monolith:
#   1. iam:PutRolePolicy is dropped — dead since 0307043.
#   2. The Operator's IAM actions are resource-scoped. CreateRole + PassRole +
#      RunInstances in one policy is an escalation chain (create a role with any
#      permissions, pass it to an instance you launch), and all three land on the
#      Operator, so the IAM half is pinned to the instance role and profile.
#   3. ec2:DeleteSnapshot is added — clean.sh:85 needs it and the monolith omits it.

# Args: <account_id> <instance_role_name> <instance_profile_name>.
build_operator_policy() {
  local acct="$1" role_name="$2" profile_name="$3"
  cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EC2InstanceManagement",
      "Effect": "Allow",
      "Action": [
        "ec2:RunInstances",
        "ec2:DescribeInstances",
        "ec2:TerminateInstances",
        "ec2:CreateSecurityGroup",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:DeleteSecurityGroup",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeAvailabilityZones",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeImages"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EBSVolumeManagement",
      "Effect": "Allow",
      "Action": [
        "ec2:CreateVolume",
        "ec2:DeleteVolume",
        "ec2:AttachVolume",
        "ec2:DescribeVolumes",
        "ec2:CreateTags"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TeardownImageAndSnapshots",
      "Effect": "Allow",
      "Action": [
        "ec2:DeregisterImage",
        "ec2:DescribeSnapshots",
        "ec2:DeleteSnapshot"
      ],
      "Resource": "*"
    },
    {
      "Sid": "InstanceRoleLifecycleScopedToTheWorkloadRoleOnly",
      "Effect": "Allow",
      "Action": [
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:GetRole",
        "iam:PassRole",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:DeleteRolePolicy"
      ],
      "Resource": "arn:aws:iam::${acct}:role/${role_name}"
    },
    {
      "Sid": "InstanceProfileLifecycleScoped",
      "Effect": "Allow",
      "Action": [
        "iam:CreateInstanceProfile",
        "iam:DeleteInstanceProfile",
        "iam:GetInstanceProfile",
        "iam:AddRoleToInstanceProfile",
        "iam:RemoveRoleFromInstanceProfile"
      ],
      "Resource": "arn:aws:iam::${acct}:instance-profile/${profile_name}"
    },
    {
      "Sid": "TeardownSecrets",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:DeleteSecret"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SSMDebugAccess",
      "Effect": "Allow",
      "Action": [
        "ssm:DescribeInstanceInformation",
        "ssm:SendCommand",
        "ssm:GetCommandInvocation",
        "ssm:StartSession"
      ],
      "Resource": "*"
    },
    {
      "Sid": "STSIdentity",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

# The key ARN does not exist when this role is created, so KMS actions cannot be
# resource-scoped here; the key policy is the binding control.
build_custodian_policy() {
  cat <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "KeyLifecycleAndPolicyControl",
      "Effect": "Allow",
      "Action": [
        "kms:CreateKey",
        "kms:PutKeyPolicy",
        "kms:ScheduleKeyDeletion",
        "kms:ListGrants",
        "kms:RevokeGrant",
        "kms:GetKeyPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ResolveAssumedRoleSessionToRoleArn",
      "Effect": "Allow",
      "Action": [
        "iam:GetRole"
      ],
      "Resource": "*"
    },
    {
      "Sid": "STSIdentity",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

build_deployer_policy() {
  cat <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AMIRegistration",
      "Effect": "Allow",
      "Action": [
        "ec2:RegisterImage",
        "ec2:DescribeImages"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SnapshotColdsnap",
      "Effect": "Allow",
      "Action": [
        "ebs:StartSnapshot",
        "ebs:PutSnapshotBlock",
        "ebs:CompleteSnapshot",
        "ec2:DescribeSnapshots",
        "ec2:CreateTags"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SigningIdentityCustody",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:CreateSecret",
        "secretsmanager:GetSecretValue",
        "secretsmanager:PutResourcePolicy",
        "secretsmanager:GetResourcePolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "STSIdentity",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

build_provisioner_policy() {
  cat <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "WrapTheDekDuringTheBootstrapWindow",
      "Effect": "Allow",
      "Action": [
        "kms:Encrypt"
      ],
      "Resource": "*"
    },
    {
      "Sid": "UploadTheClientCertificateBundle",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:CreateSecret"
      ],
      "Resource": "*"
    },
    {
      "Sid": "STSIdentity",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

# Scoped to the client-cert secret name pattern written by 05a:115 so this role
# cannot read the signing identity (named nitrotpm-sb-identity-*).
# Args: <account_id>.
build_test_client_policy() {
  local acct="$1"
  cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadTheClientCertificateBundleOnly",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:*:${acct}:secret:postgres-kms/client-cert-*"
    }
  ]
}
EOF
}
