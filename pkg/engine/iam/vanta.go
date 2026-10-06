package iam

import (
	"errors"
	"fmt"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// VantaSpec describes the auditor role a Vanta integration asks every account
// to carry.
type VantaSpec struct {
	// Partition is the ARN partition. Required.
	Partition string
	// TrustedAccountID is the vendor's AWS account that assumes the role.
	// Required.
	TrustedAccountID string
	// ExternalID is the external id of the trust relationship, the same in
	// every account of the organization. Required.
	ExternalID string
	// RoleName is the IAM role name the vendor expects. Required.
	RoleName string
	// PolicyName is the customer-managed policy name (the vendor's
	// additional-permissions policy). Required.
	PolicyName string
	// BoundaryName is the name of the permissions boundary policy that bounds
	// the role in each account. Required.
	BoundaryName string
}

// Validate reports every problem with v at once, or returns nil.
func (v *VantaSpec) Validate() error {
	var errs []error

	for name, val := range map[string]string{
		"Partition": v.Partition, "TrustedAccountID": v.TrustedAccountID, "ExternalID": v.ExternalID,
		"RoleName": v.RoleName, "PolicyName": v.PolicyName, "BoundaryName": v.BoundaryName,
	} {
		if val == "" {
			errs = append(errs, fmt.Errorf("vanta: %s is empty", name))
		}
	}

	return errors.Join(errs...)
}

// VantaAuditorRole is the auditor role of an account: SecurityAudit plus the
// additional-permissions policy, trusted by the vendor's account with the
// organization's external id, bounded by the account's own boundary policy.
func VantaAuditorRole(v VantaSpec, accountID pulumi.StringInput) (*AuditorRole, error) {
	if err := v.Validate(); err != nil {
		return nil, err
	}

	return &AuditorRole{
		Name:             v.RoleName,
		TrustedPrincipal: fmt.Sprintf("arn:%s:iam::%s:root", v.Partition, v.TrustedAccountID),
		ExternalID:       v.ExternalID,
		ManagedPolicies:  []string{fmt.Sprintf("arn:%s:iam::aws:policy/SecurityAudit", v.Partition)},
		Policy: &Policy{
			Name:     v.PolicyName,
			Document: VantaAdditionalPermissions,
		},
		PermissionsBoundary: pulumi.Sprintf("arn:%s:iam::%s:policy/%s", v.Partition, accountID, v.BoundaryName),
	}, nil
}

// VantaAdditionalPermissions supplements SecurityAudit with identitystore read
// access and codecommit read access, while denying datapipeline and RDS log
// download.
const VantaAdditionalPermissions = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "codecommit:GetApprovalRuleTemplate",
        "codecommit:GetCommentsForPullRequest",
        "codecommit:GetPullRequest",
        "codecommit:GetPullRequestApprovalStates",
        "codecommit:ListPullRequests",
        "identitystore:DescribeGroup",
        "identitystore:DescribeGroupMembership",
        "identitystore:DescribeUser",
        "identitystore:GetGroupId",
        "identitystore:GetGroupMembershipId",
        "identitystore:GetUserId",
        "identitystore:IsMemberInGroups",
        "identitystore:ListGroupMemberships",
        "identitystore:ListGroupMembershipsForMember",
        "identitystore:ListGroups",
        "identitystore:ListUsers"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Deny",
      "Action": [
        "datapipeline:EvaluateExpression",
        "datapipeline:QueryObjects",
        "rds:DownloadDBLogFilePortion"
      ],
      "Resource": "*"
    }
  ]
}`
