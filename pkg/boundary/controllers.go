package boundary

import (
	"fmt"

	"github.com/truvity/aws-structure/policy"
)

// The ACK controllers' own roles. With IAMRoleSelector a controller calls
// sts:AssumeRole on the builder of a namespace's project and then acts as the
// builder, so what a controller's own role needs is small: the platform's
// own resources (Spec.ACK) and the assumption of the builders. These
// boundaries are allowlists: anything not named is denied.

const (
	sidAssumeBuilders = "AllowAssumeProjectBuilders"

	// ackNamespaceTag is the tag ACK puts on every resource it creates, naming
	// the namespace of the custom resource.
	ackNamespaceTag = "services.k8s.aws/namespace"
)

func (s *Spec) roleARN(pattern string) string {
	return fmt.Sprintf("arn:%s:iam::*:role/%s", s.Partition, pattern)
}

// slugRoles returns the ARN patterns "*-<slug>-*" of the roles named by slugs.
func (s *Spec) slugRoles(slugs ...[]string) []string {
	var out []string

	for _, group := range slugs {
		for _, slug := range group {
			out = append(out, s.roleARN("*-"+slug+"-*"))
		}
	}

	return out
}

// assumeBuilders lets a controller's own role assume the builders.
func (s *Spec) assumeBuilders() policy.Statement {
	var roles []string
	for _, p := range s.ACK.BuilderRoles {
		roles = append(roles, s.roleARN(p))
	}

	return policy.Statement{
		Sid: sidAssumeBuilders, Effect: allow, Action: []string{"sts:AssumeRole", "sts:TagSession"},
		Resource: roles,
	}
}

func (s *Spec) controller(name string, stmts ...policy.Statement) (string, error) {
	stmts = append(stmts, s.assumeBuilders(), s.denyBoundaryEdit(), noBoundaryDelete())

	return marshal(name, stmts)
}

// controllerIAM is the IAM controller's own role: it creates and manages the
// roles named by ACK.IAMRoleSlugs that carry ACK's namespace tag ACK.IAMNamespace
// (inline policies only, no managed policies, no PassRole, no users), and only
// under the boundaries it delegates.
func (s *Spec) controllerIAM() (string, error) {
	roles := s.slugRoles(s.ACK.IAMRoleSlugs)
	ownedRequest := cond(condStringEquals, "aws:RequestTag/"+ackNamespaceTag, s.ACK.IAMNamespace)
	owned := cond(condStringEquals, "aws:ResourceTag/"+ackNamespaceTag, s.ACK.IAMNamespace)
	bounded := cond("ArnLike", condPermissionsBoundary, s.DelegateARNs(s.Names.ACKControllerIAM)...)

	return s.controller(s.Names.ACKControllerIAM,
		policy.Statement{Sid: "AllowIAMRead", Effect: allow, Action: []string{"iam:Get*", "iam:List*"}, Resource: star()},
		policy.Statement{
			Sid: "AllowCreateManagedRole", Effect: allow, Action: []string{actionCreateRole}, Resource: roles,
			Condition: []policy.Condition{bounded, ownedRequest},
		},
		policy.Statement{
			Sid: "AllowSetBoundaryOnManagedRole", Effect: allow, Action: []string{actionPutRoleBoundary}, Resource: roles,
			Condition: []policy.Condition{bounded, owned},
		},
		policy.Statement{
			Sid: "AllowManageManagedRole", Effect: allow,
			Action: []string{
				"iam:UpdateRole", "iam:UpdateRoleDescription", "iam:UpdateAssumeRolePolicy", "iam:DeleteRole",
				"iam:TagRole", "iam:UntagRole", "iam:PutRolePolicy", "iam:DeleteRolePolicy",
			},
			Resource: roles, Condition: []policy.Condition{owned},
		},
	)
}

// controllerEKS is the EKS controller's own role: Pod Identity associations,
// iam:PassRole for the platform roles it binds (ACK.IAMRoleSlugs and
// ACK.PodIdentityRoleSlugs) only, and two reads. The pass list is the control
// that matters: EKS checks that the caller may pass the role it binds.
//
// iam:PassedToService is StringEqualsIfExists: whether EKS fills the key for
// CreatePodIdentityAssociation is not verified offline, and a missing key
// must not break reconciliation.
func (s *Spec) controllerEKS() (string, error) {
	return s.controller(s.Names.ACKControllerEKS,
		s.podIdentityStatement("*", "*"),
		policy.Statement{
			Sid: "AllowPassPlatformRoles", Effect: allow, Action: []string{"iam:PassRole"},
			Resource:  s.slugRoles(s.ACK.IAMRoleSlugs, s.ACK.PodIdentityRoleSlugs),
			Condition: []policy.Condition{passedToPods()},
		},
		policy.Statement{
			Sid: "AllowRoleRead", Effect: allow, Action: []string{"iam:GetRole", "iam:ListAttachedRolePolicies"},
			Resource: []string{s.roleARN("*")},
		},
	)
}

func passedToPods() policy.Condition {
	return cond("StringEqualsIfExists", "iam:PassedToService", "pods.eks.amazonaws.com")
}

// podIdentityStatement allows the Pod Identity association calls on the
// cluster and its associations; cluster is a cluster name or a policy
// variable.
func (s *Spec) podIdentityStatement(cluster, associations string) policy.Statement {
	return policy.Statement{
		Sid: "AllowPodIdentityAssociations", Effect: allow,
		Action: []string{
			"eks:CreatePodIdentityAssociation", "eks:DeletePodIdentityAssociation",
			"eks:DescribePodIdentityAssociation", "eks:UpdatePodIdentityAssociation",
			"eks:ListPodIdentityAssociations", "eks:TagResource", "eks:UntagResource",
		},
		Resource: []string{
			fmt.Sprintf("arn:%s:eks:*:*:cluster/%s", s.Partition, cluster),
			fmt.Sprintf("arn:%s:eks:*:*:podidentityassociation/%s/%s", s.Partition, cluster, associations),
		},
	}
}

// controllerS3 is the S3 controller's own role: s3:* on exactly the bucket
// ARNs ACK.Buckets (the buckets, not their objects) and the bucket list.
func (s *Spec) controllerS3() (string, error) {
	var buckets []string
	for _, b := range s.ACK.Buckets {
		buckets = append(buckets, fmt.Sprintf("arn:%s:s3:::%s", s.Partition, b))
	}

	return s.controller(s.Names.ACKControllerS3,
		policy.Statement{Sid: "AllowOwnBuckets", Effect: allow, Action: []string{"s3:*"}, Resource: buckets},
		policy.Statement{Sid: "AllowBucketList", Effect: allow, Action: []string{"s3:ListAllMyBuckets"}, Resource: star()},
	)
}

// controllerKMS is the KMS controller's own role: reads only. The controller
// acts for projects as their builders.
func (s *Spec) controllerKMS() (string, error) {
	return s.controller(s.Names.ACKControllerKMS,
		policy.Statement{
			Sid: "AllowKeyRead", Effect: allow, Action: []string{"kms:Describe*", "kms:Get*", "kms:List*"},
			Resource: star(),
		},
	)
}

// controllerDynamoDB is the DynamoDB controller's own role: reads only.
func (s *Spec) controllerDynamoDB() (string, error) {
	return s.controller(s.Names.ACKControllerDynamoDB,
		policy.Statement{
			Sid: "AllowTableRead", Effect: allow, Action: []string{"dynamodb:Describe*", "dynamodb:List*"},
			Resource: star(),
		},
	)
}
