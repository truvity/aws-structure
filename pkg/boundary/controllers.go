package boundary

import "fmt"

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

// oneOrMany renders a one-element list as the bare value, as IAM documents
// are usually written.
func oneOrMany(v []string) any {
	if len(v) == 1 {
		return v[0]
	}

	return v
}

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
func (s *Spec) assumeBuilders() statement {
	var roles []string
	for _, p := range s.ACK.BuilderRoles {
		roles = append(roles, s.roleARN(p))
	}

	return statement{
		Sid: sidAssumeBuilders, Effect: allow, Action: []string{"sts:AssumeRole", "sts:TagSession"},
		Resource: oneOrMany(roles),
	}
}

func (s *Spec) controller(name string, stmts ...statement) (string, error) {
	stmts = append(stmts, s.assumeBuilders(), s.denyBoundaryEdit(), noBoundaryDelete())

	return marshal(name, document{Version: policyVersion, Statement: stmts})
}

// controllerIAM is the IAM controller's own role: it creates and manages the
// roles named by ACK.IAMRoleSlugs that carry ACK's namespace tag ACK.IAMNamespace
// (inline policies only, no managed policies, no PassRole, no users), and only
// under the boundaries it delegates.
func (s *Spec) controllerIAM() (string, error) {
	roles := oneOrMany(s.slugRoles(s.ACK.IAMRoleSlugs))
	ownedRequest := map[string]any{condStringEquals: map[string]any{"aws:RequestTag/" + ackNamespaceTag: s.ACK.IAMNamespace}}
	owned := map[string]any{condStringEquals: map[string]any{"aws:ResourceTag/" + ackNamespaceTag: s.ACK.IAMNamespace}}
	bounded := oneOrMany(s.DelegateARNs(s.Names.ACKControllerIAM))

	withBoundary := func(c map[string]any) map[string]any {
		out := map[string]any{"ArnLike": map[string]any{condPermissionsBoundary: bounded}}
		for k, v := range c {
			out[k] = v
		}

		return out
	}

	return s.controller(s.Names.ACKControllerIAM,
		statement{Sid: "AllowIAMRead", Effect: allow, Action: []string{"iam:Get*", "iam:List*"}, Resource: "*"},
		statement{
			Sid: "AllowCreateManagedRole", Effect: allow, Action: actionCreateRole, Resource: roles,
			Condition: withBoundary(ownedRequest),
		},
		statement{
			Sid: "AllowSetBoundaryOnManagedRole", Effect: allow, Action: actionPutRoleBoundary, Resource: roles,
			Condition: withBoundary(owned),
		},
		statement{
			Sid: "AllowManageManagedRole", Effect: allow,
			Action: []string{
				"iam:UpdateRole", "iam:UpdateRoleDescription", "iam:UpdateAssumeRolePolicy", "iam:DeleteRole",
				"iam:TagRole", "iam:UntagRole", "iam:PutRolePolicy", "iam:DeleteRolePolicy",
			},
			Resource: roles, Condition: owned,
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
		statement{
			Sid: "AllowPassPlatformRoles", Effect: allow, Action: "iam:PassRole",
			Resource:  oneOrMany(s.slugRoles(s.ACK.IAMRoleSlugs, s.ACK.PodIdentityRoleSlugs)),
			Condition: passedToPods(),
		},
		statement{
			Sid: "AllowRoleRead", Effect: allow, Action: []string{"iam:GetRole", "iam:ListAttachedRolePolicies"},
			Resource: s.roleARN("*"),
		},
	)
}

func passedToPods() map[string]any {
	return map[string]any{"StringEqualsIfExists": map[string]any{"iam:PassedToService": "pods.eks.amazonaws.com"}}
}

// podIdentityStatement allows the Pod Identity association calls on the
// cluster and its associations; cluster is a cluster name or a policy
// variable.
func (s *Spec) podIdentityStatement(cluster, associations string) statement {
	return statement{
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
		statement{Sid: "AllowOwnBuckets", Effect: allow, Action: "s3:*", Resource: oneOrMany(buckets)},
		statement{Sid: "AllowBucketList", Effect: allow, Action: "s3:ListAllMyBuckets", Resource: "*"},
	)
}

// controllerKMS is the KMS controller's own role: reads only. The controller
// acts for projects as their builders.
func (s *Spec) controllerKMS() (string, error) {
	return s.controller(s.Names.ACKControllerKMS,
		statement{
			Sid: "AllowKeyRead", Effect: allow, Action: []string{"kms:Describe*", "kms:Get*", "kms:List*"},
			Resource: "*",
		},
	)
}

// controllerDynamoDB is the DynamoDB controller's own role: reads only.
func (s *Spec) controllerDynamoDB() (string, error) {
	return s.controller(s.Names.ACKControllerDynamoDB,
		statement{
			Sid: "AllowTableRead", Effect: allow, Action: []string{"dynamodb:Describe*", "dynamodb:List*"},
			Resource: "*",
		},
	)
}
