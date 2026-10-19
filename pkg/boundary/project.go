package boundary

import "fmt"

// The project boundaries. A project's infrastructure is created by its
// builder role (ProjectACK; EmployeeACK for an employee sandbox), which every
// ACK controller assumes for the project's namespaces, and the roles the
// builder creates for the project's pods carry ProjectWorkload.
//
// One document serves every account and project: both read the principal's
// own role tags, project and cluster (${aws:PrincipalTag/...}). The tags are
// the anchor. A builder may create and tag its own roles; if it could re-tag
// one with another project, that role would reach the other project's data,
// so the builder boundaries deny setting "project" or "cluster" to a value
// other than the builder's own, and removing either.
//
// Naming, final form: roles and policies "<cluster>-<project>.<name>"
// (IAM allows "." in these names, so a project "x" never reaches "x-y");
// buckets "<ProjectBucketPrefix><cluster>-<project>-<name>"; KMS aliases
// "alias/<cluster>-<project>-<name>" (aliases and buckets cannot hold "."; no
// project name may be a hyphen-prefix of another); ECR repositories
// "<project>/...". The transition form (Spec.LegacyProjectNames) also accepts
// "<cluster>-*<project>-*" for roles and policies and
// "<prefix><cluster>-*<project>-*" for buckets.

const (
	tagProject = "${aws:PrincipalTag/project}"
	tagCluster = "${aws:PrincipalTag/cluster}"
)

// projectRoles returns the role ARN patterns a builder may name.
func (s *Spec) projectRoles(legacy bool) []string {
	out := []string{s.roleARN(tagCluster + "-" + tagProject + ".*")}
	if legacy {
		out = append(out, s.roleARN(tagCluster+"-*"+tagProject+"-*"))
	}

	return out
}

// projectPolicies returns the managed policy ARN patterns a builder may name.
func (s *Spec) projectPolicies(legacy bool) []string {
	out := []string{fmt.Sprintf("arn:%s:iam::*:policy/%s-%s.*", s.Partition, tagCluster, tagProject)}
	if legacy {
		out = append(out, fmt.Sprintf("arn:%s:iam::*:policy/%s-*%s-*", s.Partition, tagCluster, tagProject))
	}

	return out
}

// projectBuckets returns the bucket ARN patterns of the project, or of its
// objects. The legacy pattern subsumes the canonical one.
func (s *Spec) projectBuckets(legacy, objects bool) []string {
	suffix := ""
	if objects {
		suffix = "/*"
	}

	if legacy {
		return []string{fmt.Sprintf("arn:%s:s3:::%s%s-*%s-*%s", s.Partition, s.ProjectBucketPrefix, tagCluster, tagProject, suffix)}
	}

	return []string{fmt.Sprintf("arn:%s:s3:::%s%s-%s-*%s", s.Partition, s.ProjectBucketPrefix, tagCluster, tagProject, suffix)}
}

func ownProject() map[string]any {
	return map[string]any{condStringEquals: map[string]any{"aws:ResourceTag/project": tagProject}}
}

// withCond returns base plus the entries of extra, a new map.
func withCond(base map[string]any, extra map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}

	for k, v := range extra {
		out[k] = v
	}

	return out
}

func (s *Spec) projectACK() (string, error) {
	return s.builder(s.Names.ProjectACK, s.LegacyProjectNames)
}

// employeeACK is the project builder for an employee sandbox: the same
// document under its own name, in the final form only (a sandbox has no
// legacy names). Its project tag is the sandbox's own ("emp-<name>" or
// whatever the caller chooses), so a sandbox reaches nothing of any project
// and no project reaches the sandbox. Having its own name lets the caller
// grant, delegate and tighten it separately from the project builders.
func (s *Spec) employeeACK() (string, error) {
	return s.builder(s.Names.EmployeeACK, false)
}

// builder is the document of a builder role. See the package comment above for
// what it allows; what it does not: object-level S3, SSM, DynamoDB, SQS, users,
// instance profiles, OIDC providers, key policies and grants, and retiring a
// key. DynamoDB and SQS are left out because no project uses them yet (add a
// reviewed statement with the first user), and the policy size limit is 6,144
// characters.
func (s *Spec) builder(name string, legacy bool) (string, error) {
	roles := s.projectRoles(legacy)
	workload := map[string]any{"ArnLike": map[string]any{condPermissionsBoundary: oneOrMany(s.DelegateARNs(name))}}
	own := ownProject()

	stmts := []statement{
		{Sid: "AllowIAMRead", Effect: allow, Action: []string{"iam:Get*", "iam:List*"}, Resource: "*"},
		{
			Sid: "AllowCreateWorkloadRole", Effect: allow, Action: actionCreateRole, Resource: roles,
			Condition: withCond(workload, map[string]any{condStringEquals: map[string]any{
				"aws:RequestTag/project": tagProject, "aws:RequestTag/cluster": tagCluster,
			}}),
		},
		{
			Sid: "AllowSetWorkloadBoundary", Effect: allow, Action: actionPutRoleBoundary, Resource: roles,
			Condition: withCond(workload, own),
		},
		{
			Sid: "AllowManageOwnRole", Effect: allow,
			Action: []string{
				"iam:UpdateRole", "iam:UpdateRoleDescription", "iam:UpdateAssumeRolePolicy", "iam:DeleteRole",
				"iam:TagRole", "iam:UntagRole", "iam:PutRolePolicy", "iam:DeleteRolePolicy",
			},
			Resource: roles, Condition: own,
		},
		{
			Sid: "AllowAttachOwnPolicy", Effect: allow, Action: []string{"iam:AttachRolePolicy", "iam:DetachRolePolicy"},
			Resource: roles,
			Condition: withCond(own, map[string]any{
				"ArnLike": map[string]any{"iam:PolicyARN": s.projectPolicies(legacy)},
			}),
		},
		{
			Sid: "AllowManageOwnPolicy", Effect: allow,
			Action: []string{
				"iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:DeletePolicy", "iam:DeletePolicyVersion",
				"iam:SetDefaultPolicyVersion", "iam:TagPolicy", "iam:UntagPolicy",
			},
			Resource: s.projectPolicies(legacy),
		},
		{
			Sid: "AllowPassOwnRoleToPodIdentity", Effect: allow, Action: "iam:PassRole", Resource: roles,
			Condition: passedToPods(),
		},
		s.podIdentityStatement(tagCluster, "*"),
		{
			Sid: "AllowOwnBucketAdmin", Effect: allow,
			Action: []string{
				"s3:CreateBucket", "s3:ListBucket", "s3:GetBucket*", "s3:PutBucket*", "s3:DeleteBucket*",
				"s3:Get*Configuration", "s3:Put*Configuration",
			},
			Resource: s.projectBuckets(legacy, false),
		},
		{Sid: "AllowBucketList", Effect: allow, Action: "s3:ListAllMyBuckets", Resource: "*"},
		{
			// A key has no tag before it exists, so creation is conditioned on the
			// request tag. CreateKey with Tags is also authorized as
			// kms:TagResource on that key, so it is allowed here too, under the
			// same request tag and only where the key carries no project tag (a
			// key of another project is never retagged). A deny on untagged keys
			// is not possible here: AWS authorizes that TagResource against the
			// new, still untagged key. Keeping an untagged key from being
			// claimed is the account owner's rule: every customer-managed key
			// carries a project tag.
			Sid: "AllowCreateKey", Effect: allow, Action: []string{"kms:CreateKey", "kms:TagResource"}, Resource: "*",
			Condition: map[string]any{
				condStringEquals: map[string]any{"aws:RequestTag/project": tagProject},
				"Null":           map[string]any{"aws:ResourceTag/project": "true"},
			},
		},
		{
			Sid: "AllowManageOwnKey", Effect: allow,
			Action: []string{
				"kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:ListResourceTags",
				"kms:ListKeyPolicies", "kms:TagResource", "kms:UntagResource", "kms:UpdateKeyDescription",
				"kms:EnableKey", "kms:EnableKeyRotation", "kms:DisableKeyRotation", "kms:CreateAlias",
				"kms:UpdateAlias", "kms:DeleteAlias",
			},
			Resource: "*", Condition: own,
		},
		{
			Sid: "AllowOwnAlias", Effect: allow, Action: []string{"kms:CreateAlias", "kms:UpdateAlias", "kms:DeleteAlias"},
			Resource: fmt.Sprintf("arn:%s:kms:*:*:alias/%s-%s-*", s.Partition, tagCluster, tagProject),
		},
		{Sid: "AllowKeyList", Effect: allow, Action: []string{"kms:ListAliases", "kms:ListKeys"}, Resource: "*"},

		// Guards. The Denies on create and tag compare values (setting the
		// builder's own value is fine); the Deny on untag forbids removing either key.
		{
			Sid: "DenyRetagProjectOrCluster", Effect: deny, Action: []string{"iam:TagRole", actionCreateRole},
			Resource: "*",
			Condition: map[string]any{
				"Null":            map[string]any{"aws:RequestTag/project": "false"},
				"StringNotEquals": map[string]any{"aws:RequestTag/project": tagProject},
			},
		},
		{
			Sid: "DenyRetagClusterTag", Effect: deny, Action: []string{"iam:TagRole", actionCreateRole},
			Resource: "*",
			Condition: map[string]any{
				"Null":            map[string]any{"aws:RequestTag/cluster": "false"},
				"StringNotEquals": map[string]any{"aws:RequestTag/cluster": tagCluster},
			},
		},
		{
			Sid: "DenyUntagProjectOrCluster", Effect: deny, Action: "iam:UntagRole", Resource: "*",
			Condition: map[string]any{"ForAnyValue:StringEquals": map[string]any{"aws:TagKeys": []string{"project", "cluster"}}},
		},
		{
			Sid: "DenyKeyRetirement", Effect: deny, Action: []string{"kms:ScheduleKeyDeletion", "kms:DisableKey"},
			Resource: "*",
		},
	}

	if legacy {
		// A legacy pattern "<cluster>-*<project>-*" also fits the roles and
		// policies the platform mints under a project's name.
		var minted []string

		for _, slug := range s.ACK.IAMRoleSlugs {
			minted = append(minted, s.roleARN(tagCluster+"-"+slug+"-*"),
				fmt.Sprintf("arn:%s:iam::*:policy/%s-%s-*", s.Partition, tagCluster, slug))
		}

		stmts = append(stmts, statement{Sid: "DenyPlatformMintedRoles", Effect: deny, Action: "iam:*", Resource: minted})
	}

	stmts = append(stmts, s.denyBoundaryEdit(), noBoundaryDelete())

	return marshal(name, document{Version: policyVersion, Statement: stmts})
}

// projectWorkload is the boundary of the roles a builder creates for a
// project's pods: data actions on the project's own keys (by tag), buckets (by
// name prefix) and ECR repositories (by name), and no IAM at all, so the
// delegation chain ends here. SSM, Secrets Manager, DynamoDB and SQS are not in
// it.
func (s *Spec) projectWorkload() (string, error) {
	legacy := s.LegacyProjectNames

	return marshal(s.Names.ProjectWorkload, document{Version: policyVersion, Statement: []statement{
		{
			Sid: "AllowKMSUseOwnProjectKeys", Effect: allow,
			Action: []string{
				"kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey",
				"kms:GenerateDataKeyWithoutPlaintext", "kms:GenerateDataKeyPair",
				"kms:GenerateDataKeyPairWithoutPlaintext", "kms:DescribeKey", "kms:Sign", "kms:Verify",
				"kms:GetPublicKey",
			},
			Resource: "*", Condition: ownProject(),
		},
		{Sid: "AllowKMSRandom", Effect: allow, Action: "kms:GenerateRandom", Resource: "*"},
		{
			Sid: "AllowS3Objects", Effect: allow,
			Action: []string{
				"s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectTagging", "s3:PutObject", "s3:PutObjectTagging",
				"s3:DeleteObject", "s3:DeleteObjectVersion", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts",
			},
			Resource: s.projectBuckets(legacy, true),
		},
		{
			Sid: "AllowS3List", Effect: allow,
			Action:   []string{"s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:GetBucketLocation"},
			Resource: s.projectBuckets(legacy, false),
		},
		{
			Sid: "AllowECRPullOwnRepos", Effect: allow,
			Action:   []string{"ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"},
			Resource: fmt.Sprintf("arn:%s:ecr:*:*:repository/%s/*", s.Partition, tagProject),
		},
		{Sid: "AllowECRToken", Effect: allow, Action: "ecr:GetAuthorizationToken", Resource: "*"},
		{Sid: "DenyIAM", Effect: deny, Action: "iam:*", Resource: "*"},
	}})
}
