package boundary

import (
	"fmt"
	"sort"
)

// OrgAdminMode selects the variant of the admin boundary for the one
// permission-set family an organization uses everywhere (one admin set, whose
// customer-managed boundary is resolved BY NAME in each account, so the policy
// of that name may differ per account).
type OrgAdminMode string

const (
	// OrgAdminOff is the admin boundary as it has always been, byte for byte.
	// It is the zero value.
	OrgAdminOff OrgAdminMode = ""

	// OrgAdminMember is the admin boundary of a member account when the admin
	// permission set also carries the organization-admin inline policy (see
	// pkg/engine/sso.OrgAdminInlinePolicy). It adds a deny of the
	// organization-administration actions (organizations, account, sso,
	// sso-directory, identitystore), so that in a member account the set's
	// effective permissions stay what they were before the inline policy.
	// The reads the AWS-managed PowerUserAccess policy grants are carved out
	// of the deny; see OrgAdminReadCarveOuts.
	OrgAdminMember OrgAdminMode = "member"

	// OrgAdminManagement is the admin boundary of the management account: it
	// explicitly allows the organization-administration actions and the
	// management of the boundary policies of that account, and does not deny
	// editing them. The management account's admin is the owner of the
	// organization, so the boundary self-edit deny does not apply there. This
	// makes the admin set in the management account equivalent to a full
	// administrator, by design: whoever holds it can rewrite the boundary that
	// bounds it. The rest of the admin deny list stays (roles of SSO and
	// service-linked roles, roles and users created without a delegated
	// boundary, removal of a boundary, the destructive list, deleting a
	// state bucket).
	OrgAdminManagement OrgAdminMode = "management"
)

// orgAdminActions are the action patterns of organization administration.
// pkg/engine/sso.OrgAdminActions is the same list for the identity side.
var orgAdminActions = []string{
	"organizations:*", "account:*", "sso:*", "sso-directory:*", "identitystore:*",
}

// OrgAdminReadCarveOuts are the actions the member deny leaves out because the
// AWS-managed PowerUserAccess policy grants them today (its second statement,
// next to iam:CreateServiceLinkedRole, iam:DeleteServiceLinkedRole and
// iam:ListRoles), so that an admin in a member account keeps them.
func OrgAdminReadCarveOuts() []string {
	return []string{
		"account:GetAccountInformation",
		"account:ListRegions",
		"organizations:DescribeOrganization",
	}
}

func (s *Spec) allowOrgAdmin() statement {
	return statement{
		Sid: "AllowOrganizationAdmin", Effect: allow,
		Action: append([]string(nil), orgAdminActions...), Resource: "*",
	}
}

// allowBoundaryEdit names the edit actions of the account's own boundary
// policies. AllowAll already covers them; the statement states the intent.
func (s *Spec) allowBoundaryEdit() statement {
	return statement{
		Sid: "AllowBoundaryPolicyEdit", Effect: allow,
		Action: []string{
			"iam:CreatePolicy",
			"iam:CreatePolicyVersion",
			"iam:DeletePolicy",
			"iam:DeletePolicyVersion",
			"iam:SetDefaultPolicyVersion",
		},
		Resource: []string{s.arn(s.Prefix + "*")},
	}
}

// IAM has no way to deny "a service except these actions": a Deny with
// NotAction denies every other service too, and a Deny cannot be undone by an
// Allow. The member deny is therefore a list of patterns that covers a
// service's actions and leaves out the carve-outs. It is built from the verbs
// AWS names its actions with. An action AWS adds later is denied when it
// begins with a verb listed here, and not otherwise.
var (
	organizationsVerbs = []string{
		"Accept", "Attach", "Cancel", "Close", "Create", "Decline", "Delete", "Deregister", "Detach",
		"Disable", "Enable", "Invite", "Leave", "List", "Move", "Put", "Register", "Remove", "Tag",
		"Untag", "Update",
	}
	accountVerbs = []string{
		"Accept", "Close", "Create", "Delete", "Disable", "Enable", "Put", "Start", "Update",
	}
)

const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// except returns prefix+letter+"*" for every capital letter not in keep.
func except(prefix, keep string) []string {
	var out []string

	for _, c := range upper {
		if !containsRune(keep, c) {
			out = append(out, fmt.Sprintf("%s%c*", prefix, c))
		}
	}

	return out
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}

	return false
}

// memberOrgDeny returns the patterns the member deny lists.
func memberOrgDeny() []string {
	var out []string

	for _, v := range organizationsVerbs {
		out = append(out, "organizations:"+v+"*")
	}

	// organizations:Describe*, except DescribeOrganization (but its longer
	// sibling DescribeOrganizationalUnit is denied).
	out = append(out, except("organizations:Describe", "O")...)
	out = append(out, "organizations:DescribeOrganization?*")

	for _, v := range accountVerbs {
		out = append(out, "account:"+v+"*")
	}

	// account:Get*, except GetAccountInformation.
	out = append(out, except("account:Get", "A")...)
	out = append(out, "account:GetAlternateContact", "account:GetAccountInformation?*")

	// account:List*, except ListRegions.
	out = append(out, except("account:List", "R")...)
	out = append(out, "account:ListRegions?*")

	out = append(out, "sso:*", "sso-directory:*", "identitystore:*")

	sort.Strings(out)

	return out
}

func denyOrgAdmin() statement {
	return statement{Sid: "DenyOrganizationAdmin", Effect: deny, Action: memberOrgDeny(), Resource: "*"}
}
