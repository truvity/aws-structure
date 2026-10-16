package registry

// Registry is the whole file. The zero value is not valid; load one with
// Parse or Load and call Validate (Parse does).
type Registry struct {
	// Organization is the organization the rest of the file describes. In
	// v1 it is looked up, never managed.
	Organization Organization `yaml:"organization"`

	// OUs are the organizational units, a tree by Parent.
	OUs []OU `yaml:"ous"`

	// Accounts are the member accounts. Every account sits in one OU.
	Accounts []Account `yaml:"accounts"`

	// SCPEnforcement says whether service control policies are attached.
	// v1 accepts only "dormant" (the default): the policies are declared
	// and validated but never attached. See docs/decisions/0002-safety.md.
	SCPEnforcement string `yaml:"scp_enforcement"`

	// SCPs are the service control policies, by name.
	SCPs []SCP `yaml:"scps"`

	// IdentityCenter is the workforce access layer.
	IdentityCenter IdentityCenter `yaml:"identity_center"`

	// Baseline is what every account carries unless it opts out.
	Baseline Baseline `yaml:"baseline"`

	// Waivers are the exceptions a guard of pkg/preflight accepts, each
	// with the reason it exists and the condition that ends it.
	Waivers []Waiver `yaml:"waivers"`
}

// Waiver lets one target past one preflight guard. It is an exception, not a
// setting: it must say why it exists and what ends it, and it may carry the
// date it stops counting.
type Waiver struct {
	// Guard is the guard waived. v1 knows one: GuardSCPOnManagement.
	Guard string `yaml:"guard"`
	// Target is what the guard is waived for: an OU or account name, or
	// "root" for the organization root.
	Target string `yaml:"target"`
	// Reason says why the exception exists; required.
	Reason string `yaml:"reason"`
	// ExitCondition says what ends it; required.
	ExitCondition string `yaml:"exit_condition"`
	// Expires is the last day (YYYY-MM-DD, UTC) the waiver counts; empty
	// means it lasts until it is removed. The preflight refuses an expired
	// waiver rather than ignoring it.
	Expires string `yaml:"expires"`
}

// Organization identifies the organization. v1 reads it; it never creates,
// modifies or deletes it, because there is nothing to adopt it from and a
// replaced organization is not recoverable.
type Organization struct {
	// ID is the organization id, o-followed by lowercase letters and digits.
	ID string `yaml:"id"`
	// RootID is the id of the organization's root, r-followed by 4 to 32
	// lowercase letters and digits.
	RootID string `yaml:"root_id"`
	// ManagementAccount is the NAME of the account that manages the
	// organization; it must be one of Accounts.
	ManagementAccount string `yaml:"management_account"`
	// Manage must be absent or false in v1. It exists so that a registry
	// that asks for more is refused by name rather than ignored.
	Manage bool `yaml:"manage"`
}

// OU is an organizational unit.
type OU struct {
	Name string `yaml:"name"`
	// Parent is the name of the parent OU; empty means the root.
	Parent string `yaml:"parent"`
	// ID is the existing OU's id, recorded when the OU is adopted so the
	// engine imports it instead of creating a second one.
	ID string `yaml:"id"`
	// SCPs are the names of policies attached to the OU (when enforcement
	// is not dormant).
	SCPs []string `yaml:"scps"`
	// Reason says why the OU exists; required.
	Reason string `yaml:"reason"`
}

// Account is a member account.
type Account struct {
	Name string `yaml:"name"`
	// ID is the 12-digit account id, recorded when the account is adopted.
	// Empty for an account that does not exist yet.
	ID    string `yaml:"id"`
	Email string `yaml:"email"`
	// OU is the name of the OU the account sits in, or OURoot for an account
	// directly under the organization root; required.
	OU   string            `yaml:"ou"`
	SCPs []string          `yaml:"scps"`
	Tags map[string]string `yaml:"tags"`
	// BaselineExempt, when set, is the reason this account does not carry
	// the baseline. A reason, not a boolean: an exemption must explain
	// itself.
	BaselineExempt string `yaml:"baseline_exempt"`
	// Closed says the account was closed (AWS keeps it in the organization,
	// SUSPENDED, until it is purged). A closed account is declared so that it
	// is not reported as unmanaged; drift expects it not to be active, and it
	// grants no assignment and needs no break-glass way in.
	Closed bool `yaml:"closed"`
}

// SCP is a service control policy.
type SCP struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	// Document is the policy JSON. AWS caps it at 5120 bytes.
	Document string `yaml:"document"`
}

// IdentityCenter is the Identity Center configuration.
type IdentityCenter struct {
	// InstanceARN and IdentityStoreID identify the instance being managed;
	// both are inputs because they are the caller's.
	InstanceARN     string `yaml:"instance_arn"`
	IdentityStoreID string `yaml:"identity_store_id"`

	Groups         []Group         `yaml:"groups"`
	PermissionSets []PermissionSet `yaml:"permission_sets"`
	Assignments    []Assignment    `yaml:"assignments"`

	// BreakGlass is the assignment that must reach every account, so that
	// no plan can take away the last way in. pkg/preflight's lockout guard
	// refuses a registry without it, or with an account it does not reach.
	BreakGlass *BreakGlass `yaml:"break_glass"`
}

// BreakGlass names the principal and permission set of the way back into
// every account. The assignments that grant it are ordinary Assignments.
type BreakGlass struct {
	Principal     string `yaml:"principal"`
	PrincipalType string `yaml:"principal_type"`
	PermissionSet string `yaml:"permission_set"`
}

// Group is an Identity Center group.
type Group struct {
	Name string `yaml:"name"`
	// Source is "manual" (managed here) or "sync" (filled by an external
	// source such as ssosync; the registry only names it).
	Source string `yaml:"source"`
}

// PermissionSet is an Identity Center permission set.
type PermissionSet struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	// SessionDuration is an ISO-8601 duration, e.g. PT8H.
	SessionDuration string `yaml:"session_duration"`
	// ManagedPolicies are AWS-managed policy ARNs.
	ManagedPolicies []string `yaml:"managed_policies"`
	// InlinePolicy is policy JSON; at most 10240 bytes.
	InlinePolicy string `yaml:"inline_policy"`
	// Includes names permission sets whose policies this one also carries.
	// A cycle is refused.
	Includes []string `yaml:"includes"`
}

// Assignment grants a principal a permission set on accounts or OUs.
type Assignment struct {
	// Principal is a group name (type group) or a user name (type user).
	Principal     string `yaml:"principal"`
	PrincipalType string `yaml:"principal_type"`
	PermissionSet string `yaml:"permission_set"`
	// Accounts and OUs are the targets by name; an OU target means every
	// account in it, at any depth.
	Accounts []string `yaml:"accounts"`
	OUs      []string `yaml:"ous"`
}

// Baseline is the per-account baseline.
type Baseline struct {
	PasswordPolicy *PasswordPolicy `yaml:"password_policy"`
	// EBSDefaultEncryption turns on default EBS encryption in every region
	// the caller lists in Regions.
	EBSDefaultEncryption bool         `yaml:"ebs_default_encryption"`
	Regions              []string     `yaml:"regions"`
	AccessAnalyzer       bool         `yaml:"access_analyzer"`
	AuditorRole          *AuditorRole `yaml:"auditor_role"`
	Boundaries           []Boundary   `yaml:"boundaries"`
}

// PasswordPolicy is the account password policy.
type PasswordPolicy struct {
	MinimumLength    int  `yaml:"minimum_length"`
	MaxAgeDays       int  `yaml:"max_age_days"`
	ReusePrevention  int  `yaml:"reuse_prevention"`
	RequireSymbols   bool `yaml:"require_symbols"`
	RequireNumbers   bool `yaml:"require_numbers"`
	RequireUppercase bool `yaml:"require_uppercase"`
	RequireLowercase bool `yaml:"require_lowercase"`
}

// AuditorRole is the read-only role each account carries for the audit
// account to assume.
type AuditorRole struct {
	Name string `yaml:"name"`
	// TrustedAccount is the NAME of the account allowed to assume it.
	TrustedAccount string `yaml:"trusted_account"`
}

// Boundary is a permissions boundary policy created in each account.
type Boundary struct {
	Name     string `yaml:"name"`
	Document string `yaml:"document"`
}
