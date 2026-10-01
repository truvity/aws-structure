package iam

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/iam"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/registry"
)

// TypeToken is the Pulumi type of the component.
const TypeToken = "truvity:aws-structure:AccountIAM"

// Kind names which child a logical name is for.
type Kind string

const (
	// KindPasswordPolicy is the iam.AccountPasswordPolicy.
	KindPasswordPolicy Kind = "password-policy"
	// KindBoundary is the iam.Policy of one boundary; Child.Name is the
	// boundary's name.
	KindBoundary Kind = "boundary"
	// KindAuditorPolicy is the customer-managed policy of the auditor role;
	// Child.Name is the policy's name.
	KindAuditorPolicy Kind = "auditor-policy"
	// KindAuditorRole is the auditor iam.Role; Child.Name is the role's name.
	KindAuditorRole Kind = "auditor-role"
	// KindAuditorManagedAttachment attaches one AWS-managed policy to the
	// auditor role; Child.Name is the policy ARN as the caller gave it.
	KindAuditorManagedAttachment Kind = "auditor-managed-attachment"
	// KindAuditorPolicyAttachment attaches the customer-managed policy to the
	// auditor role; Child.Name is the policy's name.
	KindAuditorPolicyAttachment Kind = "auditor-policy-attachment"
)

// Child identifies one child for a NameFunc.
type Child struct {
	// Component is the logical name the component was registered with.
	Component string
	Kind      Kind
	// Account is Args.Account.
	Account string
	// Name tells apart children of one Kind; see the Kind constants. It is
	// empty for KindPasswordPolicy.
	Name string
}

// NameFunc returns the Pulumi logical name of a child. The returned name must
// be unique among the component's children; it is part of the child's URN.
type NameFunc func(Child) string

// DefaultName names the children "<c>-password-policy", "<c>-boundary-<name>",
// "<c>-auditor-policy", "<c>-auditor-role", "<c>-auditor-managed-<last path
// element of the ARN>" and "<c>-auditor-policy-attachment". These names are
// API.
func DefaultName(c Child) string {
	switch c.Kind {
	case KindPasswordPolicy:
		return c.Component + "-password-policy"
	case KindBoundary:
		return c.Component + "-boundary-" + c.Name
	case KindAuditorPolicy:
		return c.Component + "-auditor-policy"
	case KindAuditorRole:
		return c.Component + "-auditor-role"
	case KindAuditorManagedAttachment:
		return c.Component + "-auditor-managed-" + path.Base(c.Name)
	default:
		return c.Component + "-auditor-policy-attachment"
	}
}

// Policy is a customer-managed policy.
type Policy struct {
	Name string
	// Document is policy JSON.
	Document string
}

// AuditorRole is a read-only role that a principal outside the account
// assumes. It is not registry.AuditorRole: that one names an account of the
// organization, while the principal of an auditor is often an outside party,
// so it needs an ARN, an external id and policies the registry cannot carry.
type AuditorRole struct {
	// Name is the role's name.
	Name string
	// TrustedPrincipal is the ARN of the principal allowed to assume the role.
	TrustedPrincipal string
	// ExternalID is required of the principal when it assumes the role. Empty
	// means no condition.
	ExternalID string
	// ManagedPolicies are the ARNs of AWS-managed policies the role carries.
	ManagedPolicies []string
	// Policy is an additional customer-managed policy the role carries.
	// Optional.
	Policy *Policy
	// PermissionsBoundary is the ARN of the boundary policy set on the role.
	// Required: a role without a boundary can grow past it.
	PermissionsBoundary pulumi.StringInput
}

// Args configures the component.
type Args struct {
	// Account is the account's name. Required; it only feeds Child.Account.
	Account string
	// PasswordPolicy is the account password policy. Nil creates none.
	PasswordPolicy *registry.PasswordPolicy
	// Boundaries are the boundary policies created in the account.
	Boundaries []registry.Boundary
	// AuditorRole is the auditor role. Nil creates none.
	AuditorRole *AuditorRole

	// Provider is the AWS provider of the account. Required.
	Provider pulumi.ProviderResource
	// BoundaryProvider is the provider the boundaries are created with. Nil
	// means Provider.
	BoundaryProvider pulumi.ProviderResource

	// Names overrides the logical names of the children. Nil uses
	// DefaultName.
	Names NameFunc
	// LegacyTopLevel makes every child carry an alias from the URN it has
	// when it is registered directly under the stack (no parent), with the
	// same type and the name Names gives it. Set it when adopting resources
	// that were created before they were wrapped in this component.
	LegacyTopLevel bool
}

// AccountIAM is the component.
type AccountIAM struct {
	pulumi.ResourceState
}

// plan lists every child the args register, in registration order.
func (a *Args) plan(component string) []Child {
	var out []Child

	add := func(k Kind, name string) {
		out = append(out, Child{Component: component, Kind: k, Account: a.Account, Name: name})
	}

	if a.PasswordPolicy != nil {
		add(KindPasswordPolicy, "")
	}

	for _, b := range a.Boundaries {
		add(KindBoundary, b.Name)
	}

	if r := a.AuditorRole; r != nil {
		if r.Policy != nil {
			add(KindAuditorPolicy, r.Policy.Name)
		}

		add(KindAuditorRole, r.Name)

		for _, m := range r.ManagedPolicies {
			add(KindAuditorManagedAttachment, m)
		}

		if r.Policy != nil {
			add(KindAuditorPolicyAttachment, r.Policy.Name)
		}
	}

	return out
}

func (a *Args) validatePasswordPolicy() []error {
	p := a.PasswordPolicy
	if p == nil {
		return nil
	}

	var errs []error

	if p.MinimumLength < 8 || p.MinimumLength > 128 {
		errs = append(errs, fmt.Errorf("args: PasswordPolicy.MinimumLength %d is outside 8..128", p.MinimumLength))
	}

	if p.MaxAgeDays < 0 || p.MaxAgeDays > 1095 {
		errs = append(errs, fmt.Errorf("args: PasswordPolicy.MaxAgeDays %d is outside 0..1095", p.MaxAgeDays))
	}

	if p.ReusePrevention < 0 || p.ReusePrevention > 24 {
		errs = append(errs, fmt.Errorf("args: PasswordPolicy.ReusePrevention %d is outside 0..24", p.ReusePrevention))
	}

	return errs
}

func (a *Args) validateBoundaries() []error {
	var errs []error

	seen := map[string]bool{}

	for i, b := range a.Boundaries {
		switch {
		case b.Name == "":
			errs = append(errs, fmt.Errorf("args: Boundaries[%d] has no name", i))
		case seen[b.Name]:
			errs = append(errs, fmt.Errorf("args: Boundaries lists %q twice", b.Name))
		}

		seen[b.Name] = true

		if !json.Valid([]byte(b.Document)) {
			errs = append(errs, fmt.Errorf("args: Boundaries[%d] (%q) document is not JSON", i, b.Name))
		}
	}

	return errs
}

func (a *Args) validateAuditor() []error {
	r := a.AuditorRole
	if r == nil {
		return nil
	}

	var errs []error

	if r.Name == "" {
		errs = append(errs, errors.New("args: AuditorRole.Name is empty"))
	}

	if r.TrustedPrincipal == "" {
		errs = append(errs, errors.New("args: AuditorRole.TrustedPrincipal is empty"))
	}

	if r.PermissionsBoundary == nil {
		errs = append(errs, errors.New("args: AuditorRole.PermissionsBoundary is unset"))
	}

	seen := map[string]bool{}

	for _, m := range r.ManagedPolicies {
		switch {
		case m == "":
			errs = append(errs, errors.New("args: AuditorRole.ManagedPolicies has an empty entry"))
		case seen[m]:
			errs = append(errs, fmt.Errorf("args: AuditorRole.ManagedPolicies lists %q twice", m))
		}

		seen[m] = true
	}

	if p := r.Policy; p != nil {
		if p.Name == "" {
			errs = append(errs, errors.New("args: AuditorRole.Policy.Name is empty"))
		}

		if !json.Valid([]byte(p.Document)) {
			errs = append(errs, errors.New("args: AuditorRole.Policy.Document is not JSON"))
		}
	}

	return errs
}

// Validate reports every problem with args at once, or returns nil.
func (a *Args) Validate() error {
	var errs []error

	if a.Account == "" {
		errs = append(errs, errors.New("args: Account is empty"))
	}

	if a.Provider == nil {
		errs = append(errs, errors.New("args: Provider is nil"))
	}

	errs = append(errs, a.validatePasswordPolicy()...)
	errs = append(errs, a.validateBoundaries()...)
	errs = append(errs, a.validateAuditor()...)
	errs = append(errs, a.checkNames("")...)

	return errors.Join(errs...)
}

// checkNames refuses a naming hook that returns an empty or repeated name.
func (a *Args) checkNames(component string) []error {
	names := a.Names
	if names == nil {
		names = DefaultName
	}

	var errs []error

	seen := map[string]Child{}

	for _, c := range a.plan(component) {
		n := names(c)

		if n == "" {
			errs = append(errs, fmt.Errorf("args: Names returned an empty name for %s %q", c.Kind, c.Name))

			continue
		}

		if prev, dup := seen[n]; dup {
			errs = append(errs, fmt.Errorf("args: Names returned %q for both %s %q and %s %q", n, prev.Kind, prev.Name, c.Kind, c.Name))
		}

		seen[n] = c
	}

	return errs
}

// trustPolicy renders the role's trust policy. The layout is fixed: the
// document is a resource input, and a change in whitespace is an update.
func trustPolicy(principal, externalID string) string {
	p, _ := json.Marshal(principal)

	if externalID == "" {
		return fmt.Sprintf(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": %s
      },
      "Action": "sts:AssumeRole"
    }
  ]
}`, p)
	}

	e, _ := json.Marshal(externalID)

	return fmt.Sprintf(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": %s
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": %s
        }
      }
    }
  ]
}`, p, e)
}

// New registers the component and its children. It returns an error,
// registering nothing, when args.Validate does or when Names returns an empty
// or repeated name.
//
// The provider comes from Args, not from pulumi.Providers.
func New(ctx *pulumi.Context, name string, args *Args, opts ...pulumi.ResourceOption) (*AccountIAM, error) {
	if args == nil {
		return nil, errors.New("iam: args is nil")
	}

	if err := args.Validate(); err != nil {
		return nil, fmt.Errorf("iam %s: %w", name, err)
	}

	if err := errors.Join(args.checkNames(name)...); err != nil {
		return nil, fmt.Errorf("iam %s: %w", name, err)
	}

	names := args.Names
	if names == nil {
		names = DefaultName
	}

	comp := &AccountIAM{}
	if err := ctx.RegisterComponentResource(TypeToken, name, comp, opts...); err != nil {
		return nil, err
	}

	childOpts := func(p pulumi.ProviderResource) []pulumi.ResourceOption {
		o := []pulumi.ResourceOption{pulumi.Parent(comp), pulumi.Provider(p)}
		if args.LegacyTopLevel {
			o = append(o, pulumi.Aliases([]pulumi.Alias{{NoParent: pulumi.Bool(true)}}))
		}

		return o
	}

	opt := childOpts(args.Provider)

	if p := args.PasswordPolicy; p != nil {
		if _, err := iam.NewAccountPasswordPolicy(ctx, names(Child{Component: name, Kind: KindPasswordPolicy, Account: args.Account}),
			&iam.AccountPasswordPolicyArgs{
				MinimumPasswordLength:      pulumi.Int(p.MinimumLength),
				RequireUppercaseCharacters: pulumi.Bool(p.RequireUppercase),
				RequireLowercaseCharacters: pulumi.Bool(p.RequireLowercase),
				RequireNumbers:             pulumi.Bool(p.RequireNumbers),
				RequireSymbols:             pulumi.Bool(p.RequireSymbols),
				MaxPasswordAge:             pulumi.Int(p.MaxAgeDays),
				PasswordReusePrevention:    pulumi.Int(p.ReusePrevention),
				AllowUsersToChangePassword: pulumi.Bool(true),
			}, opt...); err != nil {
			return nil, fmt.Errorf("create password policy in %s: %w", args.Account, err)
		}
	}

	bp := args.BoundaryProvider
	if bp == nil {
		bp = args.Provider
	}

	for _, b := range args.Boundaries {
		if _, err := iam.NewPolicy(ctx, names(Child{Component: name, Kind: KindBoundary, Account: args.Account, Name: b.Name}),
			&iam.PolicyArgs{
				Name:   pulumi.String(b.Name),
				Policy: pulumi.String(b.Document),
			}, childOpts(bp)...); err != nil {
			return nil, fmt.Errorf("create boundary %s in %s: %w", b.Name, args.Account, err)
		}
	}

	if r := args.AuditorRole; r != nil {
		if err := newAuditor(ctx, name, names, args, opt); err != nil {
			return nil, err
		}
	}

	if err := ctx.RegisterResourceOutputs(comp, pulumi.Map{}); err != nil {
		return nil, err
	}

	return comp, nil
}

func newAuditor(ctx *pulumi.Context, name string, names NameFunc, args *Args, opt []pulumi.ResourceOption) error {
	r := args.AuditorRole
	child := func(k Kind, n string) string {
		return names(Child{Component: name, Kind: k, Account: args.Account, Name: n})
	}

	var policy *iam.Policy

	if r.Policy != nil {
		var err error

		policy, err = iam.NewPolicy(ctx, child(KindAuditorPolicy, r.Policy.Name), &iam.PolicyArgs{
			Name:   pulumi.String(r.Policy.Name),
			Policy: pulumi.String(r.Policy.Document),
		}, opt...)
		if err != nil {
			return fmt.Errorf("create auditor policy %s in %s: %w", r.Policy.Name, args.Account, err)
		}
	}

	role, err := iam.NewRole(ctx, child(KindAuditorRole, r.Name), &iam.RoleArgs{
		Name:                pulumi.String(r.Name),
		AssumeRolePolicy:    pulumi.String(trustPolicy(r.TrustedPrincipal, r.ExternalID)),
		PermissionsBoundary: r.PermissionsBoundary,
	}, opt...)
	if err != nil {
		return fmt.Errorf("create auditor role %s in %s: %w", r.Name, args.Account, err)
	}

	for _, m := range r.ManagedPolicies {
		if _, err := iam.NewRolePolicyAttachment(ctx, child(KindAuditorManagedAttachment, m), &iam.RolePolicyAttachmentArgs{
			Role:      role.Name,
			PolicyArn: pulumi.String(m),
		}, opt...); err != nil {
			return fmt.Errorf("attach %s to %s in %s: %w", m, r.Name, args.Account, err)
		}
	}

	if policy != nil {
		if _, err := iam.NewRolePolicyAttachment(ctx, child(KindAuditorPolicyAttachment, r.Policy.Name), &iam.RolePolicyAttachmentArgs{
			Role:      role.Name,
			PolicyArn: policy.Arn,
		}, opt...); err != nil {
			return fmt.Errorf("attach %s to %s in %s: %w", r.Policy.Name, r.Name, args.Account, err)
		}
	}

	return nil
}
