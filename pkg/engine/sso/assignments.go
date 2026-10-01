package sso

import (
	"errors"
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/ssoadmin"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// AssignmentsTypeToken is the Pulumi type of the assignments component.
const AssignmentsTypeToken = "truvity:aws-structure:AccountAssignments"

// Principal types, as pkg/registry spells them.
const (
	PrincipalGroup = "group"
	PrincipalUser  = "user"
)

// Assignment grants one principal one permission set on the target account.
// It is a resolved registry assignment: the registry names accounts and OUs,
// the caller resolves them to one target per component and every reference to
// an id or ARN.
type Assignment struct {
	// Principal is the principal's name. It only feeds names; PrincipalID is
	// what is assigned. Required.
	Principal string
	// PrincipalType is "group" (the default) or "user".
	PrincipalType string
	// PrincipalID is the Identity Store id of the principal. Required.
	PrincipalID pulumi.StringInput

	// PermissionSet is the permission set's name. It only feeds names;
	// PermissionSetARN is what is assigned. Required.
	PermissionSet string
	// PermissionSetARN is the permission set's ARN. Required. It is an
	// output of a PermissionSet component, or the result of
	// LookupPermissionSetARN for a set this package does not manage.
	PermissionSetARN pulumi.StringInput

	// LegacyNames are earlier logical names of this assignment. Each becomes
	// an alias, so a renamed assignment is a rename in state and not a
	// replace. With Args.LegacyTopLevel they are names under the stack.
	LegacyNames []string
}

// AssignmentChild identifies one assignment for an AssignmentNameFunc.
type AssignmentChild struct {
	// Component is the logical name the component was registered with.
	Component string
	// Account is AccountAssignmentsArgs.Account.
	Account       string
	PermissionSet string
	Principal     string
	// PrincipalType is "group" or "user", never empty.
	PrincipalType string
}

// AssignmentNameFunc returns the Pulumi logical name of an assignment. The
// returned name must be unique among the component's children; it is part of
// the child's URN.
type AssignmentNameFunc func(AssignmentChild) string

// DefaultAssignmentName names an assignment "<c>-<permission set>-<principal>"
// and, for a user, "<c>-<permission set>-<principal>-user". These names are
// API.
func DefaultAssignmentName(c AssignmentChild) string {
	n := c.Component + "-" + c.PermissionSet + "-" + c.Principal
	if c.PrincipalType == PrincipalUser {
		n += "-user"
	}

	return n
}

// AccountAssignmentsArgs configures the assignments component.
type AccountAssignmentsArgs struct {
	// Account is the target account's name. Required; it only feeds
	// AssignmentChild.Account.
	Account string
	// InstanceARN is the ARN of the Identity Center instance. Required.
	InstanceARN pulumi.StringInput
	// TargetID is the id of the target account. Required.
	TargetID pulumi.StringInput

	// Assignments are the grants on the target. May be empty.
	Assignments []Assignment

	// Provider is the AWS provider of the region the instance lives in.
	// Required.
	Provider pulumi.ProviderResource

	// Names overrides the logical names of the assignments. Nil uses
	// DefaultAssignmentName.
	Names AssignmentNameFunc
	// LegacyTopLevel makes every assignment carry an alias from the URN it
	// has when it is registered directly under the stack (no parent), with
	// the same type and the name Names gives it. Set it when adopting
	// assignments that were created before they were wrapped in this
	// component.
	LegacyTopLevel bool
}

// AccountAssignments is the component.
type AccountAssignments struct {
	pulumi.ResourceState
}

func principalType(a *Assignment) string {
	if a.PrincipalType == "" {
		return PrincipalGroup
	}

	return a.PrincipalType
}

func (a *AccountAssignmentsArgs) child(component string, as *Assignment) AssignmentChild {
	return AssignmentChild{
		Component:     component,
		Account:       a.Account,
		PermissionSet: as.PermissionSet,
		Principal:     as.Principal,
		PrincipalType: principalType(as),
	}
}

// Validate reports every problem with args at once, or returns nil.
func (a *AccountAssignmentsArgs) Validate() error {
	var errs []error

	if a.Account == "" {
		errs = append(errs, errors.New("args: Account is empty"))
	}

	if a.InstanceARN == nil {
		errs = append(errs, errors.New("args: InstanceARN is unset"))
	}

	if a.TargetID == nil {
		errs = append(errs, errors.New("args: TargetID is unset"))
	}

	if a.Provider == nil {
		errs = append(errs, errors.New("args: Provider is nil"))
	}

	type key struct{ set, principal, typ string }

	seen := map[key]bool{}

	for i := range a.Assignments {
		as := &a.Assignments[i]
		at := fmt.Sprintf("args: Assignments[%d]", i)

		if as.Principal == "" {
			errs = append(errs, fmt.Errorf("%s: Principal is empty", at))
		}

		if as.PrincipalID == nil {
			errs = append(errs, fmt.Errorf("%s: PrincipalID is unset", at))
		}

		if as.PermissionSet == "" {
			errs = append(errs, fmt.Errorf("%s: PermissionSet is empty", at))
		}

		if as.PermissionSetARN == nil {
			errs = append(errs, fmt.Errorf("%s: PermissionSetARN is unset", at))
		}

		switch t := principalType(as); t {
		case PrincipalGroup, PrincipalUser:
		default:
			errs = append(errs, fmt.Errorf("%s: PrincipalType %q is neither %q nor %q", at, t, PrincipalGroup, PrincipalUser))
		}

		k := key{as.PermissionSet, as.Principal, principalType(as)}
		if seen[k] {
			errs = append(errs, fmt.Errorf("%s: %s %q is assigned %q twice", at, k.typ, k.principal, k.set))
		}

		seen[k] = true

		for j, n := range as.LegacyNames {
			if n == "" {
				errs = append(errs, fmt.Errorf("%s: LegacyNames[%d] is empty", at, j))
			}
		}
	}

	errs = append(errs, a.checkNames("")...)

	return errors.Join(errs...)
}

// checkNames refuses a naming hook that returns an empty or repeated name.
func (a *AccountAssignmentsArgs) checkNames(component string) []error {
	names := a.Names
	if names == nil {
		names = DefaultAssignmentName
	}

	var errs []error

	seen := map[string]int{}

	for i := range a.Assignments {
		n := names(a.child(component, &a.Assignments[i]))

		if n == "" {
			errs = append(errs, fmt.Errorf("args: Names returned an empty name for Assignments[%d]", i))

			continue
		}

		if prev, dup := seen[n]; dup {
			errs = append(errs, fmt.Errorf("args: Names returned %q for both Assignments[%d] and Assignments[%d]", n, prev, i))
		}

		seen[n] = i
	}

	return errs
}

// NewAccountAssignments registers the component and its assignments. It
// returns an error, registering nothing, when args.Validate does or when Names
// returns an empty or repeated name.
//
// The provider comes from Args, not from pulumi.Providers.
func NewAccountAssignments(ctx *pulumi.Context, name string, args *AccountAssignmentsArgs, opts ...pulumi.ResourceOption) (*AccountAssignments, error) {
	if args == nil {
		return nil, errors.New("sso: args is nil")
	}

	if err := args.Validate(); err != nil {
		return nil, fmt.Errorf("sso assignments %s: %w", name, err)
	}

	if err := errors.Join(args.checkNames(name)...); err != nil {
		return nil, fmt.Errorf("sso assignments %s: %w", name, err)
	}

	names := args.Names
	if names == nil {
		names = DefaultAssignmentName
	}

	comp := &AccountAssignments{}
	if err := ctx.RegisterComponentResource(AssignmentsTypeToken, name, comp, opts...); err != nil {
		return nil, err
	}

	for i := range args.Assignments {
		as := &args.Assignments[i]

		var aliases []pulumi.Alias

		for _, n := range as.LegacyNames {
			aliases = append(aliases, pulumi.Alias{Name: pulumi.String(n), NoParent: pulumi.Bool(args.LegacyTopLevel)})
		}

		if args.LegacyTopLevel {
			aliases = append(aliases, pulumi.Alias{NoParent: pulumi.Bool(true)})
		}

		o := []pulumi.ResourceOption{pulumi.Parent(comp), pulumi.Provider(args.Provider)}
		if len(aliases) > 0 {
			o = append(o, pulumi.Aliases(aliases))
		}

		pt := "GROUP"
		if principalType(as) == PrincipalUser {
			pt = "USER"
		}

		rname := names(args.child(name, as))

		if _, err := ssoadmin.NewAccountAssignment(ctx, rname, &ssoadmin.AccountAssignmentArgs{
			InstanceArn:      args.InstanceARN,
			PermissionSetArn: as.PermissionSetARN,
			PrincipalId:      as.PrincipalID,
			PrincipalType:    pulumi.String(pt),
			TargetId:         args.TargetID,
			TargetType:       pulumi.String("AWS_ACCOUNT"),
		}, o...); err != nil {
			return nil, fmt.Errorf("create assignment %s on %s: %w", rname, args.Account, err)
		}
	}

	if err := ctx.RegisterResourceOutputs(comp, pulumi.Map{}); err != nil {
		return nil, err
	}

	return comp, nil
}
