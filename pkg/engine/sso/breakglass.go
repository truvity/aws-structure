package sso

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/registry"
)

// BreakGlassComponentPrefix starts the logical name of each break-glass
// component: "sso-break-glass-<account>". The name is API.
const BreakGlassComponentPrefix = "sso-break-glass-"

// BreakGlassArgs configures DeployBreakGlass.
type BreakGlassArgs struct {
	// Registry supplies the accounts and identity_center.break_glass.
	// Required; its BreakGlass must be declared.
	Registry *registry.Registry
	// InstanceARN is the ARN of the Identity Center instance. Required.
	InstanceARN pulumi.StringInput
	// PrincipalID is the Identity Store id of the break-glass principal and
	// PermissionSetARN the ARN of its permission set. The caller resolves
	// them as for any assignment (LookupGroupIDs, a PermissionSet component or
	// LookupPermissionSetARN). Required.
	PrincipalID      pulumi.StringInput
	PermissionSetARN pulumi.StringInput
	// Provider is the AWS provider of the Identity Center region. Required.
	Provider pulumi.ProviderResource

	// Skip, when set, is asked for each target account's name; true leaves
	// that account out. Use it for an account on which the caller's own
	// assignments (DeployAssignments, a hand-written AccountAssignments)
	// already grant the same principal and permission set: two resources
	// for one (principal, set, account) would collide in AWS. Nil skips
	// nothing. Pass the same function to preflight.Opts.BreakGlassBuilder so
	// the registry guard still expects those accounts to be reached by the
	// registry's own assignments.
	Skip func(account string) bool

	// Names overrides the logical name of the assignment. Nil uses
	// DefaultBreakGlassName. AssignmentChild.Component is the component's
	// name.
	Names AssignmentNameFunc
	// LegacyTopLevel makes the assignment carry the alias of a resource
	// registered directly under the stack; see AccountAssignmentsArgs.
	LegacyTopLevel bool
	// LegacyNames maps an account name to earlier logical names of its
	// break-glass assignment, each becoming an alias.
	LegacyNames map[string][]string
}

// DefaultBreakGlassName names the assignment "break-glass-<account>-<permission
// set>-<principal>" (with "-user" for a user principal). These names are API.
func DefaultBreakGlassName(c AssignmentChild) string {
	n := "break-glass-" + c.Account + "-" + c.PermissionSet + "-" + c.Principal
	if c.PrincipalType == PrincipalUser {
		n += "-user"
	}

	return n
}

// DeployBreakGlass declares, on every account of reg.BreakGlassTargets (open,
// with an id, at any depth including directly under the organization root),
// one AccountAssignment of the registry's identity_center.break_glass
// principal and permission set. Each account gets one AccountAssignments
// component named BreakGlassComponentPrefix+account, with one child named by
// Names (default DefaultBreakGlassName). Accounts for which Skip returns true
// get nothing.
//
// It ADDS break-glass beside whatever the caller declares for the account,
// which a scope matrix cannot do: such a matrix can only replace the set of an
// account. Because AWS allows a (principal, permission set, account) once, the
// caller must Skip the accounts its own assignments already grant it on.
//
// It returns the names of the accounts it declared, in registry order. It
// declares nothing and returns an error when Registry, its BreakGlass, the
// instance, the principal, the permission set or the provider is missing, or
// when Names returns an empty or repeated name.
func DeployBreakGlass(ctx *pulumi.Context, logger *slog.Logger, a BreakGlassArgs) ([]string, error) {
	var errs []error

	if a.Registry == nil || a.Registry.IdentityCenter.BreakGlass == nil {
		errs = append(errs, errors.New("args: Registry.IdentityCenter.BreakGlass is not declared"))
	}

	if a.InstanceARN == nil {
		errs = append(errs, errors.New("args: InstanceARN is unset"))
	}

	if a.PrincipalID == nil {
		errs = append(errs, errors.New("args: PrincipalID is unset"))
	}

	if a.PermissionSetARN == nil {
		errs = append(errs, errors.New("args: PermissionSetARN is unset"))
	}

	if a.Provider == nil {
		errs = append(errs, errors.New("args: Provider is nil"))
	}

	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("sso break-glass: %w", err)
	}

	bg := a.Registry.IdentityCenter.BreakGlass

	names := a.Names
	if names == nil {
		names = DefaultBreakGlassName
	}

	pt := bg.PrincipalType
	if pt == "" {
		pt = PrincipalGroup
	}

	var targets []registry.Account

	for _, acct := range a.Registry.BreakGlassTargets() {
		if a.Skip != nil && a.Skip(acct.Name) {
			continue
		}

		targets = append(targets, acct)
	}

	// Check every name before registering anything.
	seen := map[string]string{}

	for _, acct := range targets {
		n := names(AssignmentChild{
			Component: BreakGlassComponentPrefix + acct.Name, Account: acct.Name,
			PermissionSet: bg.PermissionSet, Principal: bg.Principal, PrincipalType: pt,
		})

		switch prev, dup := seen[n]; {
		case n == "":
			errs = append(errs, fmt.Errorf("args: Names returned an empty name for %s", acct.Name))
		case dup:
			errs = append(errs, fmt.Errorf("args: Names returned %q for both %s and %s", n, prev, acct.Name))
		}

		seen[n] = acct.Name
	}

	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("sso break-glass: %w", err)
	}

	deployed := make([]string, 0, len(targets))

	for _, acct := range targets {
		if _, err := NewAccountAssignments(ctx, BreakGlassComponentPrefix+acct.Name, &AccountAssignmentsArgs{
			Account:     acct.Name,
			InstanceARN: a.InstanceARN,
			TargetID:    pulumi.String(acct.ID),
			Assignments: []Assignment{{
				Principal:        bg.Principal,
				PrincipalType:    pt,
				PrincipalID:      a.PrincipalID,
				PermissionSet:    bg.PermissionSet,
				PermissionSetARN: a.PermissionSetARN,
				LegacyNames:      a.LegacyNames[acct.Name],
			}},
			Provider:       a.Provider,
			Names:          names,
			LegacyTopLevel: a.LegacyTopLevel,
		}); err != nil {
			return nil, fmt.Errorf("deploy break-glass on %s: %w", acct.Name, err)
		}

		logger.InfoContext(ctx.Context(), "created break-glass assignment",
			slog.String("account", acct.Name),
			slog.String("permission_set", bg.PermissionSet),
		)

		deployed = append(deployed, acct.Name)
	}

	logger.InfoContext(ctx.Context(), "break-glass assignments deployed", slog.Int("count", len(deployed)))

	return deployed, nil
}
