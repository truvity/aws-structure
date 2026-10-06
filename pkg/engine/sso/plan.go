package sso

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/ssoadmin"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/registry"
)

// SetSpec is one permission set of a deployment, known by Key. Key is the
// caller's own handle for it (grants refer to the set by Name, includes by
// Key); only Name reaches AWS.
type SetSpec struct {
	Key             string
	Name            string
	SessionDuration string
	ManagedPolicies []string
	// BoundaryPolicyName is the name of the customer-managed policy used as the
	// set's permissions boundary, by name only. Empty: no boundary.
	BoundaryPolicyName string
	// Includes are the keys of the sets whose assignments a grant of this set
	// also gives, one level deep (a grant of a set assigns the set and each
	// of its includes, not their includes).
	Includes []string
}

// Instance is the Identity Center instance of an account.
type Instance struct {
	ARN             string
	IdentityStoreID string
}

// LookupInstance reads the account's Identity Center instance. It refuses an
// account without one.
func LookupInstance(ctx *pulumi.Context, provider pulumi.ProviderResource) (*Instance, error) {
	if provider == nil {
		return nil, errors.New("sso: provider is nil")
	}

	instances, err := ssoadmin.GetInstances(ctx, nil, pulumi.Provider(provider))
	if err != nil {
		return nil, fmt.Errorf("lookup Identity Center instances: %w", err)
	}

	if len(instances.Arns) == 0 || len(instances.IdentityStoreIds) == 0 {
		return nil, errors.New("identity Center instance not found — ensure SSO is enabled in the organization")
	}

	return &Instance{ARN: instances.Arns[0], IdentityStoreID: instances.IdentityStoreIds[0]}, nil
}

// DeploySets creates one PermissionSet component per spec, named "sso-ps-<key>"
// with the children "ps-<key>", "ps-<key>-policy-<i>" and "ps-<key>-boundary".
// Those names are API. The sets are protected and retained on delete by the
// component. The result is keyed by Key.
func DeploySets(
	ctx *pulumi.Context,
	logger *slog.Logger,
	instanceARN pulumi.StringInput,
	sets map[string]*SetSpec,
	provider pulumi.ProviderResource,
) (map[string]*PermissionSet, error) {
	goCtx := ctx.Context()

	logger.InfoContext(goCtx, "deploying permission sets", slog.Int("count", len(sets)))

	keys := make([]string, 0, len(sets))
	for k := range sets {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	result := make(map[string]*PermissionSet, len(sets))

	for _, key := range keys {
		spec := sets[key]

		args := &PermissionSetArgs{
			InstanceARN: instanceARN,
			Set: registry.PermissionSet{
				Name:            spec.Name,
				SessionDuration: spec.SessionDuration,
				ManagedPolicies: spec.ManagedPolicies,
			},
			Provider:       provider,
			LegacyTopLevel: true,
			Names: func(c SetChild) string {
				switch c.Kind {
				case SetKindManagedPolicy:
					return fmt.Sprintf("ps-%s-policy-%d", key, c.Index)
				case SetKindBoundary:
					return fmt.Sprintf("ps-%s-boundary", key)
				default:
					return fmt.Sprintf("ps-%s", key)
				}
			},
			BoundaryPolicyName: spec.BoundaryPolicyName,
		}

		ps, err := NewPermissionSet(ctx, "sso-ps-"+key, args)
		if err != nil {
			return nil, fmt.Errorf("deploy permission set %s: %w", key, err)
		}

		logger.InfoContext(goCtx, "created permission set",
			slog.String("name", key),
			slog.String("session_duration", spec.SessionDuration),
			slog.Int("managed_policies", len(spec.ManagedPolicies)),
		)

		result[key] = ps
	}

	logger.InfoContext(goCtx, "all permission sets deployed", slog.Int("count", len(result)))

	return result, nil
}

// Effective resolves a set's inheritance: the set and each of its includes,
// one level deep, in that order. An unknown key is an error.
func Effective(sets map[string]*SetSpec, key string) ([]*SetSpec, error) {
	ps, ok := sets[key]
	if !ok {
		return nil, fmt.Errorf("permission set not found: %s", key)
	}

	result := []*SetSpec{ps}

	for _, include := range ps.Includes {
		included, ok := sets[include]
		if !ok {
			return nil, fmt.Errorf("included permission set not found: %s", include)
		}

		result = append(result, included)
	}

	return result, nil
}

// Grant gives a group a permission set on an account scope.
type Grant struct {
	// Scope names the account (a key of PlanArgs.AccountIDs).
	Scope string
	// Set is the permission set's NAME (SetSpec.Name).
	Set string
	// Group is the caller's name for the group (a key of PlanArgs.GroupIDs).
	Group string
	// Role is the role that produced the grant. It only feeds the aliases of
	// the names assignments had before they were named by identity.
	Role string
}

// PlanArgs configures DeployAssignments.
type PlanArgs struct {
	InstanceARN pulumi.StringInput
	Provider    pulumi.ProviderResource
	// Sets are the specs and Deployed the components DeploySets made, by key.
	Sets     map[string]*SetSpec
	Deployed map[string]*PermissionSet
	// Grants are what to assign. Each is expanded by the set's includes.
	Grants []Grant
	// Aliases maps a set NAME to the key of a second set that gets every grant
	// of the first as well (a compatibility alias). Ignored when that key is
	// not in Sets.
	Aliases map[string]string
	// RoleFirstGroup maps a role to the first group of its rung. An assignment
	// that belongs to such a role gets the pre-identity logical name
	// "assignment-<scope>-<role>-<set name>" as an alias, so adopting the
	// naming by identity renames state without touching AWS.
	RoleFirstGroup map[string]string
	AccountIDs     map[string]pulumi.StringInput
	GroupIDs       map[string]pulumi.StringOutput
	// DisplayName turns the caller's group name into the group's display name
	// in Identity Center, which names the assignment.
	DisplayName func(group string) string
}

// DeployAssignments expands the grants and creates one AccountAssignments
// component per scope that has one, named "sso-assignments-<scope>", whose
// children are named "assignment-<scope>-<set name>-<principal>".
//
// An assignment's IDENTITY is (scope, set, group), not which role emitted it:
// a group reachable through several roles, or a compatibility alias, collapse
// into one resource, emitted in sorted order, so the order of grants carries no
// meaning.
func DeployAssignments(ctx *pulumi.Context, logger *slog.Logger, a PlanArgs) error {
	goCtx := ctx.Context()

	type identity struct{ scope, setKey, group string }

	keyOfName := make(map[string]string, len(a.Sets))
	for key, ps := range a.Sets {
		keyOfName[ps.Name] = key
	}

	// Contributing roles are kept solely to alias the pre-identity names.
	desired := make(map[identity]map[string]bool)

	record := func(scope, setKey, group, role string) {
		id := identity{scope: scope, setKey: setKey, group: group}
		if desired[id] == nil {
			desired[id] = make(map[string]bool)
		}

		desired[id][role] = true
	}

	for _, g := range a.Grants {
		key, ok := keyOfName[g.Set]
		if !ok {
			return fmt.Errorf("unknown permission set %q for scope %s role %s", g.Set, g.Scope, g.Role)
		}

		effective, err := Effective(a.Sets, key)
		if err != nil {
			return fmt.Errorf("resolve permission sets for %s/%s: %w", g.Scope, g.Role, err)
		}

		for _, ps := range effective {
			record(g.Scope, ps.Key, g.Group, g.Role)
		}

		if alias, ok := a.Aliases[g.Set]; ok {
			if _, present := a.Sets[alias]; present {
				record(g.Scope, alias, g.Group, g.Role)
			}
		}
	}

	identities := make([]identity, 0, len(desired))
	for id := range desired {
		identities = append(identities, id)
	}

	sort.Slice(identities, func(i, j int) bool {
		if identities[i].scope != identities[j].scope {
			return identities[i].scope < identities[j].scope
		}

		if identities[i].setKey != identities[j].setKey {
			return identities[i].setKey < identities[j].setKey
		}

		return identities[i].group < identities[j].group
	})

	perScope := make(map[string][]Assignment)

	var scopes []string

	for _, id := range identities {
		permSet, ok := a.Deployed[id.setKey]
		if !ok {
			return fmt.Errorf("permission set resource not found: %s", id.setKey)
		}

		spec, ok := a.Sets[id.setKey]
		if !ok {
			return fmt.Errorf("permission set config not found: %s", id.setKey)
		}

		group, ok := a.GroupIDs[id.group]
		if !ok {
			return fmt.Errorf("SSO group not found: %s", id.group)
		}

		// Every live assignment predates the dual-run, so it belongs to a role
		// whose FIRST group is this one; Pulumi treats the emission as a rename
		// (zero AWS calls). A missed alias fails loudly on create: the preview
		// gate catches it.
		var aliasNames []string

		for role := range desired[id] {
			if first, ok := a.RoleFirstGroup[role]; !ok || first != id.group {
				continue
			}

			aliasNames = append(aliasNames, fmt.Sprintf("assignment-%s-%s-%s", id.scope, role, spec.Name))
		}

		sort.Strings(aliasNames)

		if _, seen := perScope[id.scope]; !seen {
			scopes = append(scopes, id.scope)
		}

		perScope[id.scope] = append(perScope[id.scope], Assignment{
			Principal:        a.DisplayName(id.group),
			PrincipalID:      group,
			PermissionSet:    spec.Name,
			PermissionSetARN: permSet.Arn,
			LegacyNames:      aliasNames,
		})
	}

	var count int

	// identities is sorted by scope, so scopes is too.
	for _, scope := range scopes {
		target, ok := a.AccountIDs[scope]
		if !ok {
			return fmt.Errorf("no account id for scope %s", scope)
		}

		if _, err := NewAccountAssignments(ctx, "sso-assignments-"+scope, &AccountAssignmentsArgs{
			Account:        scope,
			InstanceARN:    a.InstanceARN,
			TargetID:       target,
			Assignments:    perScope[scope],
			Provider:       a.Provider,
			LegacyTopLevel: true,
			Names: func(c AssignmentChild) string {
				return fmt.Sprintf("assignment-%s-%s-%s", c.Account, c.PermissionSet, c.Principal)
			},
		}); err != nil {
			return fmt.Errorf("deploy assignments on %s: %w", scope, err)
		}

		count += len(perScope[scope])

		for i := range perScope[scope] {
			logger.InfoContext(goCtx, "created account assignment",
				slog.String("scope", scope),
				slog.String("group", perScope[scope][i].Principal),
				slog.String("permission_set", perScope[scope][i].PermissionSet),
			)
		}
	}

	logger.InfoContext(goCtx, "all account assignments deployed", slog.Int("count", count))

	return nil
}

// LegacyAccount is an account whose permission sets were made by hand.
type LegacyAccount struct {
	// ID is the account's id.
	ID string
	// Sets maps the NAME of an existing permission set to the groups it is
	// assigned to.
	Sets map[string][]string
}

// DeployLegacyAssignments assigns, on each legacy account, an Identity Center
// permission set that already exists (looked up by name, never managed) to
// directory groups, one AccountAssignments per account named
// "sso-legacy-assignments-<account>" with the children
// "legacy-assignment-<account>-<set name>-<principal>". The hand-made
// assignments beside these are left alone.
func DeployLegacyAssignments(
	ctx *pulumi.Context,
	logger *slog.Logger,
	instanceARN string,
	accounts map[string]LegacyAccount,
	groupIDs map[string]pulumi.StringOutput,
	displayName func(group string) string,
	provider pulumi.ProviderResource,
) error {
	goCtx := ctx.Context()

	names := make([]string, 0, len(accounts))
	for account := range accounts {
		names = append(names, account)
	}

	sort.Strings(names)

	var count int

	for _, account := range names {
		sets := make([]string, 0, len(accounts[account].Sets))
		for set := range accounts[account].Sets {
			sets = append(sets, set)
		}

		sort.Strings(sets)

		var assignments []Assignment

		for _, set := range sets {
			setARN, err := LookupPermissionSetARN(ctx, instanceARN, set, provider)
			if err != nil {
				return fmt.Errorf("grants.legacy_aws[%s][%s]: %w", account, set, err)
			}

			members := slices.Sorted(slices.Values(accounts[account].Sets[set]))
			members = slices.Compact(members)

			for _, group := range members {
				id, ok := groupIDs[group]
				if !ok {
					return fmt.Errorf("grants.legacy_aws[%s][%s]: %s is not an Identity Center group (partner directories are not synced)", account, set, group)
				}

				assignments = append(assignments, Assignment{
					Principal:        displayName(group),
					PrincipalID:      id,
					PermissionSet:    set,
					PermissionSetARN: pulumi.String(setARN),
				})

				logger.InfoContext(goCtx, "created legacy account assignment",
					slog.String("account", account),
					slog.String("group", group),
					slog.String("permission_set", set),
				)
			}
		}

		if len(assignments) == 0 {
			continue
		}

		if _, err := NewAccountAssignments(ctx, "sso-legacy-assignments-"+account, &AccountAssignmentsArgs{
			Account:        account,
			InstanceARN:    pulumi.String(instanceARN),
			TargetID:       pulumi.String(accounts[account].ID),
			Assignments:    assignments,
			Provider:       provider,
			LegacyTopLevel: true,
			Names: func(c AssignmentChild) string {
				return fmt.Sprintf("legacy-assignment-%s-%s-%s", c.Account, c.PermissionSet, c.Principal)
			},
		}); err != nil {
			return fmt.Errorf("deploy legacy assignments on %s: %w", account, err)
		}

		count += len(assignments)
	}

	logger.InfoContext(goCtx, "legacy account assignments deployed", slog.Int("count", count))

	return nil
}
