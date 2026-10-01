package org

import (
	"errors"
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/organizations"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/registry"
)

// TypeToken is the Pulumi type of the component.
const TypeToken = "truvity:aws-structure:OrganizationalUnit"

// Kind names which child a logical name is for.
type Kind string

const (
	// KindUnit is the organizational unit itself.
	KindUnit Kind = "ou"
	// KindAccount is a member account of the unit.
	KindAccount Kind = "account"
)

// Child identifies one child for a NameFunc.
type Child struct {
	// Component is the logical name the component was registered with.
	Component string
	Kind      Kind
	// Unit is the name of the organizational unit (Args.Unit.Name).
	Unit string
	// Account is the account's name for KindAccount, and empty for KindUnit.
	Account string
}

// NameFunc returns the Pulumi logical name of a child. The returned name must
// be unique among the component's children; it is part of the child's URN.
type NameFunc func(Child) string

// DefaultName names the unit "<c>-ou" and an account "<c>-account-<name>".
// These names are API.
func DefaultName(c Child) string {
	if c.Kind == KindUnit {
		return c.Component + "-ou"
	}

	return c.Component + "-account-" + c.Account
}

// Args configures the component.
type Args struct {
	// Unit is the organizational unit. Name is required. Parent is not read:
	// the caller resolves it into ParentID. Reason is not read either. ID
	// and SCPs must be empty.
	Unit registry.OU

	// ParentID is the id of the unit's parent: the organization root's id
	// (see LookupRootID) or the id of another unit. Required.
	ParentID pulumi.StringInput

	// Accounts are the member accounts that sit in this unit. Name and Email
	// are required, and OU must be empty or equal Unit.Name. Tags are set on
	// the account only when non-empty. ID and SCPs must be empty, and
	// BaselineExempt is not read.
	Accounts []registry.Account

	// Provider is the AWS provider of the organization's management account.
	// Required.
	Provider pulumi.ProviderResource

	// Names overrides the logical names of the children. Nil uses
	// DefaultName.
	Names NameFunc
	// LegacyTopLevel makes every child carry an alias from the URN it has
	// when it is registered directly under the stack (no parent), with the
	// same type and the name Names gives it. Set it when adopting resources
	// that were created before they were wrapped in this component.
	LegacyTopLevel bool
}

// OrganizationalUnit is the component.
type OrganizationalUnit struct {
	pulumi.ResourceState

	// Unit is the organizational unit resource; its ID is the parent id of a
	// nested unit.
	Unit *organizations.OrganizationalUnit
	// Accounts are the member accounts by name.
	Accounts map[string]*organizations.Account
}

// Validate reports every problem with args at once, or returns nil.
func (a *Args) Validate() error {
	var errs []error

	if a.Unit.Name == "" {
		errs = append(errs, errors.New("args: Unit.Name is empty"))
	}

	if a.Unit.ID != "" {
		errs = append(errs, fmt.Errorf("args: Unit.ID %q is set: adopting a unit by id is not built", a.Unit.ID))
	}

	if len(a.Unit.SCPs) > 0 {
		errs = append(errs, errors.New("args: Unit.SCPs is set: SCPs are dormant and attach to nothing"))
	}

	if a.ParentID == nil {
		errs = append(errs, errors.New("args: ParentID is unset"))
	}

	if a.Provider == nil {
		errs = append(errs, errors.New("args: Provider is nil"))
	}

	seen := map[string]bool{}

	for i := range a.Accounts {
		acct := &a.Accounts[i]

		switch {
		case acct.Name == "":
			errs = append(errs, fmt.Errorf("args: Accounts[%d].Name is empty", i))
		case seen[acct.Name]:
			errs = append(errs, fmt.Errorf("args: Accounts lists %q twice", acct.Name))
		}

		seen[acct.Name] = true

		if acct.Email == "" {
			errs = append(errs, fmt.Errorf("args: account %q has no Email", acct.Name))
		}

		if acct.OU != "" && acct.OU != a.Unit.Name {
			errs = append(errs, fmt.Errorf("args: account %q sits in %q, not in unit %q", acct.Name, acct.OU, a.Unit.Name))
		}

		if acct.ID != "" {
			errs = append(errs, fmt.Errorf("args: account %q has an ID: adopting an account by id is not built", acct.Name))
		}

		if len(acct.SCPs) > 0 {
			errs = append(errs, fmt.Errorf("args: account %q has SCPs: SCPs are dormant and attach to nothing", acct.Name))
		}
	}

	errs = append(errs, a.checkNames("")...)

	return errors.Join(errs...)
}

// children lists the children the args will create, in registration order.
func (a *Args) children(component string) []Child {
	cs := []Child{{Component: component, Kind: KindUnit, Unit: a.Unit.Name}}

	for i := range a.Accounts {
		cs = append(cs, Child{Component: component, Kind: KindAccount, Unit: a.Unit.Name, Account: a.Accounts[i].Name})
	}

	return cs
}

// checkNames refuses a naming hook that returns an empty or repeated name.
func (a *Args) checkNames(component string) []error {
	names := a.Names
	if names == nil {
		names = DefaultName
	}

	var errs []error

	seen := map[string]Child{}

	for _, c := range a.children(component) {
		n := names(c)

		if n == "" {
			errs = append(errs, fmt.Errorf("args: Names returned an empty name for %s %q", c.Kind, c.Account))

			continue
		}

		if prev, dup := seen[n]; dup {
			errs = append(errs, fmt.Errorf("args: Names returned %q for both %s %q and %s %q",
				n, prev.Kind, prev.Account, c.Kind, c.Account))
		}

		seen[n] = c
	}

	return errs
}

// LookupRootID reads the organization and returns the id of its root, the
// parent of a top-level unit. The organization is only read, never managed.
func LookupRootID(ctx *pulumi.Context, provider pulumi.ProviderResource) (string, error) {
	if provider == nil {
		return "", errors.New("org: provider is nil")
	}

	o, err := organizations.LookupOrganization(ctx, nil, pulumi.Provider(provider))
	if err != nil {
		return "", fmt.Errorf("lookup organization: %w", err)
	}

	if len(o.Roots) == 0 {
		return "", errors.New("organization has no roots")
	}

	return o.Roots[0].Id, nil
}

// New registers the component and its children. It returns an error,
// registering nothing, when args.Validate does or when Names returns an empty
// or repeated name.
//
// The provider comes from Args, not from pulumi.Providers.
func New(ctx *pulumi.Context, name string, args *Args, opts ...pulumi.ResourceOption) (*OrganizationalUnit, error) {
	if args == nil {
		return nil, errors.New("org: args is nil")
	}

	if err := args.Validate(); err != nil {
		return nil, fmt.Errorf("org %s: %w", name, err)
	}

	if err := errors.Join(args.checkNames(name)...); err != nil {
		return nil, fmt.Errorf("org %s: %w", name, err)
	}

	names := args.Names
	if names == nil {
		names = DefaultName
	}

	comp := &OrganizationalUnit{Accounts: make(map[string]*organizations.Account, len(args.Accounts))}
	if err := ctx.RegisterComponentResource(TypeToken, name, comp, opts...); err != nil {
		return nil, err
	}

	opt := func(extra ...pulumi.ResourceOption) []pulumi.ResourceOption {
		o := []pulumi.ResourceOption{
			pulumi.Parent(comp), pulumi.Provider(args.Provider),
			pulumi.Protect(true), pulumi.RetainOnDelete(true),
		}
		if args.LegacyTopLevel {
			o = append(o, pulumi.Aliases([]pulumi.Alias{{NoParent: pulumi.Bool(true)}}))
		}

		return append(o, extra...)
	}

	ou, err := organizations.NewOrganizationalUnit(ctx,
		names(Child{Component: name, Kind: KindUnit, Unit: args.Unit.Name}),
		&organizations.OrganizationalUnitArgs{
			Name:     pulumi.String(args.Unit.Name),
			ParentId: args.ParentID,
		}, opt()...)
	if err != nil {
		return nil, fmt.Errorf("create OU %s: %w", args.Unit.Name, err)
	}

	comp.Unit = ou

	for i := range args.Accounts {
		acct := &args.Accounts[i]

		accountArgs := &organizations.AccountArgs{
			Name:     pulumi.String(acct.Name),
			Email:    pulumi.String(acct.Email),
			ParentId: ou.ID(),
		}

		if len(acct.Tags) > 0 {
			tags := make(pulumi.StringMap, len(acct.Tags))
			for k, v := range acct.Tags {
				tags[k] = pulumi.String(v)
			}

			accountArgs.Tags = tags
		}

		account, err := organizations.NewAccount(ctx,
			names(Child{Component: name, Kind: KindAccount, Unit: args.Unit.Name, Account: acct.Name}),
			accountArgs, opt(pulumi.DependsOn([]pulumi.Resource{ou}))...)
		if err != nil {
			return nil, fmt.Errorf("create account %s: %w", acct.Name, err)
		}

		comp.Accounts[acct.Name] = account
	}

	if err := ctx.RegisterResourceOutputs(comp, pulumi.Map{"unitId": ou.ID()}); err != nil {
		return nil, err
	}

	return comp, nil
}
