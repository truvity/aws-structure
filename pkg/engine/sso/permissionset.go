package sso

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/ssoadmin"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/registry"
)

// PermissionSetTypeToken is the Pulumi type of the permission set component.
const PermissionSetTypeToken = "truvity:aws-structure:PermissionSet"

// SetKind names which child a logical name is for.
type SetKind string

const (
	// SetKindSet is the permission set itself.
	SetKindSet SetKind = "set"
	// SetKindManagedPolicy is the attachment of one AWS-managed policy.
	SetKindManagedPolicy SetKind = "managed-policy"
	// SetKindInlinePolicy is the set's inline policy.
	SetKindInlinePolicy SetKind = "inline-policy"
	// SetKindBoundary is the set's permissions boundary attachment.
	SetKindBoundary SetKind = "boundary"
)

// SetChild identifies one child for a SetNameFunc.
type SetChild struct {
	// Component is the logical name the component was registered with.
	Component string
	Kind      SetKind
	// Name is the permission set's name (Args.Set.Name).
	Name string
	// Index is the position of the policy in Args.Set.ManagedPolicies for
	// SetKindManagedPolicy, and 0 for every other kind.
	Index int
}

// SetNameFunc returns the Pulumi logical name of a child. The returned name
// must be unique among the component's children; it is part of the child's
// URN.
type SetNameFunc func(SetChild) string

// DefaultSetName names a child "<c>-set", "<c>-managed-policy-<i>",
// "<c>-inline-policy" and "<c>-boundary". These names are API.
func DefaultSetName(c SetChild) string {
	switch c.Kind {
	case SetKindManagedPolicy:
		return fmt.Sprintf("%s-managed-policy-%d", c.Component, c.Index)
	default:
		return c.Component + "-" + string(c.Kind)
	}
}

var duration = regexp.MustCompile(`^PT([0-9]+H)?([0-9]+M)?$`)

// PermissionSetArgs configures the permission set component.
type PermissionSetArgs struct {
	// InstanceARN is the ARN of the Identity Center instance. Required.
	InstanceARN pulumi.StringInput

	// Set is the permission set. Name is required. SessionDuration and
	// Description are set on the resource only when non-empty. Includes is
	// not read: it is expanded into assignments by whoever builds
	// AccountAssignmentsArgs, never into the set.
	Set registry.PermissionSet

	// BoundaryPolicyName is the name of a customer managed policy used as the
	// permissions boundary of the set. The policy must exist, by that name,
	// in every account the set is assigned on. Empty attaches no boundary.
	BoundaryPolicyName string

	// Provider is the AWS provider of the region the instance lives in.
	// Required.
	Provider pulumi.ProviderResource

	// Names overrides the logical names of the children. Nil uses
	// DefaultSetName.
	Names SetNameFunc
	// LegacyTopLevel makes every child carry an alias from the URN it has
	// when it is registered directly under the stack (no parent), with the
	// same type and the name Names gives it. Set it when adopting resources
	// that were created before they were wrapped in this component.
	LegacyTopLevel bool
}

// PermissionSet is the component.
type PermissionSet struct {
	pulumi.ResourceState

	// Set is the permission set resource.
	Set *ssoadmin.PermissionSet
	// Arn is the ARN of the permission set.
	Arn pulumi.StringOutput
}

// Validate reports every problem with args at once, or returns nil.
func (a *PermissionSetArgs) Validate() error {
	var errs []error

	if a.InstanceARN == nil {
		errs = append(errs, errors.New("args: InstanceARN is unset"))
	}

	if a.Provider == nil {
		errs = append(errs, errors.New("args: Provider is nil"))
	}

	if a.Set.Name == "" {
		errs = append(errs, errors.New("args: Set.Name is empty"))
	}

	if d := a.Set.SessionDuration; d != "" && (!duration.MatchString(d) || d == "PT") {
		errs = append(errs, fmt.Errorf("args: Set.SessionDuration %q is not an ISO-8601 PT..H..M duration", d))
	}

	seen := map[string]bool{}

	for i, p := range a.Set.ManagedPolicies {
		switch {
		case p == "":
			errs = append(errs, fmt.Errorf("args: Set.ManagedPolicies[%d] is empty", i))
		case seen[p]:
			errs = append(errs, fmt.Errorf("args: Set.ManagedPolicies lists %q twice", p))
		}

		seen[p] = true
	}

	if p := a.Set.InlinePolicy; p != "" {
		if len(p) > registry.MaxInlinePolicyBytes {
			errs = append(errs, fmt.Errorf("args: Set.InlinePolicy is %d bytes, over the %d AWS allows",
				len(p), registry.MaxInlinePolicyBytes))
		}

		if !json.Valid([]byte(p)) {
			errs = append(errs, errors.New("args: Set.InlinePolicy is not valid JSON"))
		}
	}

	errs = append(errs, a.checkNames("")...)

	return errors.Join(errs...)
}

// children lists the children the args will create, in registration order.
func (a *PermissionSetArgs) children(component string) []SetChild {
	cs := []SetChild{{Component: component, Kind: SetKindSet, Name: a.Set.Name}}

	for i := range a.Set.ManagedPolicies {
		cs = append(cs, SetChild{Component: component, Kind: SetKindManagedPolicy, Name: a.Set.Name, Index: i})
	}

	if a.Set.InlinePolicy != "" {
		cs = append(cs, SetChild{Component: component, Kind: SetKindInlinePolicy, Name: a.Set.Name})
	}

	if a.BoundaryPolicyName != "" {
		cs = append(cs, SetChild{Component: component, Kind: SetKindBoundary, Name: a.Set.Name})
	}

	return cs
}

// checkNames refuses a naming hook that returns an empty or repeated name.
func (a *PermissionSetArgs) checkNames(component string) []error {
	names := a.Names
	if names == nil {
		names = DefaultSetName
	}

	var errs []error

	seen := map[string]SetChild{}

	for _, c := range a.children(component) {
		n := names(c)

		if n == "" {
			errs = append(errs, fmt.Errorf("args: Names returned an empty name for %s %d", c.Kind, c.Index))

			continue
		}

		if prev, dup := seen[n]; dup {
			errs = append(errs, fmt.Errorf("args: Names returned %q for both %s %d and %s %d",
				n, prev.Kind, prev.Index, c.Kind, c.Index))
		}

		seen[n] = c
	}

	return errs
}

// NewPermissionSet registers the component and its children. It returns an
// error, registering nothing, when args.Validate does or when Names returns an
// empty or repeated name.
//
// The provider comes from Args, not from pulumi.Providers.
func NewPermissionSet(ctx *pulumi.Context, name string, args *PermissionSetArgs, opts ...pulumi.ResourceOption) (*PermissionSet, error) {
	if args == nil {
		return nil, errors.New("sso: args is nil")
	}

	if err := args.Validate(); err != nil {
		return nil, fmt.Errorf("sso permission set %s: %w", name, err)
	}

	if err := errors.Join(args.checkNames(name)...); err != nil {
		return nil, fmt.Errorf("sso permission set %s: %w", name, err)
	}

	names := args.Names
	if names == nil {
		names = DefaultSetName
	}

	comp := &PermissionSet{}
	if err := ctx.RegisterComponentResource(PermissionSetTypeToken, name, comp, opts...); err != nil {
		return nil, err
	}

	child := func(k SetKind, i int) string {
		return names(SetChild{Component: name, Kind: k, Name: args.Set.Name, Index: i})
	}

	opt := func(extra ...pulumi.ResourceOption) []pulumi.ResourceOption {
		o := []pulumi.ResourceOption{pulumi.Parent(comp), pulumi.Provider(args.Provider)}
		if args.LegacyTopLevel {
			o = append(o, pulumi.Aliases([]pulumi.Alias{{NoParent: pulumi.Bool(true)}}))
		}

		return append(o, extra...)
	}

	setArgs := &ssoadmin.PermissionSetArgs{
		Name:        pulumi.String(args.Set.Name),
		InstanceArn: args.InstanceARN,
	}

	if args.Set.SessionDuration != "" {
		setArgs.SessionDuration = pulumi.String(args.Set.SessionDuration)
	}

	if args.Set.Description != "" {
		setArgs.Description = pulumi.String(args.Set.Description)
	}

	ps, err := ssoadmin.NewPermissionSet(ctx, child(SetKindSet, 0), setArgs,
		opt(pulumi.Protect(true), pulumi.RetainOnDelete(true))...)
	if err != nil {
		return nil, fmt.Errorf("create permission set %s: %w", args.Set.Name, err)
	}

	dep := pulumi.DependsOn([]pulumi.Resource{ps})

	for i, policy := range args.Set.ManagedPolicies {
		if _, err := ssoadmin.NewManagedPolicyAttachment(ctx, child(SetKindManagedPolicy, i), &ssoadmin.ManagedPolicyAttachmentArgs{
			InstanceArn:      args.InstanceARN,
			PermissionSetArn: ps.Arn,
			ManagedPolicyArn: pulumi.String(policy),
		}, opt(dep)...); err != nil {
			return nil, fmt.Errorf("attach managed policy %s to %s: %w", policy, args.Set.Name, err)
		}
	}

	if args.Set.InlinePolicy != "" {
		if _, err := ssoadmin.NewPermissionSetInlinePolicy(ctx, child(SetKindInlinePolicy, 0), &ssoadmin.PermissionSetInlinePolicyArgs{
			InstanceArn:      args.InstanceARN,
			PermissionSetArn: ps.Arn,
			InlinePolicy:     pulumi.String(args.Set.InlinePolicy),
		}, opt(dep)...); err != nil {
			return nil, fmt.Errorf("attach inline policy to %s: %w", args.Set.Name, err)
		}
	}

	if args.BoundaryPolicyName != "" {
		if _, err := ssoadmin.NewPermissionsBoundaryAttachment(ctx, child(SetKindBoundary, 0), &ssoadmin.PermissionsBoundaryAttachmentArgs{
			InstanceArn:      args.InstanceARN,
			PermissionSetArn: ps.Arn,
			PermissionsBoundary: &ssoadmin.PermissionsBoundaryAttachmentPermissionsBoundaryArgs{
				CustomerManagedPolicyReference: &ssoadmin.PermissionsBoundaryAttachmentPermissionsBoundaryCustomerManagedPolicyReferenceArgs{
					Name: pulumi.String(args.BoundaryPolicyName),
				},
			},
		}, opt(dep)...); err != nil {
			return nil, fmt.Errorf("attach boundary %s to %s: %w", args.BoundaryPolicyName, args.Set.Name, err)
		}
	}

	comp.Set = ps
	comp.Arn = ps.Arn

	if err := ctx.RegisterResourceOutputs(comp, pulumi.Map{"arn": ps.Arn}); err != nil {
		return nil, err
	}

	return comp, nil
}
