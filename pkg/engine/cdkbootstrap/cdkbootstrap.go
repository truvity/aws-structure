package cdkbootstrap

import (
	"errors"
	"fmt"
	"slices"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/cloudformation"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/cdkbootstrap"
)

// TypeToken is the Pulumi type of the component.
const TypeToken = "truvity:aws-structure:CDKBootstrap"

// Capability is the CloudFormation capability the stack is created with: its
// roles are named.
const Capability = "CAPABILITY_NAMED_IAM"

// Kind names which child a logical name is for.
type Kind string

// KindStack is the cloudformation.Stack of the bootstrap.
const KindStack Kind = "stack"

// Child identifies one child for a NameFunc.
type Child struct {
	// Component is the logical name the component was registered with.
	Component string
	Kind      Kind
	// Account is Args.Account.
	Account string
	// Region is Args.Region.
	Region string
	// Qualifier is the bootstrap's qualifier.
	Qualifier string
}

// NameFunc returns the Pulumi logical name of a child. It is part of the
// child's URN.
type NameFunc func(Child) string

// DefaultName names the stack "<c>-stack". This name is API.
func DefaultName(c Child) string { return c.Component + "-stack" }

// Args configures the component.
type Args struct {
	// Account is the account's name. Required; it only feeds Child.Account.
	Account string
	// Region is the region of Provider. Required; it only feeds Child.Region.
	Region string
	// Partition is the ARN partition, for the default execution policy.
	// Required.
	Partition string
	// Bootstrap is what to deploy. Required; Account and Region must be among
	// its Accounts and Regions.
	Bootstrap cdkbootstrap.Bootstrap
	// Provider is the AWS provider of the account in Region. Required.
	Provider pulumi.ProviderResource
	// DependsOn are the resources that must exist before the stack: the
	// account's boundary policies.
	DependsOn []pulumi.Resource

	// Names overrides the logical names of the children. Nil uses
	// DefaultName.
	Names NameFunc
}

// CDKBootstrap is the component.
type CDKBootstrap struct {
	pulumi.ResourceState

	// Stack is the CloudFormation stack.
	Stack *cloudformation.Stack
}

func (a *Args) name(component string) string {
	names := a.Names
	if names == nil {
		names = DefaultName
	}

	return names(Child{Component: component, Kind: KindStack, Account: a.Account, Region: a.Region, Qualifier: a.Bootstrap.Qualifier})
}

// Validate reports every problem with args at once, or returns nil.
func (a *Args) Validate() error {
	var errs []error

	if a.Account == "" {
		errs = append(errs, errors.New("args: Account is empty"))
	}

	if a.Region == "" {
		errs = append(errs, errors.New("args: Region is empty"))
	}

	if a.Partition == "" {
		errs = append(errs, errors.New("args: Partition is empty"))
	}

	if a.Provider == nil {
		errs = append(errs, errors.New("args: Provider is nil"))
	}

	if err := a.Bootstrap.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("args: Bootstrap: %w", err))
	}

	if a.Account != "" && !slices.Contains(a.Bootstrap.Accounts, a.Account) {
		errs = append(errs, fmt.Errorf("args: account %q is not in Bootstrap.Accounts %v", a.Account, a.Bootstrap.Accounts))
	}

	if a.Region != "" && !slices.Contains(a.Bootstrap.Regions, a.Region) {
		errs = append(errs, fmt.Errorf("args: region %q is not in Bootstrap.Regions %v", a.Region, a.Bootstrap.Regions))
	}

	return errors.Join(errs...)
}

// New registers the component and its stack. It returns an error, registering
// nothing, when args.Validate does, when Names returns an empty name, or when
// the template cannot be rendered.
func New(ctx *pulumi.Context, name string, args *Args, opts ...pulumi.ResourceOption) (*CDKBootstrap, error) {
	if args == nil {
		return nil, errors.New("cdkbootstrap: args is nil")
	}

	if err := args.Validate(); err != nil {
		return nil, fmt.Errorf("cdkbootstrap %s: %w", name, err)
	}

	child := args.name(name)
	if child == "" {
		return nil, fmt.Errorf("cdkbootstrap %s: Names returned an empty name", name)
	}

	template, err := cdkbootstrap.Render()
	if err != nil {
		return nil, fmt.Errorf("cdkbootstrap %s: %w", name, err)
	}

	comp := &CDKBootstrap{}
	if err := ctx.RegisterComponentResource(TypeToken, name, comp, opts...); err != nil {
		return nil, err
	}

	params := pulumi.StringMap{}
	for k, v := range args.Bootstrap.Parameters(args.Partition) {
		params[k] = pulumi.String(v)
	}

	stackOpts := []pulumi.ResourceOption{pulumi.Parent(comp), pulumi.Provider(args.Provider)}
	if len(args.DependsOn) > 0 {
		stackOpts = append(stackOpts, pulumi.DependsOn(args.DependsOn))
	}

	stack, err := cloudformation.NewStack(ctx, child, &cloudformation.StackArgs{
		Name:         pulumi.String(args.Bootstrap.StackName()),
		TemplateBody: pulumi.String(string(template)),
		Parameters:   params,
		Capabilities: pulumi.StringArray{pulumi.String(Capability)},
	}, stackOpts...)
	if err != nil {
		return nil, fmt.Errorf("create bootstrap stack %s in %s/%s: %w", args.Bootstrap.StackName(), args.Account, args.Region, err)
	}

	comp.Stack = stack

	if err := ctx.RegisterResourceOutputs(comp, pulumi.Map{}); err != nil {
		return nil, err
	}

	return comp, nil
}
