package baseline

import (
	"errors"
	"fmt"
	"sort"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/accessanalyzer"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/ebs"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/registry"
)

// TypeToken is the Pulumi type of the component.
const TypeToken = "truvity:aws-structure:AccountBaseline"

// Kind names which child a logical name is for.
type Kind string

const (
	// KindEBSEncryption is the ebs.EncryptionByDefault of one region.
	KindEBSEncryption Kind = "ebs-encryption"
	// KindAccessAnalyzer is the accessanalyzer.Analyzer of one region.
	KindAccessAnalyzer Kind = "access-analyzer"
)

// Child identifies one child for a NameFunc.
type Child struct {
	// Component is the logical name the component was registered with.
	Component string
	Kind      Kind
	// Account is Args.Account.
	Account string
	// Region is the region the child is created in.
	Region string
}

// NameFunc returns the Pulumi logical name of a child. The returned name must
// be unique among the component's children; it is part of the child's URN.
type NameFunc func(Child) string

// DefaultName names the children "<c>-ebs-<region>" and
// "<c>-analyzer-<region>". These names are API.
func DefaultName(c Child) string {
	if c.Kind == KindEBSEncryption {
		return c.Component + "-ebs-" + c.Region
	}

	return c.Component + "-analyzer-" + c.Region
}

// AnalyzerName is the name every Access Analyzer is created with.
const AnalyzerName = "account-analyzer"

// Args configures the component.
type Args struct {
	// Account is the account's name. Required; it only feeds Child.Account.
	Account string
	// Baseline is what the account carries. Only EBSDefaultEncryption,
	// Regions and AccessAnalyzer are implemented; PasswordPolicy,
	// AuditorRole and Boundaries must be unset or the component refuses.
	Baseline registry.Baseline
	// AnalyzerRegions are the regions of the Access Analyzers. Empty means
	// Baseline.Regions.
	AnalyzerRegions []string
	// Providers holds the AWS provider of the account for each region the
	// component creates something in. Required for every such region.
	Providers map[string]pulumi.ProviderResource

	// Names overrides the logical names of the children. Nil uses
	// DefaultName.
	Names NameFunc
	// LegacyTopLevel makes every child carry an alias from the URN it has
	// when it is registered directly under the stack (no parent), with the
	// same type and the name Names gives it. Set it when adopting resources
	// that were created before they were wrapped in this component.
	LegacyTopLevel bool
}

// AccountBaseline is the component.
type AccountBaseline struct {
	pulumi.ResourceState
}

func (a *Args) analyzerRegions() []string {
	if len(a.AnalyzerRegions) > 0 {
		return a.AnalyzerRegions
	}

	return a.Baseline.Regions
}

// plan lists every child the args register, in registration order.
func (a *Args) plan(component string) []Child {
	var out []Child

	if a.Baseline.EBSDefaultEncryption {
		for _, r := range a.Baseline.Regions {
			out = append(out, Child{Component: component, Kind: KindEBSEncryption, Account: a.Account, Region: r})
		}
	}

	if a.Baseline.AccessAnalyzer {
		for _, r := range a.analyzerRegions() {
			out = append(out, Child{Component: component, Kind: KindAccessAnalyzer, Account: a.Account, Region: r})
		}
	}

	return out
}

func checkRegions(field string, regions []string) []error {
	var errs []error

	seen := map[string]bool{}

	for _, r := range regions {
		switch {
		case r == "":
			errs = append(errs, fmt.Errorf("args: %s has an empty region", field))
		case seen[r]:
			errs = append(errs, fmt.Errorf("args: %s lists %q twice", field, r))
		}

		seen[r] = true
	}

	return errs
}

// Validate reports every problem with args at once, or returns nil.
func (a *Args) Validate() error {
	var errs []error

	if a.Account == "" {
		errs = append(errs, errors.New("args: Account is empty"))
	}

	b := a.Baseline
	if b.PasswordPolicy != nil {
		errs = append(errs, errors.New("args: Baseline.PasswordPolicy is not implemented by this component"))
	}

	if b.AuditorRole != nil {
		errs = append(errs, errors.New("args: Baseline.AuditorRole is not implemented by this component"))
	}

	if len(b.Boundaries) > 0 {
		errs = append(errs, errors.New("args: Baseline.Boundaries is not implemented by this component"))
	}

	if b.EBSDefaultEncryption && len(b.Regions) == 0 {
		errs = append(errs, errors.New("args: Baseline.EBSDefaultEncryption needs Baseline.Regions"))
	}

	if b.AccessAnalyzer && len(a.analyzerRegions()) == 0 {
		errs = append(errs, errors.New("args: Baseline.AccessAnalyzer needs AnalyzerRegions or Baseline.Regions"))
	}

	errs = append(errs, checkRegions("Baseline.Regions", b.Regions)...)
	errs = append(errs, checkRegions("AnalyzerRegions", a.AnalyzerRegions)...)

	need := map[string]bool{}

	for _, c := range a.plan("") {
		need[c.Region] = true
	}

	regions := make([]string, 0, len(need))
	for r := range need {
		regions = append(regions, r)
	}

	sort.Strings(regions)

	for _, r := range regions {
		if r != "" && a.Providers[r] == nil {
			errs = append(errs, fmt.Errorf("args: Providers has no provider for region %q", r))
		}
	}

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
			errs = append(errs, fmt.Errorf("args: Names returned an empty name for %s %s", c.Kind, c.Region))

			continue
		}

		if prev, dup := seen[n]; dup {
			errs = append(errs, fmt.Errorf("args: Names returned %q for both %s %s and %s %s", n, prev.Kind, prev.Region, c.Kind, c.Region))
		}

		seen[n] = c
	}

	return errs
}

// New registers the component and its children. It returns an error,
// registering nothing, when args.Validate does or when Names returns an empty
// or repeated name.
//
// The providers come from Args, not from pulumi.Providers.
func New(ctx *pulumi.Context, name string, args *Args, opts ...pulumi.ResourceOption) (*AccountBaseline, error) {
	if args == nil {
		return nil, errors.New("baseline: args is nil")
	}

	if err := args.Validate(); err != nil {
		return nil, fmt.Errorf("baseline %s: %w", name, err)
	}

	if err := errors.Join(args.checkNames(name)...); err != nil {
		return nil, fmt.Errorf("baseline %s: %w", name, err)
	}

	names := args.Names
	if names == nil {
		names = DefaultName
	}

	comp := &AccountBaseline{}
	if err := ctx.RegisterComponentResource(TypeToken, name, comp, opts...); err != nil {
		return nil, err
	}

	for _, c := range args.plan(name) {
		childOpts := []pulumi.ResourceOption{pulumi.Parent(comp), pulumi.Provider(args.Providers[c.Region])}
		if args.LegacyTopLevel {
			childOpts = append(childOpts, pulumi.Aliases([]pulumi.Alias{{NoParent: pulumi.Bool(true)}}))
		}

		switch c.Kind {
		case KindEBSEncryption:
			if _, err := ebs.NewEncryptionByDefault(ctx, names(c), &ebs.EncryptionByDefaultArgs{
				Enabled: pulumi.Bool(true),
			}, childOpts...); err != nil {
				return nil, fmt.Errorf("enable EBS encryption in %s/%s: %w", args.Account, c.Region, err)
			}
		case KindAccessAnalyzer:
			if _, err := accessanalyzer.NewAnalyzer(ctx, names(c), &accessanalyzer.AnalyzerArgs{
				AnalyzerName: pulumi.String(AnalyzerName),
				Type:         pulumi.String("ACCOUNT"),
			}, childOpts...); err != nil {
				return nil, fmt.Errorf("create Access Analyzer in %s/%s: %w", args.Account, c.Region, err)
			}
		}
	}

	if err := ctx.RegisterResourceOutputs(comp, pulumi.Map{}); err != nil {
		return nil, err
	}

	return comp, nil
}
