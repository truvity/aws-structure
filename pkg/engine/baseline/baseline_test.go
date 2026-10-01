package baseline_test

import (
	"sort"
	"strings"
	"sync"
	"testing"

	pulumiaws "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/engine/baseline"
	"github.com/truvity/aws-structure/pkg/registry"
)

type registration struct {
	typ, name, parent, provider string
	noParentAlias               bool
	protect                     bool
	inputs                      resource.PropertyMap
}

type recorder struct {
	mu   sync.Mutex
	regs []registration
}

func (r *recorder) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	reg := registration{typ: args.TypeToken, name: args.Name, inputs: args.Inputs}

	if rpc := args.RegisterRPC; rpc != nil {
		reg.parent = rpc.GetParent()
		reg.provider = rpc.GetProvider()
		reg.protect = rpc.GetProtect()

		for _, a := range rpc.GetAliases() {
			if spec := a.GetSpec(); spec != nil && spec.GetName() == "" && spec.GetNoParent() {
				reg.noParentAlias = true
			}
		}
	}

	r.mu.Lock()
	r.regs = append(r.regs, reg)
	r.mu.Unlock()

	return args.Name + "-id", args.Inputs.Copy(), nil
}

func (*recorder) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return args.Args, nil
}

var regions = []string{"region-a", "region-b", "region-c"}

func base() *baseline.Args {
	return &baseline.Args{
		Account: "acct",
		Baseline: registry.Baseline{
			EBSDefaultEncryption: true,
			Regions:              regions[:1],
			AccessAnalyzer:       true,
		},
		AnalyzerRegions: regions,
		LegacyTopLevel:  true,
	}
}

// legacy reproduces names an estate used before wrapping these in a component.
func legacy(c baseline.Child) string {
	if c.Kind == baseline.KindEBSEncryption {
		return "ebs-encryption-" + c.Account
	}

	return "access-analyzer-" + c.Account + "-" + c.Region
}

func run(t *testing.T, args *baseline.Args, drop ...string) ([]registration, error) {
	t.Helper()

	rec := &recorder{}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		args.Providers = map[string]pulumi.ProviderResource{}

		for _, r := range regions {
			p, err := pulumiaws.NewProvider(ctx, "p-"+r, &pulumiaws.ProviderArgs{Region: pulumi.String(r)})
			if err != nil {
				return err
			}

			args.Providers[r] = p
		}

		for _, r := range drop {
			delete(args.Providers, r)
		}

		_, err := baseline.New(ctx, "baseline-acct", args)

		return err
	}, pulumi.WithMocks("proj", "stack", rec))

	return rec.regs, err
}

func children(regs []registration) []registration {
	var out []registration

	for _, r := range regs {
		if r.typ != "pulumi:providers:aws" && r.typ != baseline.TypeToken && r.typ != "pulumi:pulumi:Stack" {
			out = append(out, r)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })

	return out
}

func names(regs []registration) []string {
	var out []string
	for _, r := range regs {
		out = append(out, r.name)
	}

	return out
}

func TestDefaultNames(t *testing.T) {
	regs, err := run(t, base())
	if err != nil {
		t.Fatal(err)
	}

	got := strings.Join(names(children(regs)), ",")
	want := "baseline-acct-analyzer-region-a,baseline-acct-analyzer-region-b,baseline-acct-analyzer-region-c,baseline-acct-ebs-region-a"

	if got != want {
		t.Fatalf("names\n got %s\nwant %s", got, want)
	}
}

func TestNamesHookReproducesLegacyNames(t *testing.T) {
	a := base()
	a.Names = legacy

	regs, err := run(t, a)
	if err != nil {
		t.Fatal(err)
	}

	got := strings.Join(names(children(regs)), ",")
	want := "access-analyzer-acct-region-a,access-analyzer-acct-region-b,access-analyzer-acct-region-c,ebs-encryption-acct"

	if got != want {
		t.Fatalf("names\n got %s\nwant %s", got, want)
	}
}

func TestChildrenAreUnderTheComponentWithItsRegionProviderAndAlias(t *testing.T) {
	regs, err := run(t, base())
	if err != nil {
		t.Fatal(err)
	}

	var comp registration

	for _, r := range regs {
		if r.typ == baseline.TypeToken {
			comp = r
		}
	}

	if comp.name != "baseline-acct" {
		t.Fatalf("component not registered: %+v", comp)
	}

	provs := map[string]string{}

	for _, r := range regs {
		if r.typ == "pulumi:providers:aws" {
			provs[r.name] = r.name
		}
	}

	if len(provs) != 3 {
		t.Fatalf("providers = %v", provs)
	}

	for _, c := range children(regs) {
		if !strings.Contains(c.parent, "baseline-acct") {
			t.Errorf("%s: parent %q is not the component", c.name, c.parent)
		}

		if !c.noParentAlias {
			t.Errorf("%s: no noParent alias", c.name)
		}

		if c.protect {
			t.Errorf("%s: must not be protected", c.name)
		}

		if c.provider == "" {
			t.Errorf("%s: no provider", c.name)
		}

		region := c.name[strings.LastIndex(c.name, "region-"):]
		if !strings.Contains(c.provider, "p-"+region) {
			t.Errorf("%s: provider %q is not the one of %s", c.name, c.provider, region)
		}
	}
}

func TestWithoutLegacyTopLevelNoAlias(t *testing.T) {
	a := base()
	a.LegacyTopLevel = false

	regs, err := run(t, a)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range children(regs) {
		if c.noParentAlias {
			t.Errorf("%s: unexpected alias", c.name)
		}
	}
}

func TestInputs(t *testing.T) {
	regs, err := run(t, base())
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range children(regs) {
		switch c.typ {
		case "aws:ebs/encryptionByDefault:EncryptionByDefault":
			if !c.inputs["enabled"].BoolValue() {
				t.Errorf("%s: not enabled", c.name)
			}
		case "aws:accessanalyzer/analyzer:Analyzer":
			if c.inputs["analyzerName"].StringValue() != "account-analyzer" || c.inputs["type"].StringValue() != "ACCOUNT" {
				t.Errorf("%s: inputs %v", c.name, c.inputs)
			}
		default:
			t.Errorf("unexpected child type %s", c.typ)
		}
	}
}

func TestAnalyzersFallBackToBaselineRegions(t *testing.T) {
	a := base()
	a.AnalyzerRegions = nil
	a.Baseline.Regions = regions[:2]

	regs, err := run(t, a)
	if err != nil {
		t.Fatal(err)
	}

	if n := len(children(regs)); n != 4 {
		t.Fatalf("children = %d, want 2 EBS + 2 analyzers", n)
	}
}

func TestTogglesOff(t *testing.T) {
	a := base()
	a.Baseline.AccessAnalyzer = false

	regs, err := run(t, a)
	if err != nil {
		t.Fatal(err)
	}

	if n := len(children(regs)); n != 1 {
		t.Fatalf("children = %d, want 1", n)
	}
}

func TestRefusals(t *testing.T) {
	cases := map[string]struct {
		mutate func(a *baseline.Args)
		drop   []string
		want   string
	}{
		"no account":     {func(a *baseline.Args) { a.Account = "" }, nil, "Account is empty"},
		"no provider":    {func(*baseline.Args) {}, []string{"region-b"}, `no provider for region "region-b"`},
		"password":       {func(a *baseline.Args) { a.Baseline.PasswordPolicy = &registry.PasswordPolicy{} }, nil, "PasswordPolicy is not implemented"},
		"auditor":        {func(a *baseline.Args) { a.Baseline.AuditorRole = &registry.AuditorRole{} }, nil, "AuditorRole is not implemented"},
		"boundaries":     {func(a *baseline.Args) { a.Baseline.Boundaries = []registry.Boundary{{Name: "x"}} }, nil, "Boundaries is not implemented"},
		"ebs no regions": {func(a *baseline.Args) { a.Baseline.Regions = nil }, nil, "EBSDefaultEncryption needs Baseline.Regions"},
		"dup region":     {func(a *baseline.Args) { a.AnalyzerRegions = []string{"region-a", "region-a"} }, nil, `lists "region-a" twice`},
		"empty name":     {func(a *baseline.Args) { a.Names = func(baseline.Child) string { return "" } }, nil, "empty name"},
		"repeated name":  {func(a *baseline.Args) { a.Names = func(baseline.Child) string { return "same" } }, nil, `returned "same" for both`},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			a := base()
			tc.mutate(a)

			regs, err := run(t, a, tc.drop...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}

			if n := len(children(regs)); n != 0 {
				t.Fatalf("registered %d children despite refusal", n)
			}
		})
	}
}

func TestRefusalReportsEveryProblemAtOnce(t *testing.T) {
	a := base()
	a.Account = ""
	a.Baseline.PasswordPolicy = &registry.PasswordPolicy{}
	a.Baseline.Boundaries = []registry.Boundary{{Name: "x"}}

	_, err := run(t, a, "region-b")
	if err == nil {
		t.Fatal("want error")
	}

	for _, w := range []string{"Account is empty", "PasswordPolicy", "Boundaries", "region-b"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error lacks %q: %v", w, err)
		}
	}
}
