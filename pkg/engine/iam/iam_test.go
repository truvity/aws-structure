package iam_test

import (
	"sort"
	"strings"
	"sync"
	"testing"

	pulumiaws "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/engine/iam"
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

	out := args.Inputs.Copy()
	if args.TypeToken == "aws:iam/policy:Policy" {
		out["arn"] = resource.NewProperty("policy-arn-of-" + args.Name)
	}

	return args.Name + "-id", out, nil
}

func (*recorder) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return args.Args, nil
}

func full() *iam.Args {
	return &iam.Args{
		Account: "acct",
		PasswordPolicy: &registry.PasswordPolicy{
			MinimumLength: 14, MaxAgeDays: 90, ReusePrevention: 24,
			RequireSymbols: true, RequireNumbers: true, RequireUppercase: true, RequireLowercase: true,
		},
		Boundaries: []registry.Boundary{
			{Name: "bound-a", Document: `{"Version":"x"}`},
			{Name: "bound-b", Document: `{"Version":"y"}`},
		},
		AuditorRole: &iam.AuditorRole{
			Name:                "auditor",
			TrustedPrincipal:    "trusted-principal",
			ExternalID:          "ext-id",
			ManagedPolicies:     []string{"managed/ReadOnly"},
			Policy:              &iam.Policy{Name: "Extra", Document: `{"Version":"z"}`},
			PermissionsBoundary: pulumi.String("boundary-ref"),
		},
		LegacyTopLevel: true,
	}
}

func run(t *testing.T, args *iam.Args, noProvider bool, bpOpt ...bool) ([]registration, error) {
	t.Helper()

	rec := &recorder{}
	useBP := len(bpOpt) > 0 && bpOpt[0]

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		p, err := pulumiaws.NewProvider(ctx, "p", &pulumiaws.ProviderArgs{Region: pulumi.String("region-a")})
		if err != nil {
			return err
		}

		bp, err := pulumiaws.NewProvider(ctx, "bp", &pulumiaws.ProviderArgs{Region: pulumi.String("region-a")})
		if err != nil {
			return err
		}

		if !noProvider {
			args.Provider = p
		}

		if useBP {
			args.BoundaryProvider = bp
		}

		_, err = iam.New(ctx, "iam-acct", args)

		return err
	}, pulumi.WithMocks("proj", "stack", rec))

	return rec.regs, err
}

func children(regs []registration) []registration {
	var out []registration

	for _, r := range regs {
		if r.typ != "pulumi:providers:aws" && r.typ != iam.TypeToken && r.typ != "pulumi:pulumi:Stack" {
			out = append(out, r)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })

	return out
}

func names(regs []registration) string {
	var out []string
	for _, r := range regs {
		out = append(out, r.name)
	}

	return strings.Join(out, ",")
}

func TestDefaultNames(t *testing.T) {
	regs, err := run(t, full(), false)
	if err != nil {
		t.Fatal(err)
	}

	got := names(children(regs))
	want := strings.Join([]string{
		"iam-acct-auditor-managed-ReadOnly", "iam-acct-auditor-policy", "iam-acct-auditor-policy-attachment",
		"iam-acct-auditor-role", "iam-acct-boundary-bound-a", "iam-acct-boundary-bound-b", "iam-acct-password-policy",
	}, ",")

	if got != want {
		t.Fatalf("names\n got %s\nwant %s", got, want)
	}
}

func TestNamesHook(t *testing.T) {
	a := full()
	a.Names = func(c iam.Child) string {
		return string(c.Kind) + "/" + c.Account + "/" + c.Name
	}

	regs, err := run(t, a, false)
	if err != nil {
		t.Fatal(err)
	}

	got := names(children(regs))
	for _, w := range []string{
		"boundary/acct/bound-a", "password-policy/acct/", "auditor-role/acct/auditor",
		"auditor-managed-attachment/acct/managed/ReadOnly", "auditor-policy-attachment/acct/Extra",
	} {
		if !strings.Contains(got, w) {
			t.Errorf("names lack %q: %s", w, got)
		}
	}
}

func TestChildrenAreUnderTheComponentWithProviderAndAlias(t *testing.T) {
	regs, err := run(t, full(), false)
	if err != nil {
		t.Fatal(err)
	}

	cs := children(regs)
	if len(cs) != 7 {
		t.Fatalf("children = %d, want 7", len(cs))
	}

	for _, c := range cs {
		if !strings.Contains(c.parent, "iam-acct") {
			t.Errorf("%s: parent %q is not the component", c.name, c.parent)
		}

		if !c.noParentAlias {
			t.Errorf("%s: no noParent alias", c.name)
		}

		if c.protect {
			t.Errorf("%s: must not be protected", c.name)
		}

		if !strings.Contains(c.provider, "::p::") {
			t.Errorf("%s: provider %q is not p", c.name, c.provider)
		}
	}
}

func TestBoundaryProvider(t *testing.T) {
	a := full()
	regs, err := run(t, a, false, true)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range children(regs) {
		want := "::p::"
		if strings.Contains(c.name, "boundary") {
			want = "::bp::"
		}

		if !strings.Contains(c.provider, want) {
			t.Errorf("%s: provider %q, want %s", c.name, c.provider, want)
		}
	}
}

func TestWithoutLegacyTopLevelNoAlias(t *testing.T) {
	a := full()
	a.LegacyTopLevel = false

	regs, err := run(t, a, false)
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
	regs, err := run(t, full(), false)
	if err != nil {
		t.Fatal(err)
	}

	by := map[string]registration{}
	for _, c := range children(regs) {
		by[c.name] = c
	}

	pp := by["iam-acct-password-policy"].inputs
	if pp["minimumPasswordLength"].NumberValue() != 14 || pp["maxPasswordAge"].NumberValue() != 90 ||
		pp["passwordReusePrevention"].NumberValue() != 24 || !pp["requireSymbols"].BoolValue() ||
		!pp["requireNumbers"].BoolValue() || !pp["requireUppercaseCharacters"].BoolValue() ||
		!pp["requireLowercaseCharacters"].BoolValue() || !pp["allowUsersToChangePassword"].BoolValue() {
		t.Errorf("password policy inputs %v", pp)
	}

	b := by["iam-acct-boundary-bound-a"].inputs
	if b["name"].StringValue() != "bound-a" || b["policy"].StringValue() != `{"Version":"x"}` {
		t.Errorf("boundary inputs %v", b)
	}

	role := by["iam-acct-auditor-role"].inputs
	if role["name"].StringValue() != "auditor" || role["permissionsBoundary"].StringValue() != "boundary-ref" {
		t.Errorf("role inputs %v", role)
	}

	trust := role["assumeRolePolicy"].StringValue()
	for _, w := range []string{`"AWS": "trusted-principal"`, `"sts:ExternalId": "ext-id"`, `"Action": "sts:AssumeRole"`} {
		if !strings.Contains(trust, w) {
			t.Errorf("trust policy lacks %s:\n%s", w, trust)
		}
	}

	if got := by["iam-acct-auditor-managed-ReadOnly"].inputs["policyArn"].StringValue(); got != "managed/ReadOnly" {
		t.Errorf("managed attachment policyArn = %q", got)
	}

	if got := by["iam-acct-auditor-policy-attachment"].inputs["policyArn"].StringValue(); got != "policy-arn-of-iam-acct-auditor-policy" {
		t.Errorf("policy attachment policyArn = %q", got)
	}
}

func TestNoExternalIDNoCondition(t *testing.T) {
	a := full()
	a.AuditorRole.ExternalID = ""

	regs, err := run(t, a, false)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range children(regs) {
		if c.name == "iam-acct-auditor-role" && strings.Contains(c.inputs["assumeRolePolicy"].StringValue(), "Condition") {
			t.Errorf("unexpected condition: %s", c.inputs["assumeRolePolicy"].StringValue())
		}
	}
}

func TestPartsAreOptional(t *testing.T) {
	regs, err := run(t, &iam.Args{Account: "acct", Boundaries: []registry.Boundary{{Name: "b", Document: "{}"}}}, false)
	if err != nil {
		t.Fatal(err)
	}

	if got := names(children(regs)); got != "iam-acct-boundary-b" {
		t.Fatalf("names = %s", got)
	}
}

func TestRefusals(t *testing.T) {
	cases := map[string]struct {
		mutate     func(a *iam.Args)
		noProvider bool
		want       string
	}{
		"no account":      {func(a *iam.Args) { a.Account = "" }, false, "Account is empty"},
		"no provider":     {func(*iam.Args) {}, true, "Provider is nil"},
		"short password":  {func(a *iam.Args) { a.PasswordPolicy.MinimumLength = 3 }, false, "MinimumLength 3 is outside"},
		"old password":    {func(a *iam.Args) { a.PasswordPolicy.MaxAgeDays = 5000 }, false, "MaxAgeDays 5000 is outside"},
		"reuse":           {func(a *iam.Args) { a.PasswordPolicy.ReusePrevention = 25 }, false, "ReusePrevention 25 is outside"},
		"nameless bound":  {func(a *iam.Args) { a.Boundaries[0].Name = "" }, false, "Boundaries[0] has no name"},
		"dup boundary":    {func(a *iam.Args) { a.Boundaries[1].Name = "bound-a" }, false, `lists "bound-a" twice`},
		"boundary json":   {func(a *iam.Args) { a.Boundaries[0].Document = "nope" }, false, "document is not JSON"},
		"auditor name":    {func(a *iam.Args) { a.AuditorRole.Name = "" }, false, "AuditorRole.Name is empty"},
		"auditor trust":   {func(a *iam.Args) { a.AuditorRole.TrustedPrincipal = "" }, false, "TrustedPrincipal is empty"},
		"auditor no pb":   {func(a *iam.Args) { a.AuditorRole.PermissionsBoundary = nil }, false, "PermissionsBoundary is unset"},
		"auditor dup":     {func(a *iam.Args) { a.AuditorRole.ManagedPolicies = []string{"m", "m"} }, false, `lists "m" twice`},
		"auditor pol":     {func(a *iam.Args) { a.AuditorRole.Policy.Name = "" }, false, "Policy.Name is empty"},
		"auditor pol doc": {func(a *iam.Args) { a.AuditorRole.Policy.Document = "" }, false, "Policy.Document is not JSON"},
		"empty name":      {func(a *iam.Args) { a.Names = func(iam.Child) string { return "" } }, false, "empty name"},
		"repeated name":   {func(a *iam.Args) { a.Names = func(iam.Child) string { return "same" } }, false, `returned "same" for both`},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			a := full()
			tc.mutate(a)

			regs, err := run(t, a, tc.noProvider)
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
	a := full()
	a.Account = ""
	a.PasswordPolicy.MinimumLength = 1
	a.Boundaries[0].Document = "x"
	a.AuditorRole.TrustedPrincipal = ""

	_, err := run(t, a, true)
	if err == nil {
		t.Fatal("want error")
	}

	for _, w := range []string{"Account is empty", "Provider is nil", "MinimumLength", "not JSON", "TrustedPrincipal"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error lacks %q: %v", w, err)
		}
	}
}
