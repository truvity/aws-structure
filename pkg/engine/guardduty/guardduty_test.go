package guardduty_test

import (
	"sort"
	"strings"
	"sync"
	"testing"

	pulumiaws "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/engine/guardduty"
)

type registration struct {
	typ, name, parent, provider string
	noParentAlias               bool
	protect, retain             bool
	dependsOn                   []string
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
		reg.retain = rpc.GetRetainOnDelete()
		reg.dependsOn = rpc.GetDependencies()

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
	out["arn"] = resource.NewProperty("ref-of-" + args.Name)

	return args.Name + "-id", out, nil
}

func (*recorder) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return args.Args, nil
}

func full() *guardduty.Args {
	return &guardduty.Args{
		Account:             "acct",
		Region:              "region-a",
		SNSTopicARN:         pulumi.String("topic-ref"),
		PermissionsBoundary: pulumi.String("boundary-ref"),
		LegacyTopLevel:      true,
	}
}

func run(t *testing.T, args *guardduty.Args, noProvider bool) ([]registration, error) {
	t.Helper()

	rec := &recorder{}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		p, err := pulumiaws.NewProvider(ctx, "p", &pulumiaws.ProviderArgs{Region: pulumi.String("region-a")})
		if err != nil {
			return err
		}

		if !noProvider {
			args.Provider = p
		}

		_, err = guardduty.New(ctx, "gd-acct-region-a", args)

		return err
	}, pulumi.WithMocks("proj", "stack", rec))

	return rec.regs, err
}

func children(regs []registration) []registration {
	var out []registration

	for _, r := range regs {
		if r.typ != "pulumi:providers:aws" && r.typ != guardduty.TypeToken && r.typ != "pulumi:pulumi:Stack" {
			out = append(out, r)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })

	return out
}

func by(regs []registration) map[string]registration {
	m := map[string]registration{}
	for _, c := range children(regs) {
		m[c.name] = c
	}

	return m
}

func TestDefaultNames(t *testing.T) {
	regs, err := run(t, full(), false)
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	for _, c := range children(regs) {
		got = append(got, strings.TrimPrefix(c.name, "gd-acct-region-a-"))
	}

	want := "detector,eventbridge-policy,eventbridge-role,rule,target"
	if strings.Join(got, ",") != want {
		t.Fatalf("names %v, want %s", got, want)
	}
}

func TestNamesHook(t *testing.T) {
	a := full()
	a.Names = func(c guardduty.Child) string { return string(c.Kind) + "/" + c.Account + "/" + c.Region }

	regs, err := run(t, a, false)
	if err != nil {
		t.Fatal(err)
	}

	m := by(regs)
	if len(m) != 5 {
		t.Fatalf("children = %d, want 5", len(m))
	}

	for _, w := range []string{"detector/acct/region-a", "target/acct/region-a"} {
		if _, ok := m[w]; !ok {
			t.Errorf("no child %q", w)
		}
	}
}

func TestChildrenAreUnderTheComponentWithProviderAndAlias(t *testing.T) {
	regs, err := run(t, full(), false)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range children(regs) {
		if !strings.Contains(c.parent, "gd-acct-region-a") {
			t.Errorf("%s: parent %q is not the component", c.name, c.parent)
		}

		if !c.noParentAlias {
			t.Errorf("%s: no noParent alias", c.name)
		}

		if c.protect || c.retain {
			t.Errorf("%s: must be neither protected nor retained", c.name)
		}

		if !strings.Contains(c.provider, "::p::") {
			t.Errorf("%s: provider %q", c.name, c.provider)
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

	m := by(regs)

	if !m["gd-acct-region-a-detector"].inputs["enable"].BoolValue() {
		t.Errorf("detector not enabled")
	}

	role := m["gd-acct-region-a-eventbridge-role"].inputs
	if role["name"].StringValue() != "eventbridge-sns-region-a" || role["permissionsBoundary"].StringValue() != "boundary-ref" {
		t.Errorf("role inputs %v", role)
	}

	wantTrust := `{"Version":"2012-10-17","Statement":[{"Sid":"EventBridgeAssume","Effect":"Allow",` +
		`"Principal":{"Service":"events.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
	if got := role["assumeRolePolicy"].StringValue(); got != wantTrust {
		t.Errorf("trust policy %s", got)
	}

	pol := m["gd-acct-region-a-eventbridge-policy"].inputs
	wantPol := `{"Version":"2012-10-17","Statement":[{"Sid":"AllowSNSPublish","Effect":"Allow",` +
		`"Action":"sns:Publish","Resource":"topic-ref"}]}`

	if pol["name"].StringValue() != "sns-publish" || pol["policy"].StringValue() != wantPol {
		t.Errorf("role policy %v", pol)
	}

	rule := m["gd-acct-region-a-rule"].inputs
	if rule["name"].StringValue() != "guardduty-findings-region-a" ||
		rule["eventPattern"].StringValue() != `{"source":["aws.guardduty"],"detail-type":["GuardDuty Finding"]}` {
		t.Errorf("rule inputs %v", rule)
	}

	target := m["gd-acct-region-a-target"].inputs
	if target["arn"].StringValue() != "topic-ref" || target["targetId"].StringValue() != "security-alerts-sns" ||
		target["roleArn"].StringValue() != "ref-of-gd-acct-region-a-eventbridge-role" {
		t.Errorf("target inputs %v", target)
	}
}

func TestFindingPublishingFrequency(t *testing.T) {
	regs, err := run(t, full(), false)
	if err != nil {
		t.Fatal(err)
	}

	if _, set := by(regs)["gd-acct-region-a-detector"].inputs["findingPublishingFrequency"]; set {
		t.Error("frequency set although the arg is empty")
	}

	a := full()
	a.FindingPublishingFrequency = "FIFTEEN_MINUTES"

	regs, err = run(t, a, false)
	if err != nil {
		t.Fatal(err)
	}

	if got := by(regs)["gd-acct-region-a-detector"].inputs["findingPublishingFrequency"].StringValue(); got != "FIFTEEN_MINUTES" {
		t.Errorf("frequency = %q", got)
	}

	a = full()
	a.FindingPublishingFrequency = "EVERY_SECOND"

	if _, err = run(t, a, false); err == nil || !strings.Contains(err.Error(), "FindingPublishingFrequency") {
		t.Errorf("err = %v, want a FindingPublishingFrequency refusal", err)
	}
}

func TestRefusals(t *testing.T) {
	cases := map[string]struct {
		mutate     func(a *guardduty.Args)
		noProvider bool
		want       string
	}{
		"no account":    {func(a *guardduty.Args) { a.Account = "" }, false, "Account is empty"},
		"no region":     {func(a *guardduty.Args) { a.Region = "" }, false, "Region is empty"},
		"no provider":   {func(*guardduty.Args) {}, true, "Provider is nil"},
		"no topic":      {func(a *guardduty.Args) { a.SNSTopicARN = nil }, false, "SNSTopicARN is unset"},
		"no boundary":   {func(a *guardduty.Args) { a.PermissionsBoundary = nil }, false, "PermissionsBoundary is unset"},
		"empty name":    {func(a *guardduty.Args) { a.Names = func(guardduty.Child) string { return "" } }, false, "empty name"},
		"repeated name": {func(a *guardduty.Args) { a.Names = func(guardduty.Child) string { return "same" } }, false, `returned "same" for both`},
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
	a.Region = ""
	a.SNSTopicARN = nil
	a.PermissionsBoundary = nil

	_, err := run(t, a, true)
	if err == nil {
		t.Fatal("want error")
	}

	for _, w := range []string{
		"Account is empty", "Region is empty", "Provider is nil", "SNSTopicARN", "PermissionsBoundary",
	} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error lacks %q: %v", w, err)
		}
	}
}
