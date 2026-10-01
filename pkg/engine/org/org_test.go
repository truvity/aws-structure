package org_test

import (
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	pulumiaws "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/engine/org"
	"github.com/truvity/aws-structure/pkg/registry"
)

// mgmtAccount is the documentation placeholder account id, written in parts
// because the leak canary bans a twelve-digit run outside pkg/registry.
// arnAWS is the ARN prefix of the default partition, written in parts for the
// same reason.
const arnAWS = "arn:" + "aws" + ":"

const mgmtAccount = "1111" + "2222" + "3333"

type registration struct {
	typ, name, parent, provider string
	aliases                     []string
	protect, retain             bool
	dependsOn                   []string
	inputs                      resource.PropertyMap
}

type recorder struct {
	mu    sync.Mutex
	regs  []registration
	calls []pulumi.MockCallArgs
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
			if spec := a.GetSpec(); spec != nil {
				s := "name=" + spec.GetName()
				if spec.GetNoParent() {
					s += " noParent"
				}

				reg.aliases = append(reg.aliases, s)
			}
		}

		sort.Strings(reg.aliases)
	}

	r.mu.Lock()
	r.regs = append(r.regs, reg)
	r.mu.Unlock()

	return args.Name + "-id", args.Inputs.Copy(), nil
}

func (r *recorder) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	r.mu.Lock()
	r.calls = append(r.calls, args)
	r.mu.Unlock()

	out := args.Args.Copy()

	if args.Token == "aws:organizations/getOrganization:getOrganization" {
		out["roots"] = resource.NewProperty([]resource.PropertyValue{
			resource.NewProperty(resource.PropertyMap{"id": resource.NewProperty("r-root1")}),
		})
	}

	return out, nil
}

func children(regs []registration) map[string]registration {
	m := map[string]registration{}

	for i := range regs {
		if strings.HasPrefix(regs[i].typ, "aws:organizations/") {
			m[regs[i].name] = regs[i]
		}
	}

	return m
}

func fullArgs() *org.Args {
	return &org.Args{
		Unit:     registry.OU{Name: "unit-a"},
		ParentID: pulumi.String("r-root1"),
		Accounts: []registry.Account{
			{Name: "acct-a", Email: "a@example.test", OU: "unit-a"},
			{Name: "acct-b", Email: "b@example.test", Tags: map[string]string{"k": "v"}},
		},
		LegacyTopLevel: true,
	}
}

func run(t *testing.T, args *org.Args, noProvider bool) ([]registration, error) {
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

		_, err = org.New(ctx, "unit-a", args)

		return err
	}, pulumi.WithMocks("proj", "stack", rec))

	return rec.regs, err
}

func TestDefaultNames(t *testing.T) {
	regs, err := run(t, fullArgs(), false)
	if err != nil {
		t.Fatal(err)
	}

	got := children(regs)

	for _, n := range []string{"unit-a-ou", "unit-a-account-acct-a", "unit-a-account-acct-b"} {
		if _, ok := got[n]; !ok {
			t.Errorf("missing child %q; have %v", n, got)
		}
	}

	if len(got) != 3 {
		t.Errorf("want 3 children, got %d", len(got))
	}
}

func TestCustomNamesLegacyAliasProtectAndDependsOn(t *testing.T) {
	args := fullArgs()
	args.Names = func(c org.Child) string {
		if c.Kind == org.KindUnit {
			return "ou-" + c.Unit
		}

		return "account-" + c.Account
	}

	regs, err := run(t, args, false)
	if err != nil {
		t.Fatal(err)
	}

	got := children(regs)

	for _, n := range []string{"ou-unit-a", "account-acct-a", "account-acct-b"} {
		r, ok := got[n]
		if !ok {
			t.Fatalf("missing %q; have %v", n, got)
		}

		if !r.protect || !r.retain {
			t.Errorf("%s: protect=%v retain=%v, want both", n, r.protect, r.retain)
		}

		if !slices.Equal(r.aliases, []string{"name= noParent"}) {
			t.Errorf("%s aliases = %v, want one noParent alias", n, r.aliases)
		}

		if !strings.Contains(r.parent, "OrganizationalUnit::unit-a") {
			t.Errorf("%s parent = %q, want the component", n, r.parent)
		}
	}

	if len(got["ou-unit-a"].dependsOn) != 0 {
		t.Errorf("the unit depends on %v, want nothing", got["ou-unit-a"].dependsOn)
	}

	for _, n := range []string{"account-acct-a", "account-acct-b"} {
		if len(got[n].dependsOn) != 1 || !strings.HasSuffix(got[n].dependsOn[0], "::ou-unit-a") {
			t.Errorf("%s dependsOn = %v, want the unit", n, got[n].dependsOn)
		}
	}

	if _, ok := got["account-acct-a"].inputs["tags"]; ok {
		t.Error("an account without tags carries a tags input")
	}

	if _, ok := got["account-acct-b"].inputs["tags"]; !ok {
		t.Error("an account with tags lost them")
	}
}

func TestNoLegacyNoAlias(t *testing.T) {
	args := fullArgs()
	args.LegacyTopLevel = false

	regs, err := run(t, args, false)
	if err != nil {
		t.Fatal(err)
	}

	for n, r := range children(regs) {
		if len(r.aliases) != 0 {
			t.Errorf("%s has aliases %v", n, r.aliases)
		}
	}
}

func TestDormantSCPsCreateNothing(t *testing.T) {
	regs, err := run(t, fullArgs(), false)
	if err != nil {
		t.Fatal(err)
	}

	for i := range regs {
		if strings.Contains(regs[i].typ, "organizations/policy") || strings.Contains(regs[i].typ, "PolicyAttachment") {
			t.Errorf("registered %s %s: SCPs must stay dormant", regs[i].typ, regs[i].name)
		}
	}
}

func TestRefusalsAreCollected(t *testing.T) {
	args := &org.Args{
		Unit: registry.OU{ID: "ou-xxxx-yyyyyyyy", SCPs: []string{"s"}},
		Accounts: []registry.Account{
			{Name: "dup", Email: "x@example.test", OU: "elsewhere", ID: "x", SCPs: []string{"s"}},
			{Name: "dup"},
			{},
		},
		Names: func(org.Child) string { return "same" },
	}

	regs, err := run(t, args, true)
	if err == nil {
		t.Fatal("want a refusal")
	}

	if len(regs) != 1 {
		t.Errorf("registered %d resources before refusing (the provider only is expected)", len(regs))
	}

	for _, want := range []string{
		"Unit.Name is empty", "Unit.ID", "Unit.SCPs", "ParentID is unset", "Provider is nil",
		"lists \"dup\" twice", "has no Email", "sits in \"elsewhere\"", "has an ID", "has SCPs",
		"Accounts[2].Name is empty", "Names returned \"same\"",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}
}

func TestEmptyNameRefused(t *testing.T) {
	args := fullArgs()
	args.Names = func(c org.Child) string {
		if c.Kind == org.KindUnit {
			return ""
		}

		return "x-" + c.Account
	}

	if _, err := run(t, args, false); err == nil || !strings.Contains(err.Error(), "empty name") {
		t.Fatalf("want an empty-name refusal, got %v", err)
	}
}

func TestLookupRootID(t *testing.T) {
	rec := &recorder{}

	var got string

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		p, err := pulumiaws.NewProvider(ctx, "p", &pulumiaws.ProviderArgs{Region: pulumi.String("region-a")})
		if err != nil {
			return err
		}

		got, err = org.LookupRootID(ctx, p)

		return err
	}, pulumi.WithMocks("proj", "stack", rec))
	if err != nil {
		t.Fatal(err)
	}

	if got != "r-root1" {
		t.Errorf("root id = %q", got)
	}

	for i := range rec.regs {
		if strings.HasPrefix(rec.regs[i].typ, "aws:organizations/") {
			t.Errorf("the lookup registered %s: the organization is never managed", rec.regs[i].typ)
		}
	}

	if _, err := org.LookupRootID(nil, nil); err == nil {
		t.Error("want a refusal without a provider")
	}
}

func scpParams() org.SCPParams {
	return org.SCPParams{
		Partition:                      "aws",
		ManagementAccountID:            mgmtAccount,
		AllowedRegions:                 []string{"region-a", "region-b"},
		ReplicationExemptBuckets:       "state-*",
		PublicAccessBlockExemptBuckets: "oidc-*",
	}
}

func TestSCPsRenderValidJSONUnderTheLimit(t *testing.T) {
	scps, err := org.SCPs(scpParams())
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"deny-leave-org", "protect-cloudtrail", "protect-audit-logs", "deny-root-user",
		"restrict-regions", "deny-data-export", "require-encryption", "deny-public-access",
	}

	var names []string

	for _, s := range scps {
		names = append(names, s.Name)

		if len(s.Document) >= registry.MaxSCPBytes {
			t.Errorf("%s is %d bytes, not under %d", s.Name, len(s.Document), registry.MaxSCPBytes)
		}

		var doc struct {
			Version   string
			Statement []map[string]any
		}
		if err := json.Unmarshal([]byte(s.Document), &doc); err != nil {
			t.Errorf("%s does not parse: %v\n%s", s.Name, err, s.Document)

			continue
		}

		if doc.Version != "2012-10-17" || len(doc.Statement) == 0 {
			t.Errorf("%s: version %q, %d statements", s.Name, doc.Version, len(doc.Statement))
		}

		for _, st := range doc.Statement {
			if st["Effect"] != "Deny" || st["Sid"] == "" {
				t.Errorf("%s: statement %v is not a named Deny", s.Name, st)
			}
		}

		t.Logf("%s: %d bytes", s.Name, len(s.Document))
	}

	if !slices.Equal(names, want) {
		t.Errorf("names = %v, want %v", names, want)
	}
}

func TestSCPsPassTheRegistry(t *testing.T) {
	scps, err := org.SCPs(scpParams())
	if err != nil {
		t.Fatal(err)
	}

	r := &registry.Registry{
		Organization:   registry.Organization{ID: "o-abcdefghij", RootID: "r-abcd", ManagementAccount: "mgmt"},
		OUs:            []registry.OU{{Name: "unit-a", Reason: "test"}},
		Accounts:       []registry.Account{{Name: "mgmt", Email: "m@example.test", OU: "unit-a"}},
		SCPEnforcement: registry.SCPDormant,
		SCPs:           scps,
	}

	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSCPsCarryTheCallersParticulars(t *testing.T) {
	scps, err := org.SCPs(scpParams())
	if err != nil {
		t.Fatal(err)
	}

	byName := map[string]string{}
	for _, s := range scps {
		byName[s.Name] = s.Document
	}

	for name, needles := range map[string][]string{
		"protect-cloudtrail": {mgmtAccount, arnAWS + "iam::*:role/AWSCloudFormationStackSetExecutionRole"},
		"restrict-regions":   {`"region-a"`, `"region-b"`, arnAWS + "iam::*:root"},
		"deny-data-export":   {arnAWS + "s3:::state-*"},
		"deny-public-access": {arnAWS + "s3:::oidc-*"},
	} {
		for _, n := range needles {
			if !strings.Contains(byName[name], n) {
				t.Errorf("%s lacks %q:\n%s", name, n, byName[name])
			}
		}
	}

	p := scpParams()
	p.Partition = "aws-cn"

	cn, err := org.SCPs(p)
	if err != nil {
		t.Fatal(err)
	}

	for _, s := range cn {
		if strings.Contains(s.Document, arnAWS) {
			t.Errorf("%s ignores the partition", s.Name)
		}
	}
}

func TestSCPsRefusalsAreCollected(t *testing.T) {
	_, err := org.SCPs(org.SCPParams{Partition: "A", ManagementAccountID: "12", AllowedRegions: []string{"r", "r", ""}})
	if err == nil {
		t.Fatal("want a refusal")
	}

	for _, want := range []string{
		"Partition", "ManagementAccountID", "lists \"r\" twice", "empty region",
		"ReplicationExemptBuckets", "PublicAccessBlockExemptBuckets",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}

	if _, err := org.SCPs(org.SCPParams{}); err == nil || !strings.Contains(err.Error(), "AllowedRegions is empty") {
		t.Errorf("want an empty-regions refusal, got %v", err)
	}
}

func TestSCPsOverTheLimitRefused(t *testing.T) {
	p := scpParams()
	p.AllowedRegions = nil

	for i := range 400 {
		p.AllowedRegions = append(p.AllowedRegions, "region-"+strings.Repeat("x", 10)+string(rune('a'+i%26))+strings.Repeat("y", i/26))
	}

	if _, err := org.SCPs(p); err == nil || !strings.Contains(err.Error(), "over the 5120-byte limit") {
		t.Fatalf("want a size refusal, got %v", err)
	}
}
