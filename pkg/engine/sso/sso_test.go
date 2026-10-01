package sso_test

import (
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	pulumiaws "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/engine/sso"
	"github.com/truvity/aws-structure/pkg/registry"
)

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

	out := args.Inputs.Copy()
	out["arn"] = resource.NewProperty("ref-of-" + args.Name)

	return args.Name + "-id", out, nil
}

func (r *recorder) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	r.mu.Lock()
	r.calls = append(r.calls, args)
	r.mu.Unlock()

	out := args.Args.Copy()

	switch args.Token {
	case "aws:identitystore/getGroup:getGroup":
		name := args.Args["alternateIdentifier"].ObjectValue()["uniqueAttribute"].ObjectValue()["attributeValue"].StringValue()
		out["groupId"] = resource.NewProperty("id-of-" + name)
	case "aws:ssoadmin/getPermissionSet:getPermissionSet":
		out["arn"] = resource.NewProperty("ref-of-set-" + args.Args["name"].StringValue())
	}

	return out, nil
}

func children(regs []registration) []registration {
	var out []registration

	for i := range regs {
		if !strings.HasPrefix(regs[i].typ, "aws:ssoadmin/") {
			continue
		}

		out = append(out, regs[i])
	}

	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })

	return out
}

func names(regs []registration) []string {
	var out []string
	cs := children(regs)
	for i := range cs {
		out = append(out, cs[i].name)
	}

	return out
}

func by(regs []registration) map[string]registration {
	m := map[string]registration{}
	cs := children(regs)
	for i := range cs {
		m[cs[i].name] = cs[i]
	}

	return m
}

func fullSet() *sso.PermissionSetArgs {
	return &sso.PermissionSetArgs{
		InstanceARN: pulumi.String("instance-ref"),
		Set: registry.PermissionSet{
			Name:            "set-a",
			SessionDuration: "PT8H",
			ManagedPolicies: []string{"managed-ref-0", "managed-ref-1"},
		},
		BoundaryPolicyName: "boundary-a",
		LegacyTopLevel:     true,
	}
}

func runSet(t *testing.T, args *sso.PermissionSetArgs, noProvider bool) ([]registration, error) {
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

		_, err = sso.NewPermissionSet(ctx, "ps-a", args)

		return err
	}, pulumi.WithMocks("proj", "stack", rec))

	return rec.regs, err
}

func fullAssignments() *sso.AccountAssignmentsArgs {
	return &sso.AccountAssignmentsArgs{
		Account:     "acct",
		InstanceARN: pulumi.String("instance-ref"),
		TargetID:    pulumi.String("target-ref"),
		Assignments: []sso.Assignment{
			{
				Principal: "group-a", PrincipalID: pulumi.String("gid-a"),
				PermissionSet: "set-a", PermissionSetARN: pulumi.String("set-a-ref"),
				LegacyNames: []string{"older-name"},
			},
			{
				Principal: "person-a", PrincipalType: "user", PrincipalID: pulumi.String("uid-a"),
				PermissionSet: "set-b", PermissionSetARN: pulumi.String("set-b-ref"),
			},
		},
		LegacyTopLevel: true,
	}
}

func runAssignments(t *testing.T, args *sso.AccountAssignmentsArgs, noProvider bool) ([]registration, error) {
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

		_, err = sso.NewAccountAssignments(ctx, "as-acct", args)

		return err
	}, pulumi.WithMocks("proj", "stack", rec))

	return rec.regs, err
}

func TestSetDefaultNames(t *testing.T) {
	regs, err := runSet(t, fullSet(), false)
	if err != nil {
		t.Fatal(err)
	}

	want := "ps-a-boundary,ps-a-managed-policy-0,ps-a-managed-policy-1,ps-a-set"
	if got := strings.Join(names(regs), ","); got != want {
		t.Fatalf("names %s, want %s", got, want)
	}
}

func TestSetNamesHook(t *testing.T) {
	a := fullSet()
	a.Names = func(c sso.SetChild) string {
		if c.Kind == sso.SetKindManagedPolicy {
			return "x-" + c.Name + "-policy-" + string(rune('0'+c.Index))
		}

		return "x-" + c.Name + "-" + string(c.Kind)
	}

	regs, err := runSet(t, a, false)
	if err != nil {
		t.Fatal(err)
	}

	want := "x-set-a-boundary,x-set-a-policy-0,x-set-a-policy-1,x-set-a-set"
	if got := strings.Join(names(regs), ","); got != want {
		t.Fatalf("names %s, want %s", got, want)
	}
}

func TestSetProtectionAndDependencies(t *testing.T) {
	regs, err := runSet(t, fullSet(), false)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range children(regs) {
		if !strings.Contains(c.parent, "ps-a") {
			t.Errorf("%s: parent %q is not the component", c.name, c.parent)
		}

		if !slices.Equal(c.aliases, []string{"name= noParent"}) {
			t.Errorf("%s: aliases %v", c.name, c.aliases)
		}

		if !strings.Contains(c.provider, "::p::") {
			t.Errorf("%s: provider %q", c.name, c.provider)
		}

		isSet := c.name == "ps-a-set"
		if c.protect != isSet || c.retain != isSet {
			t.Errorf("%s: protect=%v retain=%v, want both %v", c.name, c.protect, c.retain, isSet)
		}

		if isSet != (len(c.dependsOn) == 0) {
			t.Errorf("%s: dependsOn %v", c.name, c.dependsOn)
		}

		if !isSet && !strings.HasSuffix(c.dependsOn[0], "::ps-a-set") {
			t.Errorf("%s: depends on %v, not the set", c.name, c.dependsOn)
		}
	}
}

func TestSetInputs(t *testing.T) {
	regs, err := runSet(t, fullSet(), false)
	if err != nil {
		t.Fatal(err)
	}

	m := by(regs)

	set := m["ps-a-set"].inputs
	if set["name"].StringValue() != "set-a" || set["sessionDuration"].StringValue() != "PT8H" ||
		set["instanceArn"].StringValue() != "instance-ref" {
		t.Errorf("set inputs %v", set)
	}

	if _, ok := set["description"]; ok {
		t.Errorf("an empty description must not be sent: %v", set)
	}

	for i, want := range []string{"managed-ref-0", "managed-ref-1"} {
		in := m["ps-a-managed-policy-"+string(rune('0'+i))].inputs
		if in["managedPolicyArn"].StringValue() != want || in["permissionSetArn"].StringValue() != "ref-of-ps-a-set" ||
			in["instanceArn"].StringValue() != "instance-ref" {
			t.Errorf("managed policy %d inputs %v", i, in)
		}
	}

	b := m["ps-a-boundary"].inputs["permissionsBoundary"].ObjectValue()["customerManagedPolicyReference"].ObjectValue()
	if b["name"].StringValue() != "boundary-a" {
		t.Errorf("boundary %v", b)
	}
}

func TestSetOptionalParts(t *testing.T) {
	a := fullSet()
	a.BoundaryPolicyName = ""
	a.Set.ManagedPolicies = nil
	a.Set.Description = "describes"
	a.Set.SessionDuration = ""
	a.Set.InlinePolicy = `{"Version":"x"}`
	a.LegacyTopLevel = false

	regs, err := runSet(t, a, false)
	if err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(names(regs), ","); got != "ps-a-inline-policy,ps-a-set" {
		t.Fatalf("names %s", got)
	}

	m := by(regs)

	if m["ps-a-inline-policy"].inputs["inlinePolicy"].StringValue() != `{"Version":"x"}` {
		t.Errorf("inline policy %v", m["ps-a-inline-policy"].inputs)
	}

	set := m["ps-a-set"].inputs
	if set["description"].StringValue() != "describes" {
		t.Errorf("description %v", set)
	}

	if _, ok := set["sessionDuration"]; ok {
		t.Errorf("an empty session duration must not be sent: %v", set)
	}

	for _, c := range children(regs) {
		if len(c.aliases) != 0 {
			t.Errorf("%s: unexpected aliases %v", c.name, c.aliases)
		}
	}
}

func TestSetRefusals(t *testing.T) {
	cases := map[string]struct {
		mutate     func(a *sso.PermissionSetArgs)
		noProvider bool
		want       string
	}{
		"no instance":   {func(a *sso.PermissionSetArgs) { a.InstanceARN = nil }, false, "InstanceARN is unset"},
		"no provider":   {func(*sso.PermissionSetArgs) {}, true, "Provider is nil"},
		"no name":       {func(a *sso.PermissionSetArgs) { a.Set.Name = "" }, false, "Set.Name is empty"},
		"bad duration":  {func(a *sso.PermissionSetArgs) { a.Set.SessionDuration = "8h" }, false, "not an ISO-8601"},
		"bare PT":       {func(a *sso.PermissionSetArgs) { a.Set.SessionDuration = "PT" }, false, "not an ISO-8601"},
		"empty policy":  {func(a *sso.PermissionSetArgs) { a.Set.ManagedPolicies = []string{""} }, false, "ManagedPolicies[0] is empty"},
		"repeat policy": {func(a *sso.PermissionSetArgs) { a.Set.ManagedPolicies = []string{"p", "p"} }, false, `lists "p" twice`},
		"inline not json": {
			func(a *sso.PermissionSetArgs) { a.Set.InlinePolicy = "{" }, false, "not valid JSON",
		},
		"inline too big": {
			func(a *sso.PermissionSetArgs) { a.Set.InlinePolicy = `"` + strings.Repeat("a", 10240) + `"` }, false, "over the",
		},
		"empty name": {func(a *sso.PermissionSetArgs) { a.Names = func(sso.SetChild) string { return "" } }, false, "empty name"},
		"repeated name": {
			func(a *sso.PermissionSetArgs) { a.Names = func(sso.SetChild) string { return "same" } }, false, `returned "same" for both`,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			a := fullSet()
			tc.mutate(a)

			regs, err := runSet(t, a, tc.noProvider)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}

			if n := len(children(regs)); n != 0 {
				t.Fatalf("registered %d children despite refusal", n)
			}
		})
	}
}

func TestSetRefusalReportsEveryProblemAtOnce(t *testing.T) {
	a := fullSet()
	a.InstanceARN = nil
	a.Set.Name = ""
	a.Set.SessionDuration = "x"
	a.Set.ManagedPolicies = []string{""}

	_, err := runSet(t, a, true)
	if err == nil {
		t.Fatal("want error")
	}

	for _, w := range []string{"InstanceARN", "Provider", "Set.Name", "SessionDuration", "ManagedPolicies[0]"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error lacks %q: %v", w, err)
		}
	}
}

func TestAssignmentsDefaultNamesAndInputs(t *testing.T) {
	regs, err := runAssignments(t, fullAssignments(), false)
	if err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(names(regs), ","); got != "as-acct-set-a-group-a,as-acct-set-b-person-a-user" {
		t.Fatalf("names %s", got)
	}

	m := by(regs)

	g := m["as-acct-set-a-group-a"].inputs
	if g["principalType"].StringValue() != "GROUP" || g["principalId"].StringValue() != "gid-a" ||
		g["permissionSetArn"].StringValue() != "set-a-ref" || g["targetId"].StringValue() != "target-ref" ||
		g["targetType"].StringValue() != "AWS_ACCOUNT" || g["instanceArn"].StringValue() != "instance-ref" {
		t.Errorf("group assignment inputs %v", g)
	}

	u := m["as-acct-set-b-person-a-user"].inputs
	if u["principalType"].StringValue() != "USER" || u["principalId"].StringValue() != "uid-a" {
		t.Errorf("user assignment inputs %v", u)
	}

	for _, c := range children(regs) {
		if c.protect || c.retain || len(c.dependsOn) != 0 {
			t.Errorf("%s: must be neither protected, retained nor ordered: %+v", c.name, c)
		}

		if !strings.Contains(c.parent, "as-acct") || !strings.Contains(c.provider, "::p::") {
			t.Errorf("%s: parent %q provider %q", c.name, c.parent, c.provider)
		}
	}
}

func TestAssignmentsAliases(t *testing.T) {
	regs, err := runAssignments(t, fullAssignments(), false)
	if err != nil {
		t.Fatal(err)
	}

	m := by(regs)

	if got := m["as-acct-set-a-group-a"].aliases; !slices.Equal(got, []string{"name= noParent", "name=older-name noParent"}) {
		t.Errorf("aliases %v", got)
	}

	if got := m["as-acct-set-b-person-a-user"].aliases; !slices.Equal(got, []string{"name= noParent"}) {
		t.Errorf("aliases %v", got)
	}

	a := fullAssignments()
	a.LegacyTopLevel = false

	regs, err = runAssignments(t, a, false)
	if err != nil {
		t.Fatal(err)
	}

	m = by(regs)

	if got := m["as-acct-set-a-group-a"].aliases; !slices.Equal(got, []string{"name=older-name"}) {
		t.Errorf("aliases without LegacyTopLevel: %v", got)
	}

	if got := m["as-acct-set-b-person-a-user"].aliases; len(got) != 0 {
		t.Errorf("aliases without LegacyTopLevel: %v", got)
	}
}

func TestAssignmentsNamesHookAndEmpty(t *testing.T) {
	a := fullAssignments()
	a.Names = func(c sso.AssignmentChild) string {
		return c.Account + "/" + c.PermissionSet + "/" + c.Principal + "/" + c.PrincipalType
	}

	regs, err := runAssignments(t, a, false)
	if err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(names(regs), ","); got != "acct/set-a/group-a/group,acct/set-b/person-a/user" {
		t.Fatalf("names %s", got)
	}

	a = fullAssignments()
	a.Assignments = nil

	regs, err = runAssignments(t, a, false)
	if err != nil || len(children(regs)) != 0 {
		t.Fatalf("no assignments: err %v, %d children", err, len(children(regs)))
	}
}

func TestAssignmentsRefusals(t *testing.T) {
	cases := map[string]struct {
		mutate     func(a *sso.AccountAssignmentsArgs)
		noProvider bool
		want       string
	}{
		"no account":   {func(a *sso.AccountAssignmentsArgs) { a.Account = "" }, false, "Account is empty"},
		"no instance":  {func(a *sso.AccountAssignmentsArgs) { a.InstanceARN = nil }, false, "InstanceARN is unset"},
		"no target":    {func(a *sso.AccountAssignmentsArgs) { a.TargetID = nil }, false, "TargetID is unset"},
		"no provider":  {func(*sso.AccountAssignmentsArgs) {}, true, "Provider is nil"},
		"no principal": {func(a *sso.AccountAssignmentsArgs) { a.Assignments[0].Principal = "" }, false, "Assignments[0]: Principal is empty"},
		"no principal id": {
			func(a *sso.AccountAssignmentsArgs) { a.Assignments[0].PrincipalID = nil }, false, "PrincipalID is unset",
		},
		"no set": {func(a *sso.AccountAssignmentsArgs) { a.Assignments[1].PermissionSet = "" }, false, "Assignments[1]: PermissionSet is empty"},
		"no set arn": {
			func(a *sso.AccountAssignmentsArgs) { a.Assignments[1].PermissionSetARN = nil }, false, "PermissionSetARN is unset",
		},
		"bad type": {func(a *sso.AccountAssignmentsArgs) { a.Assignments[0].PrincipalType = "robot" }, false, `PrincipalType "robot"`},
		"repeated": {
			func(a *sso.AccountAssignmentsArgs) { a.Assignments = append(a.Assignments, a.Assignments[0]) }, false, "twice",
		},
		"empty legacy name": {func(a *sso.AccountAssignmentsArgs) { a.Assignments[0].LegacyNames = []string{""} }, false, "LegacyNames[0] is empty"},
		"empty name":        {func(a *sso.AccountAssignmentsArgs) { a.Names = func(sso.AssignmentChild) string { return "" } }, false, "empty name"},
		"repeated name": {
			func(a *sso.AccountAssignmentsArgs) { a.Names = func(sso.AssignmentChild) string { return "same" } }, false, `returned "same" for both`,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			a := fullAssignments()
			tc.mutate(a)

			regs, err := runAssignments(t, a, tc.noProvider)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}

			if n := len(children(regs)); n != 0 {
				t.Fatalf("registered %d children despite refusal", n)
			}
		})
	}
}

func TestAssignmentsRefusalReportsEveryProblemAtOnce(t *testing.T) {
	a := fullAssignments()
	a.Account = ""
	a.InstanceARN = nil
	a.TargetID = nil
	a.Assignments[0].Principal = ""
	a.Assignments[1].PermissionSetARN = nil

	_, err := runAssignments(t, a, true)
	if err == nil {
		t.Fatal("want error")
	}

	for _, w := range []string{"Account", "InstanceARN", "TargetID", "Provider", "Assignments[0]: Principal", "Assignments[1]: PermissionSetARN"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error lacks %q: %v", w, err)
		}
	}
}

func TestLookups(t *testing.T) {
	rec := &recorder{}

	var gotIDs map[string]string

	var setARN string

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		p, err := pulumiaws.NewProvider(ctx, "p", &pulumiaws.ProviderArgs{Region: pulumi.String("region-a")})
		if err != nil {
			return err
		}

		ids, err := sso.LookupGroupIDs(ctx, "store-ref", []string{"b", "a", "b"}, p)
		if err != nil {
			return err
		}

		gotIDs = map[string]string{}

		for k, v := range ids {
			k := k

			v.ApplyT(func(s string) string { gotIDs[k] = s; return s })
		}

		setARN, err = sso.LookupPermissionSetARN(ctx, "instance-ref", "set-a", p)

		return err
	}, pulumi.WithMocks("proj", "stack", rec))
	if err != nil {
		t.Fatal(err)
	}

	if setARN != "ref-of-set-set-a" {
		t.Errorf("set ARN %q", setARN)
	}

	var groups []string

	for _, c := range rec.calls {
		if c.Token == "aws:identitystore/getGroup:getGroup" {
			if c.Args["identityStoreId"].StringValue() != "store-ref" || c.Provider == "" {
				t.Errorf("group lookup args %v provider %q", c.Args, c.Provider)
			}

			groups = append(groups, c.Args["alternateIdentifier"].ObjectValue()["uniqueAttribute"].ObjectValue()["attributeValue"].StringValue())
		}
	}

	if !slices.Equal(groups, []string{"a", "b"}) {
		t.Errorf("groups looked up %v, want a and b once each", groups)
	}
}

func TestLookupRefusals(t *testing.T) {
	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		if _, err := sso.LookupGroupIDs(ctx, "", []string{"a"}, nil); err == nil {
			t.Error("LookupGroupIDs: want error")
		}

		if _, err := sso.LookupGroupIDs(ctx, "store-ref", []string{"a"}, nil); err == nil {
			t.Error("LookupGroupIDs without provider: want error")
		}

		_, err := sso.LookupPermissionSetARN(ctx, "", "", nil)
		if err == nil {
			t.Fatal("LookupPermissionSetARN: want error")
		}

		for _, w := range []string{"instance ARN", "name", "provider"} {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("error lacks %q: %v", w, err)
			}
		}

		return nil
	}, pulumi.WithMocks("proj", "stack", &recorder{}))
	if err != nil {
		t.Fatal(err)
	}
}
