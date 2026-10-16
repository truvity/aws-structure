package sso_test

import (
	"slices"
	"strings"
	"testing"

	pulumiaws "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/engine/sso"
	"github.com/truvity/aws-structure/pkg/registry"
)

func bgRegistry() *registry.Registry {
	return &registry.Registry{
		Accounts: []registry.Account{
			{Name: "mgmt", ID: "id-mgmt", OU: registry.OURoot},
			{Name: "app", ID: "id-app", OU: "workloads"},
			{Name: "old", ID: "id-old", OU: "workloads", Closed: true},
			{Name: "planned", OU: "workloads"},
			{Name: "data", ID: "id-data", OU: "workloads"},
		},
		IdentityCenter: registry.IdentityCenter{
			BreakGlass: &registry.BreakGlass{Principal: "admins", PrincipalType: "group", PermissionSet: "admin"},
		},
	}
}

func runBreakGlass(t *testing.T, mutate func(*sso.BreakGlassArgs)) ([]string, []registration, error) {
	t.Helper()

	rec := &recorder{}

	var deployed []string

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		p, err := pulumiaws.NewProvider(ctx, "p", &pulumiaws.ProviderArgs{Region: pulumi.String("region-a")})
		if err != nil {
			return err
		}

		a := sso.BreakGlassArgs{
			Registry:         bgRegistry(),
			InstanceARN:      pulumi.String("instance-ref"),
			PrincipalID:      pulumi.String("g-admins"),
			PermissionSetARN: pulumi.String("ps-admin-ref"),
			Provider:         p,
		}
		if mutate != nil {
			mutate(&a)
		}

		deployed, err = sso.DeployBreakGlass(ctx, quiet(), a)

		return err
	}, pulumi.WithMocks("proj", "stack", rec))

	return deployed, rec.regs, err
}

func TestBreakGlassOpenAccountsOnly(t *testing.T) {
	deployed, regs, err := runBreakGlass(t, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Closed and id-less accounts are skipped; the root-OU account is not.
	if want := []string{"mgmt", "app", "data"}; !slices.Equal(deployed, want) {
		t.Fatalf("deployed = %v, want %v", deployed, want)
	}

	got := by(regs)

	var comps []string

	for i := range regs {
		if regs[i].typ == sso.AssignmentsTypeToken {
			comps = append(comps, regs[i].name)
		}
	}

	slices.Sort(comps)

	if want := []string{"sso-break-glass-app", "sso-break-glass-data", "sso-break-glass-mgmt"}; !slices.Equal(comps, want) {
		t.Errorf("components = %v, want %v", comps, want)
	}

	for _, n := range []string{
		"break-glass-mgmt-admin-admins", "break-glass-app-admin-admins", "break-glass-data-admin-admins",
	} {
		if _, ok := got[n]; !ok {
			t.Errorf("missing %s", n)
		}
	}

	for _, n := range []string{"old", "planned"} {
		for name := range got {
			if strings.Contains(name, "-"+n) {
				t.Errorf("%s must get no break-glass: %s", n, name)
			}
		}
	}

	in := got["break-glass-mgmt-admin-admins"].inputs
	if in["targetId"].StringValue() != "id-mgmt" || in["principalId"].StringValue() != "g-admins" ||
		in["permissionSetArn"].StringValue() != "ps-admin-ref" || in["principalType"].StringValue() != "GROUP" {
		t.Errorf("inputs = %v", in)
	}
}

func TestBreakGlassSkipAndNames(t *testing.T) {
	deployed, regs, err := runBreakGlass(t, func(a *sso.BreakGlassArgs) {
		a.Skip = func(acct string) bool { return acct == "app" }
		a.Names = func(c sso.AssignmentChild) string { return "bg-" + c.Account }
		a.LegacyTopLevel = true
		a.LegacyNames = map[string][]string{"data": {"older"}}
	})
	if err != nil {
		t.Fatal(err)
	}

	if want := []string{"mgmt", "data"}; !slices.Equal(deployed, want) {
		t.Fatalf("deployed = %v, want %v (app skipped)", deployed, want)
	}

	got := by(regs)
	if _, ok := got["bg-app"]; ok {
		t.Error("a skipped account got an assignment")
	}

	if _, ok := got["bg-data"]; !ok {
		t.Fatalf("names hook not used: %v", names(regs))
	}

	if a := got["bg-data"].aliases; !slices.Contains(a, "name=older noParent") {
		t.Errorf("aliases = %v, want the legacy name", a)
	}
}

func TestBreakGlassUserPrincipalName(t *testing.T) {
	_, regs, err := runBreakGlass(t, func(a *sso.BreakGlassArgs) {
		a.Registry.IdentityCenter.BreakGlass.PrincipalType = "user"
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := by(regs)["break-glass-app-admin-admins-user"]; !ok {
		t.Errorf("names = %v", names(regs))
	}
}

func TestBreakGlassRefusals(t *testing.T) {
	for name, mutate := range map[string]func(*sso.BreakGlassArgs){
		"no break glass": func(a *sso.BreakGlassArgs) { a.Registry.IdentityCenter.BreakGlass = nil },
		"no principal":   func(a *sso.BreakGlassArgs) { a.PrincipalID = nil },
		"no set":         func(a *sso.BreakGlassArgs) { a.PermissionSetARN = nil },
		"no instance":    func(a *sso.BreakGlassArgs) { a.InstanceARN = nil },
		"no provider":    func(a *sso.BreakGlassArgs) { a.Provider = nil },
		"empty name":     func(a *sso.BreakGlassArgs) { a.Names = func(sso.AssignmentChild) string { return "" } },
		"repeated name":  func(a *sso.BreakGlassArgs) { a.Names = func(sso.AssignmentChild) string { return "same" } },
	} {
		_, regs, err := runBreakGlass(t, mutate)
		if err == nil {
			t.Errorf("%s: not refused", name)
		}

		if len(children(regs)) != 0 {
			t.Errorf("%s: registered %v before refusing", name, names(regs))
		}
	}
}
