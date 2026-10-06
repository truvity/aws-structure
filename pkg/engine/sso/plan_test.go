package sso_test

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	pulumiaws "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/engine/sso"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func specs() map[string]*sso.SetSpec {
	return map[string]*sso.SetSpec{
		"viewer": {Key: "viewer", Name: "role-viewer", SessionDuration: "PT12H", ManagedPolicies: []string{"managed-ref"}},
		"admin": {
			Key: "admin", Name: "role-admin", SessionDuration: "PT4H", ManagedPolicies: []string{"managed-ref"},
			BoundaryPolicyName: "boundary-a", Includes: []string{"viewer"},
		},
		"power": {Key: "power", Name: "role-power", SessionDuration: "PT4H", ManagedPolicies: []string{"managed-ref"}},
	}
}

func TestEffectiveIsOneLevelDeep(t *testing.T) {
	sets := specs()
	sets["viewer"].Includes = []string{"power"}

	got, err := sso.Effective(sets, "admin")
	if err != nil || len(got) != 2 || got[0].Key != "admin" || got[1].Key != "viewer" {
		t.Fatalf("effective(admin) = %v, %v: the set and its direct includes only", got, err)
	}

	if _, err := sso.Effective(sets, "missing"); err == nil {
		t.Fatal("an unknown key must be refused")
	}

	sets["admin"].Includes = []string{"ghost"}

	if _, err := sso.Effective(sets, "admin"); err == nil || !strings.Contains(err.Error(), "included permission set not found") {
		t.Fatalf("an unknown include must be refused: %v", err)
	}
}

func deployAll(t *testing.T, grants []sso.Grant, aliases map[string]string) ([]registration, error) {
	t.Helper()

	rec := &recorder{}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		p, err := pulumiaws.NewProvider(ctx, "p", &pulumiaws.ProviderArgs{Region: pulumi.String("region-a")})
		if err != nil {
			return err
		}

		deployed, err := sso.DeploySets(ctx, quiet(), pulumi.String("instance-ref"), specs(), p)
		if err != nil {
			return err
		}

		return sso.DeployAssignments(ctx, quiet(), sso.PlanArgs{
			InstanceARN:    pulumi.String("instance-ref"),
			Provider:       p,
			Sets:           specs(),
			Deployed:       deployed,
			Grants:         grants,
			Aliases:        aliases,
			RoleFirstGroup: map[string]string{"ops": "ops@example.test"},
			AccountIDs:     map[string]pulumi.StringInput{"acct-a": pulumi.String("id-a"), "acct-b": pulumi.String("id-b")},
			GroupIDs: map[string]pulumi.StringOutput{
				"ops@example.test": pulumi.String("g-ops").ToStringOutput(),
				"dev@example.test": pulumi.String("g-dev").ToStringOutput(),
			},
			DisplayName: func(g string) string { return strings.TrimSuffix(g, "@example.test") },
		})
	}, pulumi.WithMocks("proj", "stack", rec))

	return rec.regs, err
}

func TestDeploySetsAndAssignmentsNames(t *testing.T) {
	regs, err := deployAll(t, []sso.Grant{
		// The same identity through two roles collapses into one resource.
		{Scope: "acct-a", Set: "role-admin", Group: "ops@example.test", Role: "ops"},
		{Scope: "acct-a", Set: "role-admin", Group: "ops@example.test", Role: "other"},
		{Scope: "acct-b", Set: "role-viewer", Group: "dev@example.test", Role: "dev"},
	}, map[string]string{"role-admin": "power"})
	if err != nil {
		t.Fatal(err)
	}

	got := by(regs)

	for _, name := range []string{
		"ps-admin", "ps-admin-policy-0", "ps-admin-boundary", "ps-viewer", "ps-power",
		// admin includes viewer, and the alias adds power: three identities on a.
		"assignment-acct-a-role-admin-ops", "assignment-acct-a-role-viewer-ops", "assignment-acct-a-role-power-ops",
		"assignment-acct-b-role-viewer-dev",
	} {
		if _, ok := got[name]; !ok {
			t.Errorf("missing %s", name)
		}
	}

	// The ops role's first group is ops: the pre-identity name is an alias.
	var aliased bool

	for _, a := range got["assignment-acct-a-role-admin-ops"].aliases {
		aliased = aliased || strings.HasPrefix(a, "name=assignment-acct-a-ops-role-admin")
	}

	if !aliased {
		t.Errorf("aliases = %v, want the pre-identity name", got["assignment-acct-a-role-admin-ops"].aliases)
	}

	if len(got["assignment-acct-b-role-viewer-dev"].aliases) != 1 { // noParent only
		t.Errorf("a role whose first group is not this one has no pre-identity alias: %v", got["assignment-acct-b-role-viewer-dev"].aliases)
	}
}

func TestUnknownSetAndMissingGroupAreRefused(t *testing.T) {
	if _, err := deployAll(t, []sso.Grant{{Scope: "acct-a", Set: "role-ghost", Group: "ops@example.test", Role: "ops"}}, nil); err == nil ||
		!strings.Contains(err.Error(), "unknown permission set") {
		t.Errorf("unknown set not refused: %v", err)
	}

	if _, err := deployAll(t, []sso.Grant{{Scope: "acct-a", Set: "role-viewer", Group: "nobody@example.test", Role: "ops"}}, nil); err == nil ||
		!strings.Contains(err.Error(), "SSO group not found") {
		t.Errorf("missing group not refused: %v", err)
	}
}

func TestLegacyAssignments(t *testing.T) {
	rec := &recorder{}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		p, err := pulumiaws.NewProvider(ctx, "p", &pulumiaws.ProviderArgs{Region: pulumi.String("region-a")})
		if err != nil {
			return err
		}

		return sso.DeployLegacyAssignments(ctx, quiet(), "instance-ref",
			map[string]sso.LegacyAccount{"old": {ID: "old-id", Sets: map[string][]string{"hand-made": {"ops@example.test", "ops@example.test"}}}},
			map[string]pulumi.StringOutput{"ops@example.test": pulumi.String("g-ops").ToStringOutput()},
			func(g string) string { return strings.TrimSuffix(g, "@example.test") }, p)
	}, pulumi.WithMocks("proj", "stack", rec))
	if err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(names(rec.regs), ","); !strings.Contains(got, "legacy-assignment-old-hand-made-ops") || strings.Count(got, "legacy-assignment-") != 1 {
		t.Errorf("names = %s (a repeated member is assigned once)", got)
	}
}
