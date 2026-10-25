package fleet_test

import (
	"strings"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/engine/iam"
	"github.com/truvity/aws-structure/pkg/fleet"
)

func standaloneArgs(accounts ...string) fleet.StandaloneAuditorsArgs {
	return fleet.StandaloneAuditorsArgs{
		Accounts:   accounts,
		Management: "root",
		AccountIDs: map[string]string{"root": "id-root", "outside": "id-outside"},
		Auditor: func(id pulumi.StringInput) (*iam.AuditorRole, error) {
			return &iam.AuditorRole{
				Name: "auditor", TrustedPrincipal: "principal-ref", ManagedPolicies: []string{"managed-ref"},
				PermissionsBoundary: pulumi.Sprintf("boundary-%s", id),
			}, nil
		},
	}
}

func TestStandaloneAuditorsDeployManagementSkippedMemberAndOutsider(t *testing.T) {
	rec := run(t, func(ctx *pulumi.Context) error {
		return members().StandaloneAuditors(ctx, quiet(), standaloneArgs("root", "b", "outside"))
	})

	got := strings.Join(rec.names("vanta-"), ",")
	for _, want := range []string{"vanta-provider-root", "vanta-provider-b", "vanta-provider-outside", "vanta-root", "vanta-b", "vanta-outside"} {
		if !strings.Contains(got, want) {
			t.Errorf("%s not registered: %s", want, got)
		}
	}
}

func TestStandaloneAuditorsRefusals(t *testing.T) {
	cases := map[string]struct {
		account string
		want    string
	}{
		"a member the fleet gives an auditor": {"a", "the fleet already deploys its auditor role"},
		"an unknown account":                  {"nowhere", "neither a fleet account nor in AccountIDs"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := pulumi.RunErr(func(ctx *pulumi.Context) error {
				return members().StandaloneAuditors(ctx, quiet(), standaloneArgs(tc.account))
			}, pulumi.WithMocks("proj", "stack", &recorder{}))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}

	t.Run("management without an id", func(t *testing.T) {
		a := standaloneArgs("root")
		a.AccountIDs = nil

		err := pulumi.RunErr(func(ctx *pulumi.Context) error {
			return members().StandaloneAuditors(ctx, quiet(), a)
		}, pulumi.WithMocks("proj", "stack", &recorder{}))
		if err == nil || !strings.Contains(err.Error(), "no account id") {
			t.Fatalf("err = %v", err)
		}
	})
}
