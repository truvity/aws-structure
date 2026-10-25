package sso_test

import (
	"strings"
	"testing"

	pulumiaws "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/engine/sso"
)

func TestDeployInlinePolicies(t *testing.T) {
	rec := &recorder{}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		p, err := pulumiaws.NewProvider(ctx, "p", &pulumiaws.ProviderArgs{Region: pulumi.String("region-a")})
		if err != nil {
			return err
		}

		sets, err := sso.DeploySets(ctx, quiet(), pulumi.String("instance-ref"), specs(), p)
		if err != nil {
			return err
		}

		return sso.DeployInlinePolicies(ctx, pulumi.String("instance-ref"), sets, map[string]string{"admin": `{"Version":"2012-10-17"}`}, p)
	}, pulumi.WithMocks("proj", "stack", rec))
	if err != nil {
		t.Fatal(err)
	}

	var found bool

	for _, r := range rec.regs {
		if strings.HasSuffix(r.name, "ps-admin-inline-policy") {
			found = true

			if r.parent == "" || len(r.dependsOn) == 0 {
				t.Errorf("inline policy must be a child of the set and depend on it: %+v", r)
			}
		}
	}

	if !found {
		t.Errorf("no ps-admin-inline-policy registered: %+v", rec.regs)
	}
}

func TestDeployInlinePoliciesRefusesAnUndeployedSet(t *testing.T) {
	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		return sso.DeployInlinePolicies(ctx, pulumi.String("i"), map[string]*sso.PermissionSet{}, map[string]string{"nope": "{}"}, nil)
	}, pulumi.WithMocks("proj", "stack", &recorder{}))
	if err == nil || !strings.Contains(err.Error(), "not deployed") {
		t.Fatalf("err = %v, want a not-deployed error", err)
	}
}
