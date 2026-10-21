package fleet_test

import (
	"strings"
	"sync"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/cdkbootstrap"
	"github.com/truvity/aws-structure/pkg/engine/iam"
	"github.com/truvity/aws-structure/pkg/fleet"
	"github.com/truvity/aws-structure/pkg/registry"
)

type depRecorder struct {
	mu   sync.Mutex
	deps map[string][]string
	typ  map[string]string
}

func (r *depRecorder) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.deps == nil {
		r.deps, r.typ = map[string][]string{}, map[string]string{}
	}

	r.typ[args.Name] = args.TypeToken

	if rpc := args.RegisterRPC; rpc != nil {
		r.deps[args.Name] = rpc.GetDependencies()
	}

	out := args.Inputs.Copy()
	out["arn"] = resource.NewProperty("arn-of-" + args.Name)
	out["id"] = resource.NewProperty(args.Name + "-id")

	return args.Name + "-id", out, nil
}

func (*depRecorder) Call(pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return resource.PropertyMap{}, nil
}

func iamArgs() fleet.IAMArgs {
	return fleet.IAMArgs{
		RootAccount:    "root",
		Boundaries:     []registry.Boundary{{Name: "boundary", Document: "{}"}},
		RootBoundaries: []registry.Boundary{{Name: "boundary", Document: "{}"}},
		PasswordPolicy: registry.PasswordPolicy{MinimumLength: 14},
		Auditor: func(id pulumi.StringInput) (*iam.AuditorRole, error) {
			return &iam.AuditorRole{
				Name: "auditor", TrustedPrincipal: "principal-ref", ManagedPolicies: []string{"managed-ref"},
				PermissionsBoundary: pulumi.Sprintf("boundary-%s", id),
			}, nil
		},
	}
}

func appBootstrap(q string, accounts, regions []string) cdkbootstrap.Bootstrap {
	return cdkbootstrap.Bootstrap{Qualifier: q, DeployBoundary: "boundary", Accounts: accounts, Regions: regions}
}

func TestCDKBootstrapsDependOnTheAccountsBoundaries(t *testing.T) {
	rec := &depRecorder{}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		f := members()
		if err := f.IAM(ctx, quiet(), iamArgs()); err != nil {
			return err
		}

		return f.CDKBootstraps(ctx, quiet(), fleet.CDKBootstrapsArgs{Bootstraps: []cdkbootstrap.Bootstrap{
			appBootstrap("one", []string{"a"}, []string{"eu-west-1"}),
			appBootstrap("two", []string{"a", "b"}, []string{"eu-west-1", "eu-west-2"}),
		}})
	}, pulumi.WithMocks("proj", "stack", rec))
	if err != nil {
		t.Fatal(err)
	}

	// 1 + 4 components, one stack each, one provider per account and region.
	for _, name := range []string{
		"cdkbootstrap-one-a-eu-west-1", "cdkbootstrap-two-a-eu-west-1", "cdkbootstrap-two-a-eu-west-2",
		"cdkbootstrap-two-b-eu-west-1", "cdkbootstrap-two-b-eu-west-2",
	} {
		if rec.typ[name] != "truvity:aws-structure:CDKBootstrap" {
			t.Errorf("%s: type = %q", name, rec.typ[name])
		}

		stack := name + "-stack"
		if rec.typ[stack] != "aws:cloudformation/stack:Stack" {
			t.Errorf("%s: type = %q", stack, rec.typ[stack])
		}

		account := strings.Split(name, "-")[2]

		// Pulumi expands a dependency on a component into its children.
		boundaryPolicy := false

		for _, d := range rec.deps[stack] {
			if !strings.Contains(d, "truvity:aws-structure:AccountIAM$") || !strings.Contains(d, "::iam-"+account+"-") {
				t.Errorf("%s depends on %s, which is not a child of the AccountIAM iam-%s", stack, d, account)
			}

			boundaryPolicy = boundaryPolicy || strings.HasSuffix(d, "::iam-"+account+"-boundary-boundary")
		}

		if !boundaryPolicy {
			t.Errorf("%s does not depend on the boundary policy of %s: %v", stack, account, rec.deps[stack])
		}
	}

	providers := 0

	for name, typ := range rec.typ {
		if strings.HasPrefix(name, "cdkbootstrap-") && typ == "pulumi:providers:aws" {
			providers++
		}
	}

	if providers != 4 { // (a, x), (a, y), (b, x), (b, y)
		t.Errorf("%d bootstrap providers, want 4", providers)
	}
}

func TestCDKBootstrapsRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		iam  bool
		bs   cdkbootstrap.Bootstrap
		want string
	}{
		"before IAM":   {false, appBootstrap("one", []string{"a"}, []string{"eu-west-1"}), "run IAM before CDKBootstraps"},
		"not a member": {true, appBootstrap("one", []string{"zzz"}, []string{"eu-west-1"}), `"zzz" is not a member account`},
		"invalid":      {true, appBootstrap("Bad", []string{"a"}, []string{"eu-west-1"}), "qualifier"},
	} {
		t.Run(name, func(t *testing.T) {
			rec := &depRecorder{}

			err := pulumi.RunErr(func(ctx *pulumi.Context) error {
				f := members()
				if tc.iam {
					if err := f.IAM(ctx, quiet(), iamArgs()); err != nil {
						return err
					}
				}

				return f.CDKBootstraps(ctx, quiet(), fleet.CDKBootstrapsArgs{Bootstraps: []cdkbootstrap.Bootstrap{tc.bs}})
			}, pulumi.WithMocks("proj", "stack", rec))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}

			for n := range rec.typ {
				if strings.HasPrefix(n, "cdkbootstrap-") {
					t.Errorf("%s registered before the refusal", n)
				}
			}
		})
	}
}
