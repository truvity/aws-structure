package fleet_test

import (
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/engine/iam"
	"github.com/truvity/aws-structure/pkg/fleet"
	"github.com/truvity/aws-structure/pkg/registry"
)

type recorded struct{ typ, name string }

type recorder struct {
	mu   sync.Mutex
	regs []recorded
}

func (r *recorder) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	r.mu.Lock()
	r.regs = append(r.regs, recorded{args.TypeToken, args.Name})
	r.mu.Unlock()

	out := args.Inputs.Copy()
	out["arn"] = resource.NewProperty("arn-of-" + args.Name)
	out["id"] = resource.NewProperty(args.Name + "-id")

	return args.Name + "-id", out, nil
}

func (*recorder) Call(_ pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return resource.PropertyMap{"roots": resource.NewProperty([]resource.PropertyValue{
		resource.NewProperty(resource.PropertyMap{"id": resource.NewProperty("root-ref")}),
	})}, nil
}

func (r *recorder) names(prefixes ...string) []string {
	var out []string

	for _, g := range r.regs {
		for _, p := range prefixes {
			if strings.HasPrefix(g.name, p) {
				out = append(out, g.name)
			}
		}
	}

	sort.Strings(out)

	return out
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func members() *fleet.Fleet {
	return &fleet.Fleet{
		Partition:     "part",
		RootProfile:   "root-profile",
		Accounts:      map[string]pulumi.StringInput{"a": pulumi.String("id-a"), "b": pulumi.String("id-b")},
		Expected:      []string{"a", "b"},
		PrimaryRegion: "region-a",
		Regions:       []string{"region-a", "region-b"},
		BoundaryName:  "boundary",
		Skip:          map[string]bool{"b": true},
	}
}

func run(t *testing.T, fn func(ctx *pulumi.Context) error) *recorder {
	t.Helper()

	rec := &recorder{}
	if err := pulumi.RunErr(fn, pulumi.WithMocks("proj", "stack", rec)); err != nil {
		t.Fatal(err)
	}

	return rec
}

func TestValidateRefusesADriftedAccountSet(t *testing.T) {
	f := members()
	f.Accounts["c"] = pulumi.String("id-c")
	delete(f.Accounts, "a")
	f.PrimaryRegion = "region-z"

	err := f.Validate()
	if err == nil {
		t.Fatal("drifted set accepted")
	}

	for _, frag := range []string{"missing=[a]", "extra=[c]", "does not contain PrimaryRegion"} {
		if !strings.Contains(err.Error(), frag) {
			t.Errorf("error %q lacks %q", err, frag)
		}
	}
}

func TestBaselineSkipsButStillBuildsProviders(t *testing.T) {
	rec := run(t, func(ctx *pulumi.Context) error { return members().Baseline(ctx, quiet(), fleet.BaselineArgs{}) })

	if got := strings.Join(rec.names("baseline-"), ","); !strings.Contains(got, "baseline-a-region-a") ||
		!strings.Contains(got, "baseline-b-region-b") {
		t.Errorf("providers are built for every account and region: %s", got)
	}

	for _, n := range rec.names("baseline-b", "ebs-encryption-b") {
		if !strings.HasPrefix(n, "baseline-b-region") {
			t.Errorf("a skipped account gets providers and nothing else: %s", n)
		}
	}
}

func TestIAMNames(t *testing.T) {
	rec := run(t, func(ctx *pulumi.Context) error {
		return members().IAM(ctx, quiet(), fleet.IAMArgs{
			RootAccount:    "root",
			Boundaries:     []registry.Boundary{{Name: "b1", Document: "{}"}},
			RootBoundaries: []registry.Boundary{{Name: "b1", Document: "{}"}},
			PasswordPolicy: registry.PasswordPolicy{MinimumLength: 14},
			Auditor: func(id pulumi.StringInput) (*iam.AuditorRole, error) {
				return &iam.AuditorRole{
					Name: "auditor", TrustedPrincipal: "principal-ref", ManagedPolicies: []string{"managed-ref"},
					PermissionsBoundary: pulumi.Sprintf("boundary-%s", id),
				}, nil
			},
		})
	})

	got := strings.Join(rec.names("provider-", "root-iam-provider", "iam-"), ",")
	for _, want := range []string{"provider-a", "provider-b", "root-iam-provider", "iam-a-region-a", "iam-b-region-a"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
}

func TestUnitsRefuseAnUndeclaredOU(t *testing.T) {
	rec := &recorder{}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		return fleet.DeployUnits(ctx, quiet(), fleet.UnitsArgs{
			Profile: "root-profile", Region: "region-a", OUs: []string{"Known"},
			Accounts: []registry.Account{{Name: "x", Email: "x@example.test", OU: "Unknown"}},
		})
	}, pulumi.WithMocks("proj", "stack", rec))
	if err == nil || !strings.Contains(err.Error(), "OU not found for account x: Unknown") {
		t.Fatalf("undeclared OU not refused: %v", err)
	}
}

func TestUnitsNames(t *testing.T) {
	rec := run(t, func(ctx *pulumi.Context) error {
		return fleet.DeployUnits(ctx, quiet(), fleet.UnitsArgs{
			Profile: "root-profile", Region: "region-a", OUs: []string{"Known"},
			Accounts: []registry.Account{{Name: "x", Email: "x@example.test", OU: "Known"}},
		})
	})

	if got := strings.Join(rec.names("orgunit-"), ","); got != "orgunit-Known,orgunit-Known-account-x,orgunit-Known-ou" {
		t.Errorf("components = %s", got)
	}
}
