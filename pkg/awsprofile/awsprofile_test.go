package awsprofile_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/awsprofile"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// sharedConfig points the AWS SDK at a config file with one profile, and no
// credentials file, for the duration of the test.
func sharedConfig(t *testing.T, body string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "config")

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("AWS_CONFIG_FILE", path)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")

	return path
}

func TestConfigRegionFromProfileAndCached(t *testing.T) {
	path := sharedConfig(t, "[profile p]\nregion = region-x\n")
	m := awsprofile.NewManager(discard())

	cfg, err := m.GetAWSConfig(context.Background(), "p")
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Region != "region-x" {
		t.Fatalf("region %q, want the profile's", cfg.Region)
	}

	if err := os.WriteFile(path, []byte("[profile p]\nregion = region-y\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if cfg, _ := m.GetAWSConfig(context.Background(), "p"); cfg.Region != "region-x" {
		t.Fatalf("second call reloaded the profile: region %q", cfg.Region)
	}

	cfg, err = m.GetAWSConfigWithRegion(context.Background(), "p", "region-z")
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Region != "region-z" {
		t.Fatalf("explicit region %q, want region-z", cfg.Region)
	}
}

func TestConfigUnknownProfileRefused(t *testing.T) {
	sharedConfig(t, "[profile p]\nregion = region-x\n")

	if _, err := awsprofile.NewManager(discard()).GetAWSConfig(context.Background(), "nope"); err == nil {
		t.Fatal("a profile the shared config does not have was accepted")
	}
}

func TestAccountIDCached(t *testing.T) {
	sharedConfig(t, "[profile p]\nregion = region-x\n")
	m := awsprofile.NewManager(discard())

	calls := 0

	m.SetIdentity(func(_ context.Context, cfg aws.Config) (string, error) {
		calls++

		if cfg.Region != "region-x" {
			t.Errorf("identity asked with region %q", cfg.Region)
		}

		return "acct-of-p", nil
	})

	for range 2 {
		id, err := m.GetAccountID(context.Background(), "p")
		if err != nil {
			t.Fatal(err)
		}

		if id != "acct-of-p" {
			t.Fatalf("id %q", id)
		}
	}

	if calls != 1 {
		t.Fatalf("identity called %d times, want 1", calls)
	}
}

type recorder struct {
	mu    sync.Mutex
	names []string
}

func (r *recorder) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	r.mu.Lock()
	r.names = append(r.names, args.TypeToken+" "+args.Name)
	r.mu.Unlock()

	return args.Name + "-id", args.Inputs, nil
}

func (*recorder) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return args.Args, nil
}

func TestProvidersNamedCachedAndSharedPerProgram(t *testing.T) {
	rec := &recorder{}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		a, b := awsprofile.NewManager(discard()), awsprofile.NewManager(discard())

		p1, err := a.GetAWSProviderWithRegion(ctx, "p", "region-x")
		if err != nil {
			return err
		}

		p2, err := a.GetAWSProviderWithRegion(ctx, "p", "region-x")
		if err != nil {
			return err
		}

		// Another Manager of the same program shares the regional provider.
		p3, err := b.GetAWSProviderWithRegion(ctx, "p", "region-x")
		if err != nil {
			return err
		}

		if p1 != p2 || p1 != p3 {
			t.Error("the regional provider was not reused")
		}

		d1, err := a.GetAWSProvider(ctx, "p")
		if err != nil {
			return err
		}

		d2, err := a.GetAWSProvider(ctx, "p")
		if err != nil {
			return err
		}

		if d1 != d2 {
			t.Error("the profile provider was not cached")
		}

		return nil
	}, pulumi.WithMocks("proj", "stack", rec))
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]int{
		"pulumi:providers:aws provider/aws/p/region-x": 1,
		"pulumi:providers:aws provider/aws/p":          1,
	}

	got := map[string]int{}
	for _, n := range rec.names {
		got[n]++
	}

	for name, n := range want {
		if got[name] != n {
			t.Errorf("%s registered %d times, want %d (all: %v)", name, got[name], n, rec.names)
		}
	}
}
