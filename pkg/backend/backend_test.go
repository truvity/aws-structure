package backend_test

import (
	"sort"
	"strings"
	"sync"
	"testing"

	pulumiaws "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/backend"
)

type recorder struct {
	mu    sync.Mutex
	names map[string]string // logical name -> type token
}

func (r *recorder) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	r.mu.Lock()
	r.names[args.Name] = args.TypeToken
	r.mu.Unlock()

	out := args.Inputs.Copy()
	out["arn"] = resource.NewProperty("ref-of-" + args.Name)
	out["bucket"] = resource.NewProperty("bucket-of-" + args.Name)

	return args.Name + "-id", out, nil
}

func (*recorder) Call(_ pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return resource.PropertyMap{"accountId": resource.NewProperty("acct-ref")}, nil
}

var fakeID = strings.Repeat("1", 12)

func spec() backend.Bucket {
	return backend.Bucket{
		Account:       "acct",
		AccountID:     fakeID,
		Name:          backend.BucketName(fakeID, "region-a"),
		KMSAlias:      backend.KMSAlias(),
		Region:        "region-a",
		ReplicaRegion: "region-b",
		ReplicaName:   backend.BucketName(fakeID, "region-b"),
		ReplicaTags:   map[string]string{"Purpose": "replica"},
	}
}

func TestBucketAndReplicationNames(t *testing.T) {
	rec := &recorder{names: map[string]string{}}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		p, err := pulumiaws.NewProvider(ctx, "p", &pulumiaws.ProviderArgs{Region: pulumi.String("region-a")})
		if err != nil {
			return err
		}

		logger := slogDiscard()
		res, err := backend.NewBucket(ctx, logger, spec(), p)
		if err != nil {
			return err
		}

		return backend.NewReplication(ctx, logger, spec(), res, p, backend.Replication{
			Profile: "prof", Partition: "part", BoundaryName: "boundary",
		})
	}, pulumi.WithMocks("proj", "stack", rec))
	if err != nil {
		t.Fatal(err)
	}

	var got []string

	for n := range rec.names {
		if strings.HasPrefix(n, "pulumi-state-") {
			got = append(got, n)
		}
	}

	sort.Strings(got)

	want := []string{
		"pulumi-state-acct-replica-provider",
		"pulumi-state-acct-replica/bucket",
		"pulumi-state-acct-replica/bucket-encryption",
		"pulumi-state-acct-replica/bucket-https-policy",
		"pulumi-state-acct-replica/bucket-pab",
		"pulumi-state-acct-replica/bucket-versioning",
		"pulumi-state-acct-replica/kms-alias",
		"pulumi-state-acct-replica/kms-key",
		"pulumi-state-acct-replica/replication-config",
		"pulumi-state-acct-replica/replication-policy",
		"pulumi-state-acct-replica/replication-role",
		"pulumi-state-acct/bucket",
		"pulumi-state-acct/bucket-encryption",
		"pulumi-state-acct/bucket-https-policy",
		"pulumi-state-acct/bucket-lifecycle",
		"pulumi-state-acct/bucket-pab",
		"pulumi-state-acct/bucket-versioning",
		"pulumi-state-acct/kms-alias",
		"pulumi-state-acct/kms-key",
	}
	sort.Strings(want)

	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("logical names:\n got %v\nwant %v", got, want)
	}
}

func TestValidate(t *testing.T) {
	b := spec()
	if err := b.Validate(); err != nil {
		t.Fatalf("valid bucket refused: %v", err)
	}

	b.Name = "elsewhere"
	b.AccountID = "short"
	b.Region = ""

	err := b.Validate()
	if err == nil {
		t.Fatal("invalid bucket accepted")
	}

	for _, frag := range []string{"region must not be empty", "12 digits", "does not match"} {
		if !strings.Contains(err.Error(), frag) {
			t.Errorf("error %q lacks %q", err, frag)
		}
	}

	a, c := spec(), spec()
	if err := backend.ValidateSet([]backend.Bucket{a, c}); err == nil || !strings.Contains(err.Error(), "duplicate account") {
		t.Fatalf("duplicate not refused: %v", err)
	}
}

func TestReplicationNeedsInputs(t *testing.T) {
	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		p, err := pulumiaws.NewProvider(ctx, "p", &pulumiaws.ProviderArgs{Region: pulumi.String("region-a")})
		if err != nil {
			return err
		}

		return backend.NewReplication(ctx, slogDiscard(), spec(), &backend.Result{}, p, backend.Replication{})
	}, pulumi.WithMocks("proj", "stack", &recorder{names: map[string]string{}}))
	if err == nil || !strings.Contains(err.Error(), "partition") {
		t.Fatalf("missing partition not refused: %v", err)
	}
}
