package backend_test

import (
	"strings"
	"sync"
	"testing"

	pulumiaws "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/backend"
)

// inputRecorder keeps the inputs of every resource by logical name.
type inputRecorder struct {
	mu     sync.Mutex
	inputs map[string]resource.PropertyMap
}

func (r *inputRecorder) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	r.mu.Lock()
	r.inputs[args.Name] = args.Inputs.Copy()
	r.mu.Unlock()

	out := args.Inputs.Copy()
	out["arn"] = resource.NewProperty("arn:of:" + args.Name)
	out["bucket"] = resource.NewProperty("bucket-of-" + args.Name)
	out["keyId"] = resource.NewProperty("keyid-of-" + args.Name)

	return args.Name + "-id", out, nil
}

func (*inputRecorder) Call(_ pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return resource.PropertyMap{"accountId": resource.NewProperty("acct-ref")}, nil
}

func deploy(t *testing.T, b backend.Bucket) *inputRecorder {
	t.Helper()

	rec := &inputRecorder{inputs: map[string]resource.PropertyMap{}}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		p, err := pulumiaws.NewProvider(ctx, "p", &pulumiaws.ProviderArgs{Region: pulumi.String("region-a")})
		if err != nil {
			return err
		}

		res, err := backend.NewBucket(ctx, slogDiscard(), b, p)
		if err != nil {
			return err
		}

		return backend.NewReplication(ctx, slogDiscard(), b, res, p, backend.Replication{
			Profile: "prof", Partition: "part", BoundaryName: "boundary",
		})
	}, pulumi.WithMocks("proj", "stack", rec))
	if err != nil {
		t.Fatal(err)
	}

	return rec
}

func str(t *testing.T, rec *inputRecorder, name, prop string) string {
	t.Helper()

	in, ok := rec.inputs[name]
	if !ok {
		t.Fatalf("resource %q was not declared", name)
	}

	v := in[resource.PropertyKey(prop)]
	if !v.IsString() {
		t.Fatalf("%s.%s is not a string: %v", name, prop, v)
	}

	return v.StringValue()
}

func rules(t *testing.T, rec *inputRecorder, name string) string {
	t.Helper()

	in, ok := rec.inputs[name]
	if !ok {
		t.Fatalf("resource %q was not declared", name)
	}

	return in["rules"].String()
}

var (
	keyUUID     = "0a0a0a0a-0a0a-4a0a-8a0a-0a0a0a0a0a0a"
	existingKey = keyARN("region-a", fakeID, keyUUID)
)

func keyARN(region, account, id string) string {
	return "arn:part:kms:" + region + ":" + account + ":key/" + id
}

func existingSpec() backend.Bucket {
	b := spec()
	b.Region = "region-a"
	b.ExistingKeyARN = existingKey

	return b
}

func TestDefaultCreatesItsOwnKey(t *testing.T) {
	rec := deploy(t, spec())

	if _, ok := rec.inputs["pulumi-state-acct/kms-key"]; !ok {
		t.Fatal("the default creates the key")
	}

	if got := str(t, rec, "pulumi-state-acct/kms-alias", "targetKeyId"); got != "keyid-of-pulumi-state-acct/kms-key" {
		t.Errorf("alias target = %q, want the created key", got)
	}

	if _, ok := rec.inputs["pulumi-state-acct/kms-legacy-alias"]; ok {
		t.Error("the default declares no legacy alias")
	}

	pol := str(t, rec, "pulumi-state-acct-replica/replication-policy", "policy")
	if !strings.Contains(pol, `"Resource": "arn:of:pulumi-state-acct/kms-key"`) {
		t.Errorf("the replication policy names a single source key: %s", pol)
	}
}

func TestExistingKeyWithoutLegacy(t *testing.T) {
	rec := deploy(t, existingSpec())

	if _, ok := rec.inputs["pulumi-state-acct/kms-key"]; ok {
		t.Fatal("an existing key means no new key")
	}

	if got := str(t, rec, "pulumi-state-acct/kms-alias", "targetKeyId"); got != existingKey {
		t.Errorf("alias target = %q, want %q", got, existingKey)
	}

	if got := str(t, rec, "pulumi-state-acct/kms-alias", "name"); got != backend.KMSAlias() {
		t.Errorf("alias name = %q", got)
	}

	if enc := rules(t, rec, "pulumi-state-acct/bucket-encryption"); !strings.Contains(enc, existingKey) {
		t.Errorf("bucket default encryption does not name the existing key: %s", enc)
	}

	pol := str(t, rec, "pulumi-state-acct-replica/replication-policy", "policy")
	if !strings.Contains(pol, `"Resource": "`+existingKey+`"`) {
		t.Errorf("the replication policy must decrypt with the existing key: %s", pol)
	}

	// The replica keeps its own key and alias.
	if _, ok := rec.inputs["pulumi-state-acct-replica/kms-key"]; !ok {
		t.Error("the replica key is still created")
	}
}

func TestExistingKeyKeepsTheLegacyKey(t *testing.T) {
	b := existingSpec()
	b.LegacyKeyAlias = "alias/pulumi-state-legacy"

	rec := deploy(t, b)

	if _, ok := rec.inputs["pulumi-state-acct/kms-key"]; !ok {
		t.Fatal("the legacy key keeps its logical name")
	}

	if got := str(t, rec, "pulumi-state-acct/kms-legacy-alias", "targetKeyId"); got != "keyid-of-pulumi-state-acct/kms-key" {
		t.Errorf("legacy alias target = %q", got)
	}

	if got := str(t, rec, "pulumi-state-acct/kms-legacy-alias", "name"); got != "alias/pulumi-state-legacy" {
		t.Errorf("legacy alias name = %q", got)
	}

	if got := str(t, rec, "pulumi-state-acct/kms-alias", "targetKeyId"); got != existingKey {
		t.Errorf("alias target = %q, want the existing key", got)
	}

	pol := str(t, rec, "pulumi-state-acct-replica/replication-policy", "policy")
	if !strings.Contains(pol, existingKey) || !strings.Contains(pol, "arn:of:pulumi-state-acct/kms-key") {
		t.Errorf("the replication policy must decrypt with both keys: %s", pol)
	}
}

func TestExistingKeyValidation(t *testing.T) {
	cases := []struct {
		name string
		edit func(*backend.Bucket)
		want string
	}{
		{"legacy alone", func(b *backend.Bucket) { b.ExistingKeyARN = ""; b.LegacyKeyAlias = "alias/x" }, "needs ExistingKeyARN"},
		{"not a key", func(b *backend.Bucket) { b.ExistingKeyARN = "alias/eks" }, "single-region key ARN"},
		{"multi-region key", func(b *backend.Bucket) {
			b.ExistingKeyARN = keyARN("region-a", fakeID, "mrk-0123456789abcdef0123456789abcdef")
		}, "single-region key ARN"},
		{"other region", func(b *backend.Bucket) { b.Region = "region-c"; b.Name = backend.BucketName(fakeID, "region-c") }, "existing key is in region-a"},
		{"other account", func(b *backend.Bucket) {
			b.ExistingKeyARN = keyARN("region-a", strings.Repeat("2", 12), keyUUID)
		}, "existing key is in account"},
		{"legacy without prefix", func(b *backend.Bucket) { b.LegacyKeyAlias = "legacy" }, "must start with alias/"},
		{"legacy is the alias", func(b *backend.Bucket) { b.LegacyKeyAlias = b.KMSAlias }, "must differ"},
	}

	if err := existingSpec().Validate(); err != nil {
		t.Fatalf("valid bucket refused: %v", err)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := existingSpec()
			tc.edit(&b)

			err := b.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}
