package trail_test

import (
	"sort"
	"strings"
	"sync"
	"testing"

	pulumiaws "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/engine/trail"
)

type registration struct {
	typ, name, parent, provider string
	noParentAlias               bool
	protect, retain             bool
	dependsOn                   []string
	inputs                      resource.PropertyMap
}

type recorder struct {
	mu   sync.Mutex
	regs []registration
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
			if spec := a.GetSpec(); spec != nil && spec.GetName() == "" && spec.GetNoParent() {
				reg.noParentAlias = true
			}
		}
	}

	r.mu.Lock()
	r.regs = append(r.regs, reg)
	r.mu.Unlock()

	out := args.Inputs.Copy()
	out["arn"] = resource.NewProperty("ref-of-" + args.Name)
	out["keyId"] = resource.NewProperty("key-id-of-" + args.Name)

	return args.Name + "-id", out, nil
}

func (*recorder) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return args.Args, nil
}

func full() *trail.Args {
	return &trail.Args{
		Account: "acct",
		Buckets: trail.Buckets{
			Trail:     pulumi.String("trail-bucket-x"),
			AccessLog: pulumi.String("log-bucket-x"),
			Replica:   pulumi.String("replica-bucket-x"),
		},
		KeyAlias:          "alias/trail",
		KeyAdministrator:  pulumi.String("admin-ref"),
		TrailARN:          pulumi.String("trail-ref/*"),
		DataEventResource: "data-ref",
		ReplicationRole: trail.ReplicationRole{
			Name:                "replication-x",
			PermissionsBoundary: pulumi.String("boundary-ref"),
		},
		LegacyTopLevel: true,
	}
}

type opt struct{ noProvider, noReplica bool }

func run(t *testing.T, args *trail.Args, o opt) ([]registration, error) {
	t.Helper()

	rec := &recorder{}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		p, err := pulumiaws.NewProvider(ctx, "p", &pulumiaws.ProviderArgs{Region: pulumi.String("region-a")})
		if err != nil {
			return err
		}

		rp, err := pulumiaws.NewProvider(ctx, "rp", &pulumiaws.ProviderArgs{Region: pulumi.String("region-b")})
		if err != nil {
			return err
		}

		if !o.noProvider {
			args.Provider = p
		}

		if !o.noReplica {
			args.ReplicaProvider = rp
		}

		_, err = trail.New(ctx, "trail-acct", args)

		return err
	}, pulumi.WithMocks("proj", "stack", rec))

	return rec.regs, err
}

func children(regs []registration) []registration {
	var out []registration

	for _, r := range regs {
		if r.typ != "pulumi:providers:aws" && r.typ != trail.TypeToken && r.typ != "pulumi:pulumi:Stack" {
			out = append(out, r)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })

	return out
}

func by(regs []registration) map[string]registration {
	m := map[string]registration{}
	for _, c := range children(regs) {
		m[c.name] = c
	}

	return m
}

func TestDefaultNames(t *testing.T) {
	regs, err := run(t, full(), opt{})
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	for _, c := range children(regs) {
		got = append(got, strings.TrimPrefix(c.name, "trail-acct-"))
	}

	want := []string{
		"access-log-bucket", "access-log-bucket-policy", "access-log-lifecycle", "access-log-ownership",
		"access-log-public-access-block", "access-log-sse", "bucket", "bucket-policy", "kms-alias", "kms-key",
		"lifecycle", "logging", "public-access-block", "replica-bucket", "replica-bucket-policy",
		"replica-lifecycle", "replica-public-access-block", "replica-sse", "replica-versioning",
		"replication", "replication-policy", "replication-role", "sse", "trail", "versioning",
	}

	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("names\n got %v\nwant %v", got, want)
	}
}

func TestNamesHook(t *testing.T) {
	a := full()
	a.Names = func(c trail.Child) string { return string(c.Kind) + "/" + c.Account }

	regs, err := run(t, a, opt{})
	if err != nil {
		t.Fatal(err)
	}

	m := by(regs)
	if len(m) != 25 {
		t.Fatalf("children = %d, want 25", len(m))
	}

	for _, w := range []string{"key/acct", "trail/acct", "replica-bucket-versioning/acct", "log-bucket-ownership/acct"} {
		if _, ok := m[w]; !ok {
			t.Errorf("no child %q", w)
		}
	}
}

func TestChildrenAreUnderTheComponentWithProviderAndAlias(t *testing.T) {
	regs, err := run(t, full(), opt{})
	if err != nil {
		t.Fatal(err)
	}

	replica := map[string]bool{
		"trail-acct-replica-bucket": true, "trail-acct-replica-versioning": true, "trail-acct-replica-sse": true,
		"trail-acct-replica-public-access-block": true, "trail-acct-replica-bucket-policy": true,
		"trail-acct-replica-lifecycle": true,
	}

	for _, c := range children(regs) {
		if !strings.Contains(c.parent, "trail-acct") {
			t.Errorf("%s: parent %q is not the component", c.name, c.parent)
		}

		if !c.noParentAlias {
			t.Errorf("%s: no noParent alias", c.name)
		}

		if c.protect || c.retain {
			t.Errorf("%s: must be neither protected nor retained", c.name)
		}

		want := "::p::"
		if replica[c.name] {
			want = "::rp::"
		}

		if !strings.Contains(c.provider, want) {
			t.Errorf("%s: provider %q, want %s", c.name, c.provider, want)
		}
	}
}

func TestWithoutLegacyTopLevelNoAlias(t *testing.T) {
	a := full()
	a.LegacyTopLevel = false

	regs, err := run(t, a, opt{})
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range children(regs) {
		if c.noParentAlias {
			t.Errorf("%s: unexpected alias", c.name)
		}
	}
}

func TestInputs(t *testing.T) {
	regs, err := run(t, full(), opt{})
	if err != nil {
		t.Fatal(err)
	}

	m := by(regs)

	key := m["trail-acct-kms-key"].inputs
	if !key["enableKeyRotation"].BoolValue() {
		t.Errorf("key rotation off: %v", key)
	}

	wantKey := `{"Version":"2012-10-17","Statement":[` +
		`{"Sid":"AllowRootKeyManagement","Effect":"Allow","Principal":{"AWS":"admin-ref"},"Action":"kms:*","Resource":"*"},` +
		`{"Sid":"AllowCloudTrailEncryptDecrypt","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},` +
		`"Action":["kms:GenerateDataKey*","kms:Decrypt"],"Resource":"*",` +
		`"Condition":{"StringLike":{"kms:EncryptionContext:aws:cloudtrail:arn":"trail-ref/*"}}},` +
		`{"Sid":"AllowCloudTrailDescribe","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},` +
		`"Action":"kms:DescribeKey","Resource":"*"}]}`
	if got := key["policy"].StringValue(); got != wantKey {
		t.Errorf("key policy\n got %s\nwant %s", got, wantKey)
	}

	if got := m["trail-acct-kms-alias"].inputs["name"].StringValue(); got != "alias/trail" {
		t.Errorf("alias name = %q", got)
	}

	if got := m["trail-acct-bucket"].inputs["bucket"].StringValue(); got != "trail-bucket-x" {
		t.Errorf("trail bucket = %q", got)
	}

	wantBucketPolicy := `{"Version":"2012-10-17","Statement":[` +
		`{"Sid":"AllowCloudTrailGetBucketAcl","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},` +
		`"Action":"s3:GetBucketAcl","Resource":"ref-of-trail-acct-bucket"},` +
		`{"Sid":"AllowCloudTrailPutObject","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},` +
		`"Action":"s3:PutObject","Resource":"ref-of-trail-acct-bucket/*",` +
		`"Condition":{"StringEquals":{"s3:x-amz-acl":"bucket-owner-full-control"}}},` +
		`{"Sid":"DenyInsecureTransport","Effect":"Deny","Principal":"*","Action":"s3:*",` +
		`"Resource":["ref-of-trail-acct-bucket","ref-of-trail-acct-bucket/*"],` +
		`"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`
	if got := m["trail-acct-bucket-policy"].inputs["policy"].StringValue(); got != wantBucketPolicy {
		t.Errorf("trail bucket policy\n got %s\nwant %s", got, wantBucketPolicy)
	}

	wantHTTPS := `{"Version":"2012-10-17","Statement":[{"Sid":"DenyInsecureTransport","Effect":"Deny","Principal":"*",` +
		`"Action":"s3:*","Resource":["ref-of-trail-acct-access-log-bucket","ref-of-trail-acct-access-log-bucket/*"],` +
		`"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`
	if got := m["trail-acct-access-log-bucket-policy"].inputs["policy"].StringValue(); got != wantHTTPS {
		t.Errorf("access log policy\n got %s\nwant %s", got, wantHTTPS)
	}

	role := m["trail-acct-replication-role"].inputs
	if role["name"].StringValue() != "replication-x" || role["permissionsBoundary"].StringValue() != "boundary-ref" {
		t.Errorf("role inputs %v", role)
	}

	if got := role["assumeRolePolicy"].StringValue(); got !=
		`{"Statement":[{"Action":"sts:AssumeRole","Effect":"Allow","Principal":{"Service":"s3.amazonaws.com"}}],"Version":"2012-10-17"}` {
		t.Errorf("trust policy %s", got)
	}

	pol := m["trail-acct-replication-policy"].inputs["policy"].StringValue()
	for _, w := range []string{
		`"Resource":"ref-of-trail-acct-bucket/*"`, `"Resource":"ref-of-trail-acct-replica-bucket/*"`,
		`"s3:ReplicateObject"`, `"s3:GetObjectVersionForReplication"`,
	} {
		if !strings.Contains(pol, w) {
			t.Errorf("replication policy lacks %s:\n%s", w, pol)
		}
	}

	tr := m["trail-acct-trail"].inputs
	if !tr["isMultiRegionTrail"].BoolValue() || !tr["enableLogFileValidation"].BoolValue() ||
		!tr["includeGlobalServiceEvents"].BoolValue() || tr["isOrganizationTrail"].BoolValue() {
		t.Errorf("trail inputs %v", tr)
	}

	sel := tr["eventSelectors"].ArrayValue()[0].ObjectValue()
	dr := sel["dataResources"].ArrayValue()[0].ObjectValue()

	if dr["type"].StringValue() != "AWS::S3::Object" || dr["values"].ArrayValue()[0].StringValue() != "data-ref" {
		t.Errorf("data resources %v", dr)
	}

	if sel["readWriteType"].StringValue() != "All" || !sel["includeManagementEvents"].BoolValue() {
		t.Errorf("selector %v", sel)
	}
}

func TestDependencies(t *testing.T) {
	regs, err := run(t, full(), opt{})
	if err != nil {
		t.Fatal(err)
	}

	m := by(regs)

	if n := len(m["trail-acct-trail"].dependsOn); n < 2 {
		t.Errorf("trail depends on %d resources, want the bucket and its policy", n)
	}

	if n := len(m["trail-acct-replication"].dependsOn); n < 2 {
		t.Errorf("replication depends on %d resources, want both versionings", n)
	}
}

func TestRefusals(t *testing.T) {
	cases := map[string]struct {
		mutate func(a *trail.Args)
		o      opt
		want   string
	}{
		"no account":     {func(a *trail.Args) { a.Account = "" }, opt{}, "Account is empty"},
		"no provider":    {func(*trail.Args) {}, opt{noProvider: true}, "Provider is nil"},
		"no replica":     {func(*trail.Args) {}, opt{noReplica: true}, "ReplicaProvider is nil"},
		"no trail bkt":   {func(a *trail.Args) { a.Buckets.Trail = nil }, opt{}, "Buckets.Trail is unset"},
		"no log bkt":     {func(a *trail.Args) { a.Buckets.AccessLog = nil }, opt{}, "Buckets.AccessLog is unset"},
		"no replica bkt": {func(a *trail.Args) { a.Buckets.Replica = nil }, opt{}, "Buckets.Replica is unset"},
		"no alias":       {func(a *trail.Args) { a.KeyAlias = "" }, opt{}, "KeyAlias is empty"},
		"bad alias":      {func(a *trail.Args) { a.KeyAlias = "trail" }, opt{}, "lacks the alias/ prefix"},
		"no admin":       {func(a *trail.Args) { a.KeyAdministrator = nil }, opt{}, "KeyAdministrator is unset"},
		"no trail arn":   {func(a *trail.Args) { a.TrailARN = nil }, opt{}, "TrailARN is unset"},
		"no data":        {func(a *trail.Args) { a.DataEventResource = "" }, opt{}, "DataEventResource is empty"},
		"no role name":   {func(a *trail.Args) { a.ReplicationRole.Name = "" }, opt{}, "ReplicationRole.Name is empty"},
		"no boundary":    {func(a *trail.Args) { a.ReplicationRole.PermissionsBoundary = nil }, opt{}, "PermissionsBoundary is unset"},
		"empty name":     {func(a *trail.Args) { a.Names = func(trail.Child) string { return "" } }, opt{}, "empty name"},
		"repeated name":  {func(a *trail.Args) { a.Names = func(trail.Child) string { return "same" } }, opt{}, `returned "same" for both`},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			a := full()
			tc.mutate(a)

			regs, err := run(t, a, tc.o)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}

			if n := len(children(regs)); n != 0 {
				t.Fatalf("registered %d children despite refusal", n)
			}
		})
	}
}

func TestRefusalReportsEveryProblemAtOnce(t *testing.T) {
	a := full()
	a.Account = ""
	a.KeyAlias = "x"
	a.TrailARN = nil
	a.ReplicationRole.PermissionsBoundary = nil

	_, err := run(t, a, opt{noProvider: true, noReplica: true})
	if err == nil {
		t.Fatal("want error")
	}

	for _, w := range []string{
		"Account is empty", "Provider is nil", "ReplicaProvider is nil", "alias/", "TrailARN", "PermissionsBoundary",
	} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error lacks %q: %v", w, err)
		}
	}
}
