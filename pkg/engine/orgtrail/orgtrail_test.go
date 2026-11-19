package orgtrail_test

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"

	pulumiaws "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/engine/orgtrail"
)

// The repository holds no literal account id or ARN (see hack/leak-canary.sh):
// the fixtures are built at runtime from documentation-style values.
const (
	orgID     = "o-exampleorg1"
	trailName = "example-org-trail"
	region    = "eu-west-1"
	part      = "aws"
)

func mgmtID() string { return strings.Repeat("1", 12) }

func role(name string) string {
	return fmt.Sprintf("arn:%s:iam::%s:role/%s", part, strings.Repeat("2", 12), name)
}

func trailARN() string {
	return fmt.Sprintf("arn:%s:cloudtrail:%s:%s:trail/%s", part, region, mgmtID(), trailName)
}

type registration struct {
	typ, name, parent, provider string
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

func full() *orgtrail.Args {
	return &orgtrail.Args{
		ManagementAccount:          "mgmt",
		LogsAccount:                "logs",
		ManagementAccountID:        pulumi.String(mgmtID()),
		OrganizationID:             pulumi.String(orgID),
		TrailName:                  trailName,
		Region:                     region,
		Bucket:                     pulumi.String("example-org-trail-logs"),
		KeyAlias:                   "alias/example-org-trail",
		KeyAdministrators:          []pulumi.StringInput{pulumi.String(role("deployer"))},
		Readers:                    []pulumi.StringInput{pulumi.String(role("reader-a")), pulumi.String(role("reader-b"))},
		RetentionDays:              365,
		RetentionMode:              orgtrail.Governance,
		BypassGovernancePrincipals: []string{fmt.Sprintf("arn:%s:iam::%s:role/break-glass-*", part, strings.Repeat("2", 12))},
		GlacierAfterDays:           90,
	}
}

type opt struct{ noMgmt, noLogs bool }

type outs struct{ bucketName, bucketArn, keyArn, trailArn string }

func run(t *testing.T, args *orgtrail.Args, o opt) ([]registration, outs, error) {
	t.Helper()

	rec := &recorder{}

	var got outs

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		mp, err := pulumiaws.NewProvider(ctx, "mp", &pulumiaws.ProviderArgs{Region: pulumi.String(region)})
		if err != nil {
			return err
		}

		lp, err := pulumiaws.NewProvider(ctx, "lp", &pulumiaws.ProviderArgs{Region: pulumi.String(region)})
		if err != nil {
			return err
		}

		if !o.noMgmt {
			args.ManagementProvider = mp
		}

		if !o.noLogs {
			args.LogsProvider = lp
		}

		c, err := orgtrail.New(ctx, "org-trail", args)
		if err != nil {
			return err
		}

		pulumi.All(c.BucketName, c.BucketArn, c.KeyArn, c.TrailArn).ApplyT(func(v []any) error {
			got = outs{v[0].(string), v[1].(string), v[2].(string), v[3].(string)}

			return nil
		})

		return nil
	}, pulumi.WithMocks("proj", "stack", rec))

	return rec.regs, got, err
}

func children(regs []registration) []registration {
	var out []registration

	for _, r := range regs {
		if r.typ != "pulumi:providers:aws" && r.typ != orgtrail.TypeToken && r.typ != "pulumi:pulumi:Stack" {
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

func mustRun(t *testing.T, a *orgtrail.Args) map[string]registration {
	t.Helper()

	regs, _, err := run(t, a, opt{})
	if err != nil {
		t.Fatal(err)
	}

	return by(regs)
}

func TestDefaultNames(t *testing.T) {
	var got []string
	for n := range mustRun(t, full()) {
		got = append(got, strings.TrimPrefix(n, "org-trail-"))
	}

	sort.Strings(got)

	want := []string{
		"bucket", "bucket-policy", "kms-alias", "kms-key", "lifecycle", "object-lock", "ownership",
		"public-access-block", "sse", "trail", "versioning",
	}

	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("names\n got %v\nwant %v", got, want)
	}
}

func TestNamesHook(t *testing.T) {
	a := full()
	a.Names = func(c orgtrail.Child) string { return string(c.Kind) + "/" + c.ManagementAccount + "/" + c.LogsAccount }

	m := mustRun(t, a)
	if len(m) != 11 {
		t.Fatalf("children = %d, want 11", len(m))
	}

	for _, w := range []string{"key/mgmt/logs", "trail/mgmt/logs", "bucket-object-lock/mgmt/logs"} {
		if _, ok := m[w]; !ok {
			t.Errorf("no child %q", w)
		}
	}
}

func TestProvidersParentAndNoProtection(t *testing.T) {
	for name, c := range mustRun(t, full()) {
		if !strings.Contains(c.parent, "org-trail") {
			t.Errorf("%s: parent %q is not the component", name, c.parent)
		}

		if c.protect || c.retain {
			t.Errorf("%s: must be neither protected nor retained", name)
		}

		want := "::lp::"
		if name == "org-trail-trail" {
			want = "::mp::"
		}

		if !strings.Contains(c.provider, want) {
			t.Errorf("%s: provider %q, want %s", name, c.provider, want)
		}
	}
}

func TestTrail(t *testing.T) {
	tr := mustRun(t, full())["org-trail-trail"].inputs

	if tr["name"].StringValue() != trailName {
		t.Errorf("trail name = %v", tr["name"])
	}

	for _, f := range []string{"isOrganizationTrail", "isMultiRegionTrail", "enableLogFileValidation", "includeGlobalServiceEvents"} {
		if !tr[resource.PropertyKey(f)].BoolValue() {
			t.Errorf("%s is not true: %v", f, tr)
		}
	}

	if tr["s3BucketName"].StringValue() != "org-trail-bucket-id" || tr["kmsKeyId"].StringValue() != "ref-of-org-trail-kms-key" {
		t.Errorf("bucket or key: %v / %v", tr["s3BucketName"], tr["kmsKeyId"])
	}

	if _, ok := tr["advancedEventSelectors"]; ok {
		t.Errorf("advanced selectors set: %v", tr["advancedEventSelectors"])
	}

	sels := tr["eventSelectors"].ArrayValue()
	if len(sels) != 1 {
		t.Fatalf("event selectors = %v", sels)
	}

	sel := sels[0].ObjectValue()
	if sel["readWriteType"].StringValue() != "All" || !sel["includeManagementEvents"].BoolValue() {
		t.Errorf("selector %v", sel)
	}

	if dr, ok := sel["dataResources"]; ok && dr.IsArray() && len(dr.ArrayValue()) > 0 {
		t.Errorf("data resources set: %v", dr)
	}
}

func TestTrailWaitsForBucketPolicyKeyAndObjectLock(t *testing.T) {
	deps := strings.Join(mustRun(t, full())["org-trail-trail"].dependsOn, " ")

	for _, w := range []string{"org-trail-bucket-policy", "org-trail-kms-key", "org-trail-object-lock", "org-trail-bucket"} {
		if !strings.Contains(deps, "::"+w) {
			t.Errorf("trail does not depend on %s: %s", w, deps)
		}
	}
}

func TestBucketIsCreatedWithObjectLock(t *testing.T) {
	b := mustRun(t, full())["org-trail-bucket"]

	if !b.inputs["objectLockEnabled"].BoolValue() {
		t.Errorf("objectLockEnabled is not true: %v", b.inputs)
	}

	if b.inputs["bucket"].StringValue() != "example-org-trail-logs" {
		t.Errorf("bucket = %v", b.inputs["bucket"])
	}

	if !strings.Contains(b.provider, "::lp::") {
		t.Errorf("provider %q is not the logs provider", b.provider)
	}
}

func TestObjectLockConfiguration(t *testing.T) {
	for _, mode := range []string{orgtrail.Governance, orgtrail.Compliance} {
		a := full()
		a.RetentionMode = mode
		a.RetentionDays = 400

		lock := mustRun(t, a)["org-trail-object-lock"]
		dr := lock.inputs["rule"].ObjectValue()["defaultRetention"].ObjectValue()

		if dr["mode"].StringValue() != mode || dr["days"].NumberValue() != 400 {
			t.Errorf("%s: default retention %v", mode, dr)
		}

		if !strings.Contains(lock.provider, "::lp::") {
			t.Errorf("provider %q", lock.provider)
		}

		if !strings.Contains(strings.Join(lock.dependsOn, " "), "::org-trail-versioning") {
			t.Errorf("object lock does not wait for versioning: %v", lock.dependsOn)
		}
	}
}

func TestBucketSettings(t *testing.T) {
	m := mustRun(t, full())

	if v := m["org-trail-versioning"].inputs["versioningConfiguration"].ObjectValue()["status"].StringValue(); v != "Enabled" {
		t.Errorf("versioning = %q", v)
	}

	pab := m["org-trail-public-access-block"].inputs
	for _, f := range []string{"blockPublicAcls", "blockPublicPolicy", "ignorePublicAcls", "restrictPublicBuckets"} {
		if !pab[resource.PropertyKey(f)].BoolValue() {
			t.Errorf("public access block %s is not true", f)
		}
	}

	rule := m["org-trail-sse"].inputs["rules"].ArrayValue()[0].ObjectValue()
	def := rule["applyServerSideEncryptionByDefault"].ObjectValue()

	if def["sseAlgorithm"].StringValue() != "aws:kms" || def["kmsMasterKeyId"].StringValue() != "ref-of-org-trail-kms-key" ||
		!rule["bucketKeyEnabled"].BoolValue() {
		t.Errorf("encryption %v", rule)
	}

	if v := m["org-trail-ownership"].inputs["rule"].ObjectValue()["objectOwnership"].StringValue(); v != "BucketOwnerEnforced" {
		t.Errorf("ownership = %q", v)
	}

	key := m["org-trail-kms-key"].inputs
	if !key["enableKeyRotation"].BoolValue() || key["description"].StringValue() == "" {
		t.Errorf("key inputs %v", key)
	}

	if m["org-trail-kms-alias"].inputs["name"].StringValue() != "alias/example-org-trail" {
		t.Errorf("alias %v", m["org-trail-kms-alias"].inputs["name"])
	}
}

func TestLifecycle(t *testing.T) {
	rule := func(a *orgtrail.Args) resource.PropertyMap {
		return mustRun(t, a)["org-trail-lifecycle"].inputs["rules"].ArrayValue()[0].ObjectValue()
	}

	r := rule(full())

	if r["status"].StringValue() != "Enabled" ||
		r["expiration"].ObjectValue()["days"].NumberValue() != 365 ||
		r["noncurrentVersionExpiration"].ObjectValue()["noncurrentDays"].NumberValue() != 1 ||
		r["abortIncompleteMultipartUpload"].ObjectValue()["daysAfterInitiation"].NumberValue() != 7 {
		t.Errorf("rule %v", r)
	}

	tr := r["transitions"].ArrayValue()
	if len(tr) != 1 || tr[0].ObjectValue()["days"].NumberValue() != 90 || tr[0].ObjectValue()["storageClass"].StringValue() != "GLACIER" {
		t.Errorf("transitions %v", tr)
	}

	a := full()
	a.GlacierAfterDays = 0

	if r := rule(a); r["transitions"].IsArray() && len(r["transitions"].ArrayValue()) > 0 {
		t.Errorf("transition set without GlacierAfterDays: %v", r["transitions"])
	}
}

type policyDoc struct {
	Version   string
	Statement []map[string]any
}

func parse(t *testing.T, s string) policyDoc {
	t.Helper()

	var d policyDoc
	if err := json.Unmarshal([]byte(s), &d); err != nil {
		t.Fatalf("policy is not JSON: %v\n%s", err, s)
	}

	if d.Version != "2012-10-17" {
		t.Errorf("version %q", d.Version)
	}

	return d
}

func (d policyDoc) sid(t *testing.T, sid string) map[string]any {
	t.Helper()

	for _, s := range d.Statement {
		if s["Sid"] == sid {
			return s
		}
	}

	t.Fatalf("no statement %q in %v", sid, d.Statement)

	return nil
}

func (d policyDoc) has(sid string) bool {
	for _, s := range d.Statement {
		if s["Sid"] == sid {
			return true
		}
	}

	return false
}

func strs(t *testing.T, v any) []string {
	t.Helper()

	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, e.(string))
		}

		return out
	}

	t.Fatalf("not a string or list: %v", v)

	return nil
}

func cond(s map[string]any, op, key string) any {
	c, _ := s["Condition"].(map[string]any)
	o, _ := c[op].(map[string]any)

	return o[key]
}

func keyPolicyOf(t *testing.T, a *orgtrail.Args) (string, policyDoc) {
	t.Helper()

	s := mustRun(t, a)["org-trail-kms-key"].inputs["policy"].StringValue()

	return s, parse(t, s)
}

func bucketPolicyOf(t *testing.T, a *orgtrail.Args) (string, policyDoc) {
	t.Helper()

	s := mustRun(t, a)["org-trail-bucket-policy"].inputs["policy"].StringValue()

	return s, parse(t, s)
}

func TestKeyPolicy(t *testing.T) {
	raw, d := keyPolicyOf(t, full())

	if strings.Contains(raw, ":root") {
		t.Errorf("key policy names an account root: %s", raw)
	}

	for _, s := range d.Statement {
		if p, ok := s["Principal"].(map[string]any); ok {
			for _, v := range p {
				for _, x := range strs(t, v) {
					if strings.HasSuffix(x, ":root") || x == "*" {
						t.Errorf("principal %q in %v", x, s["Sid"])
					}
				}
			}
		}
	}

	admin := d.sid(t, "AllowKeyAdministration")
	if admin["Action"] != "kms:*" || strs(t, admin["Principal"].(map[string]any)["AWS"])[0] != role("deployer") {
		t.Errorf("administrators %v", admin)
	}

	gen := d.sid(t, "AllowCloudTrailGenerateDataKey")
	if gen["Principal"].(map[string]any)["Service"] != "cloudtrail.amazonaws.com" || gen["Action"] != "kms:GenerateDataKey*" {
		t.Errorf("generate data key %v", gen)
	}

	if got := cond(gen, "StringEquals", "aws:SourceArn"); got != trailARN() {
		t.Errorf("SourceArn = %v, want %s", got, trailARN())
	}

	wantCtx := fmt.Sprintf("arn:%s:cloudtrail:*:%s:trail/*", part, mgmtID())
	if got := cond(gen, "StringLike", "kms:EncryptionContext:aws:cloudtrail:arn"); got != wantCtx {
		t.Errorf("encryption context = %v, want %s", got, wantCtx)
	}

	desc := d.sid(t, "AllowCloudTrailDescribe")
	if desc["Action"] != "kms:DescribeKey" || desc["Principal"].(map[string]any)["Service"] != "cloudtrail.amazonaws.com" {
		t.Errorf("describe %v", desc)
	}

	if got := cond(desc, "StringEquals", "aws:SourceArn"); got != trailARN() {
		t.Errorf("describe SourceArn = %v", got)
	}

	rd := d.sid(t, "AllowReadersDecrypt")
	if got := strings.Join(strs(t, rd["Action"]), ","); got != "kms:Decrypt,kms:DescribeKey" {
		t.Errorf("reader actions %s", got)
	}

	if got := strs(t, rd["Principal"].(map[string]any)["AWS"]); len(got) != 2 || got[0] != role("reader-a") || got[1] != role("reader-b") {
		t.Errorf("readers %v", got)
	}
}

func TestKeyPolicyWithoutReaders(t *testing.T) {
	a := full()
	a.Readers = nil

	raw, d := keyPolicyOf(t, a)

	if d.has("AllowReadersDecrypt") || strings.Contains(raw, "kms:Decrypt") {
		t.Errorf("reader statement without readers: %s", raw)
	}

	if len(d.Statement) != 3 {
		t.Errorf("statements = %d, want 3", len(d.Statement))
	}
}

func TestBucketPolicy(t *testing.T) {
	raw, d := bucketPolicyOf(t, full())
	bucket := "ref-of-org-trail-bucket"

	if strings.Contains(raw, ":root") {
		t.Errorf("bucket policy names an account root: %s", raw)
	}

	acl := d.sid(t, "AllowCloudTrailGetBucketAcl")
	if acl["Action"] != "s3:GetBucketAcl" || acl["Resource"] != bucket || cond(acl, "StringEquals", "aws:SourceArn") != trailARN() {
		t.Errorf("get bucket acl %v", acl)
	}

	put := d.sid(t, "AllowCloudTrailPutObject")

	wantRes := []string{bucket + "/AWSLogs/" + mgmtID() + "/*", bucket + "/AWSLogs/" + orgID + "/*"}
	if got := strs(t, put["Resource"]); strings.Join(got, ",") != strings.Join(wantRes, ",") {
		t.Errorf("put resources %v, want %v", got, wantRes)
	}

	if put["Action"] != "s3:PutObject" || put["Principal"].(map[string]any)["Service"] != "cloudtrail.amazonaws.com" {
		t.Errorf("put %v", put)
	}

	if cond(put, "StringEquals", "aws:SourceArn") != trailARN() || cond(put, "StringEquals", "s3:x-amz-acl") != "bucket-owner-full-control" {
		t.Errorf("put conditions %v", put["Condition"])
	}

	rd := d.sid(t, "AllowReadersRead")
	if got := strings.Join(strs(t, rd["Action"]), ","); got != "s3:GetObject,s3:GetObjectVersion,s3:ListBucket,s3:GetBucketLocation" {
		t.Errorf("reader actions %s", got)
	}

	if got := strs(t, rd["Principal"].(map[string]any)["AWS"]); len(got) != 2 || got[0] != role("reader-a") {
		t.Errorf("readers %v", got)
	}

	if got := strs(t, rd["Resource"]); len(got) != 2 || got[0] != bucket || got[1] != bucket+"/*" {
		t.Errorf("reader resources %v", got)
	}

	tls := d.sid(t, "DenyInsecureTransport")
	if tls["Effect"] != "Deny" || cond(tls, "Bool", "aws:SecureTransport") != "false" {
		t.Errorf("tls %v", tls)
	}

	byp := d.sid(t, "DenyBypassGovernanceRetention")
	if byp["Effect"] != "Deny" || byp["Principal"] != "*" || byp["Action"] != "s3:BypassGovernanceRetention" || byp["Resource"] != bucket+"/*" {
		t.Errorf("bypass %v", byp)
	}

	pats := strs(t, cond(byp, "ArnNotLike", "aws:PrincipalArn"))
	if len(pats) != 1 || pats[0] != full().BypassGovernancePrincipals[0] {
		t.Errorf("bypass patterns %v", pats)
	}
}

func TestEveryCloudTrailStatementNamesTheTrail(t *testing.T) {
	_, kd := keyPolicyOf(t, full())
	_, bd := bucketPolicyOf(t, full())

	n := 0

	for _, d := range []policyDoc{kd, bd} {
		for _, s := range d.Statement {
			p, ok := s["Principal"].(map[string]any)
			if !ok || p["Service"] != "cloudtrail.amazonaws.com" {
				continue
			}

			n++

			if got := cond(s, "StringEquals", "aws:SourceArn"); got != trailARN() {
				t.Errorf("%v: SourceArn = %v, want %s", s["Sid"], got, trailARN())
			}
		}
	}

	if n != 4 {
		t.Errorf("CloudTrail statements = %d, want 4", n)
	}
}

func TestBucketPolicyWithoutReaders(t *testing.T) {
	raw, d := bucketPolicyOf(t, withoutReaders(full()))

	if d.has("AllowReadersRead") || strings.Contains(raw, "s3:GetObject") {
		t.Errorf("reader statement without readers: %s", raw)
	}
}

func TestBucketPolicyUnderCompliance(t *testing.T) {
	a := full()
	a.RetentionMode = orgtrail.Compliance
	a.BypassGovernancePrincipals = nil

	raw, d := bucketPolicyOf(t, a)

	if d.has("DenyBypassGovernanceRetention") || strings.Contains(raw, "BypassGovernanceRetention") {
		t.Errorf("bypass statement under COMPLIANCE: %s", raw)
	}
}

func TestPartitionAndRegionReachThePolicies(t *testing.T) {
	a := full()
	a.Partition = "aws-cn"
	a.Region = "cn-north-1"

	m := mustRun(t, a)
	want := fmt.Sprintf("arn:%s:cloudtrail:cn-north-1:%s:trail/%s", a.Partition, mgmtID(), trailName)

	for _, n := range []string{"org-trail-kms-key", "org-trail-bucket-policy"} {
		key := "policy"
		if got := m[n].inputs[resource.PropertyKey(key)].StringValue(); !strings.Contains(got, want) {
			t.Errorf("%s lacks %s: %s", n, want, got)
		}
	}
}

func TestComponentOutputs(t *testing.T) {
	_, got, err := run(t, full(), opt{})
	if err != nil {
		t.Fatal(err)
	}

	want := outs{
		bucketName: "example-org-trail-logs",
		bucketArn:  "ref-of-org-trail-bucket",
		keyArn:     "ref-of-org-trail-kms-key",
		trailArn:   "ref-of-org-trail-trail",
	}

	if got != want {
		t.Errorf("outputs\n got %+v\nwant %+v", got, want)
	}
}

func withoutReaders(a *orgtrail.Args) *orgtrail.Args {
	a.Readers = nil

	return a
}

func TestRefusals(t *testing.T) {
	cases := map[string]struct {
		mutate func(a *orgtrail.Args)
		o      opt
		want   string
	}{
		"no mgmt account":    {func(a *orgtrail.Args) { a.ManagementAccount = "" }, opt{}, "ManagementAccount is empty"},
		"no logs account":    {func(a *orgtrail.Args) { a.LogsAccount = "" }, opt{}, "LogsAccount is empty"},
		"no mgmt provider":   {func(*orgtrail.Args) {}, opt{noMgmt: true}, "ManagementProvider is nil"},
		"no logs provider":   {func(*orgtrail.Args) {}, opt{noLogs: true}, "LogsProvider is nil"},
		"no mgmt id":         {func(a *orgtrail.Args) { a.ManagementAccountID = nil }, opt{}, "ManagementAccountID is unset"},
		"short mgmt id":      {func(a *orgtrail.Args) { a.ManagementAccountID = pulumi.String("12345") }, opt{}, "12-digit"},
		"no org id":          {func(a *orgtrail.Args) { a.OrganizationID = nil }, opt{}, "OrganizationID is unset"},
		"bad org id":         {func(a *orgtrail.Args) { a.OrganizationID = pulumi.String("exampleorg1") }, opt{}, "not an organisation id"},
		"no trail name":      {func(a *orgtrail.Args) { a.TrailName = "" }, opt{}, "TrailName is empty"},
		"bad trail name":     {func(a *orgtrail.Args) { a.TrailName = "a b" }, opt{}, "not a CloudTrail name"},
		"no region":          {func(a *orgtrail.Args) { a.Region = "" }, opt{}, "Region is empty"},
		"bad region":         {func(a *orgtrail.Args) { a.Region = "europe" }, opt{}, "not a region name"},
		"bad partition":      {func(a *orgtrail.Args) { a.Partition = "a:b" }, opt{}, "not a partition name"},
		"no bucket":          {func(a *orgtrail.Args) { a.Bucket = nil }, opt{}, "Bucket is unset"},
		"no alias":           {func(a *orgtrail.Args) { a.KeyAlias = "" }, opt{}, "KeyAlias is empty"},
		"bad alias":          {func(a *orgtrail.Args) { a.KeyAlias = "trail" }, opt{}, "lacks the alias/ prefix"},
		"no key admins":      {func(a *orgtrail.Args) { a.KeyAdministrators = nil }, opt{}, "KeyAdministrators is empty"},
		"nil key admin":      {func(a *orgtrail.Args) { a.KeyAdministrators = []pulumi.StringInput{nil} }, opt{}, "KeyAdministrators[0] is unset"},
		"nil reader":         {func(a *orgtrail.Args) { a.Readers = []pulumi.StringInput{nil} }, opt{}, "Readers[0] is unset"},
		"retention zero":     {func(a *orgtrail.Args) { a.RetentionDays = 0 }, opt{}, "RetentionDays"},
		"retention negative": {func(a *orgtrail.Args) { a.RetentionDays = -3 }, opt{}, "RetentionDays"},
		"no mode":            {func(a *orgtrail.Args) { a.RetentionMode = "" }, opt{}, "RetentionMode"},
		"bad mode":           {func(a *orgtrail.Args) { a.RetentionMode = "governance" }, opt{}, "neither GOVERNANCE nor COMPLIANCE"},
		"glacier equals":     {func(a *orgtrail.Args) { a.GlacierAfterDays = a.RetentionDays }, opt{}, "GlacierAfterDays"},
		"glacier after":      {func(a *orgtrail.Args) { a.GlacierAfterDays = a.RetentionDays + 1 }, opt{}, "GlacierAfterDays"},
		"glacier negative":   {func(a *orgtrail.Args) { a.GlacierAfterDays = -1 }, opt{}, "GlacierAfterDays"},
		"empty bypass":       {func(a *orgtrail.Args) { a.BypassGovernancePrincipals = nil }, opt{}, "BypassGovernancePrincipals is empty"},
		"bypass not an arn":  {func(a *orgtrail.Args) { a.BypassGovernancePrincipals = []string{"*"} }, opt{}, "not an ARN pattern"},
		"bypass bad under comp": {func(a *orgtrail.Args) {
			a.RetentionMode = orgtrail.Compliance
			a.BypassGovernancePrincipals = []string{"x"}
		}, opt{}, "not an ARN pattern"},
		"empty name":    {func(a *orgtrail.Args) { a.Names = func(orgtrail.Child) string { return "" } }, opt{}, "empty name"},
		"repeated name": {func(a *orgtrail.Args) { a.Names = func(orgtrail.Child) string { return "same" } }, opt{}, `returned "same" for both`},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			a := full()
			tc.mutate(a)

			regs, _, err := run(t, a, tc.o)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}

			if n := len(children(regs)); n != 0 {
				t.Fatalf("registered %d children despite refusal", n)
			}
		})
	}
}

func TestComplianceWithoutBypassListIsAccepted(t *testing.T) {
	a := full()
	a.RetentionMode = orgtrail.Compliance
	a.BypassGovernancePrincipals = nil

	if _, _, err := run(t, a, opt{}); err != nil {
		t.Fatal(err)
	}
}

func TestRefusalReportsEveryProblemAtOnce(t *testing.T) {
	a := full()
	a.ManagementAccount = ""
	a.KeyAlias = "x"
	a.KeyAdministrators = nil
	a.RetentionDays = 0
	a.RetentionMode = "WORM"
	a.TrailName = ""

	_, _, err := run(t, a, opt{noMgmt: true, noLogs: true})
	if err == nil {
		t.Fatal("want error")
	}

	for _, w := range []string{
		"ManagementAccount is empty", "ManagementProvider is nil", "LogsProvider is nil", "alias/", "KeyAdministrators",
		"RetentionDays", "RetentionMode", "TrailName",
	} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error lacks %q: %v", w, err)
		}
	}
}

func TestComputedIDsAreCheckedWhenKnown(t *testing.T) {
	a := full()
	a.ManagementAccountID = pulumi.ToOutput("not-an-id").(pulumi.StringOutput)

	_, _, err := run(t, a, opt{})
	if err == nil || !strings.Contains(err.Error(), "12-digit") {
		t.Fatalf("err = %v", err)
	}
}
