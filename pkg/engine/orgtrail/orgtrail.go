package orgtrail

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/cloudtrail"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/kms"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/s3"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// TypeToken is the Pulumi type of the component.
const TypeToken = "truvity:aws-structure:OrgTrail"

const (
	policyVersion = "2012-10-17"
	cloudTrailSvc = "cloudtrail.amazonaws.com"

	// DefaultPartition is the partition used when Args.Partition is empty.
	DefaultPartition = "aws"

	// Governance is the Object Lock mode that principals holding
	// s3:BypassGovernanceRetention can override.
	Governance = "GOVERNANCE"
	// Compliance is the Object Lock mode nobody can override: it can never be
	// shortened or removed, the account root included.
	Compliance = "COMPLIANCE"

	// abortMultipartDays and noncurrentDays are fixed: they only clean up.
	abortMultipartDays = 7
	noncurrentDays     = 1
)

var (
	accountIDRe = regexp.MustCompile(`^[0-9]{12}$`)
	orgIDRe     = regexp.MustCompile(`^o-[a-z0-9]{10,32}$`)
	regionRe    = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)
	partitionRe = regexp.MustCompile(`^aws(-[a-z]+)*$`)
	trailNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$`)
)

// Kind names which child a logical name is for.
type Kind string

const (
	// KindKey is the KMS key of the trail.
	KindKey Kind = "key"
	// KindKeyAlias is the alias of the KMS key.
	KindKeyAlias Kind = "key-alias"
	// KindBucket is the log bucket.
	KindBucket Kind = "bucket"
	// KindBucketVersioning is the versioning of the log bucket.
	KindBucketVersioning Kind = "bucket-versioning"
	// KindBucketObjectLock is the Object Lock default retention of the bucket.
	KindBucketObjectLock Kind = "bucket-object-lock"
	// KindBucketPublicAccessBlock blocks public access to the bucket.
	KindBucketPublicAccessBlock Kind = "bucket-public-access-block"
	// KindBucketEncryption is the default encryption of the bucket.
	KindBucketEncryption Kind = "bucket-encryption"
	// KindBucketOwnership is the ownership controls of the bucket.
	KindBucketOwnership Kind = "bucket-ownership"
	// KindBucketLifecycle is the lifecycle of the bucket.
	KindBucketLifecycle Kind = "bucket-lifecycle"
	// KindBucketPolicy is the policy of the bucket.
	KindBucketPolicy Kind = "bucket-policy"
	// KindTrail is the organisation trail.
	KindTrail Kind = "trail"
)

// suffix is the tail of each child's DefaultName.
var suffix = map[Kind]string{
	KindKey:                     "kms-key",
	KindKeyAlias:                "kms-alias",
	KindBucket:                  "bucket",
	KindBucketVersioning:        "versioning",
	KindBucketObjectLock:        "object-lock",
	KindBucketPublicAccessBlock: "public-access-block",
	KindBucketEncryption:        "sse",
	KindBucketOwnership:         "ownership",
	KindBucketLifecycle:         "lifecycle",
	KindBucketPolicy:            "bucket-policy",
	KindTrail:                   "trail",
}

// kinds lists every child in registration order.
var kinds = []Kind{
	KindKey, KindKeyAlias,
	KindBucket, KindBucketVersioning, KindBucketObjectLock, KindBucketPublicAccessBlock,
	KindBucketEncryption, KindBucketOwnership, KindBucketLifecycle, KindBucketPolicy,
	KindTrail,
}

// Child identifies one child for a NameFunc.
type Child struct {
	// Component is the logical name the component was registered with.
	Component string
	Kind      Kind
	// ManagementAccount is Args.ManagementAccount.
	ManagementAccount string
	// LogsAccount is Args.LogsAccount.
	LogsAccount string
}

// NameFunc returns the Pulumi logical name of a child. The returned name must
// be unique among the component's children; it is part of the child's URN.
type NameFunc func(Child) string

// DefaultName names a child "<c>-<tail>": "<c>-kms-key", "<c>-kms-alias",
// "<c>-bucket", "<c>-versioning", "<c>-object-lock", "<c>-public-access-block",
// "<c>-sse", "<c>-ownership", "<c>-lifecycle", "<c>-bucket-policy" and
// "<c>-trail". These names are API.
func DefaultName(c Child) string {
	return c.Component + "-" + suffix[c.Kind]
}

// Args configures the component.
type Args struct {
	// ManagementAccount is the name of the organisation's management account.
	// Required; it only feeds error messages and Child.ManagementAccount.
	ManagementAccount string
	// LogsAccount is the name of the account that holds the bucket and the
	// key. Required; it only feeds error messages and Child.LogsAccount.
	LogsAccount string

	// ManagementAccountID is the 12-digit id of the management account. It is
	// written into the trail ARN and the bucket path of the policies.
	ManagementAccountID pulumi.StringInput
	// OrganizationID is the organisation id ("o-" and lower-case letters and
	// digits). The trail writes under AWSLogs/<OrganizationID>/.
	OrganizationID pulumi.StringInput

	// TrailName is the physical name of the CloudTrail trail. The policies
	// name the exact trail ARN
	// "arn:<Partition>:cloudtrail:<Region>:<ManagementAccountID>:trail/<TrailName>",
	// so only that trail may use the bucket and the key.
	TrailName string
	// Region is the region of the ManagementProvider, where the trail is
	// created ("eu-west-1"). It is not looked up: it is an argument so the
	// policies are known without a provider call and a test can see them. It
	// must match the provider; a trail created elsewhere is refused by S3 and
	// KMS.
	Region string
	// Partition is the AWS partition of the ManagementProvider. Empty means
	// "aws".
	Partition string

	// Bucket is the physical name of the log bucket. Bucket names are global
	// to AWS, so the caller owns it.
	Bucket pulumi.StringInput
	// KeyAlias is the alias of the KMS key, "alias/<name>".
	KeyAlias string
	// KeyAdministrators are the ARNs of the principals the key policy lets
	// manage the key (kms:*). At least one. There is no statement for the
	// account root: pass the role the stack deploys with in the logs account,
	// so the principal that creates the key stays in its policy.
	KeyAdministrators []pulumi.StringInput
	// Readers are the ARNs of the roles, in either account, that may read the
	// logs: s3:GetObject, s3:GetObjectVersion, s3:ListBucket and
	// s3:GetBucketLocation on the bucket, kms:Decrypt and kms:DescribeKey on
	// the key. The roles must already exist (S3 and KMS refuse a policy naming
	// a principal that does not). Optional.
	Readers []pulumi.StringInput

	// RetentionDays is the default Object Lock retention of every log file, in
	// days. Positive. Current versions also expire at this age.
	RetentionDays int
	// RetentionMode is the Object Lock mode: "GOVERNANCE" or "COMPLIANCE".
	//
	// COMPLIANCE can never be shortened or removed by anyone, the account
	// root included, and the bucket cannot be emptied or deleted until every
	// object's retention ends. Under GOVERNANCE a principal with
	// s3:BypassGovernanceRetention can delete locked objects; see
	// BypassGovernancePrincipals.
	RetentionMode string
	// BypassGovernancePrincipals are ARN patterns (a "*" is allowed) of the
	// principals that may use s3:BypassGovernanceRetention. Everyone else is
	// denied by the bucket policy. Required, non-empty, under GOVERNANCE, so
	// that someone can still repair a mistake. Ignored under COMPLIANCE
	// (nothing can bypass it), but still checked for shape if set.
	BypassGovernancePrincipals []string
	// GlacierAfterDays moves current versions to Glacier after that many
	// days. Optional: 0 means no transition. When set it must be less than
	// RetentionDays.
	GlacierAfterDays int

	// ManagementProvider is the AWS provider of the management account, in
	// the region Region. It creates the trail. Required.
	ManagementProvider pulumi.ProviderResource
	// LogsProvider is the AWS provider of the logs account. It creates the
	// key and the bucket. Required.
	LogsProvider pulumi.ProviderResource

	// Names overrides the logical names of the children. Nil uses
	// DefaultName.
	Names NameFunc
}

// OrgTrail is the component.
type OrgTrail struct {
	pulumi.ResourceState

	// BucketName is the physical name of the log bucket.
	BucketName pulumi.StringOutput `pulumi:"bucketName"`
	// BucketArn is the ARN of the log bucket.
	BucketArn pulumi.StringOutput `pulumi:"bucketArn"`
	// KeyArn is the ARN of the KMS key.
	KeyArn pulumi.StringOutput `pulumi:"keyArn"`
	// TrailArn is the ARN of the trail.
	TrailArn pulumi.StringOutput `pulumi:"trailArn"`
}

// literal returns the string behind an input that is a plain pulumi.String.
// Anything computed is not known until the program runs and is checked then.
func literal(in pulumi.StringInput) (string, bool) {
	s, ok := in.(pulumi.String)

	return string(s), ok
}

// Validate reports every problem with args at once, or returns nil.
func (a *Args) Validate() error {
	var errs []error

	if a.ManagementAccount == "" {
		errs = append(errs, errors.New("args: ManagementAccount is empty"))
	}

	if a.LogsAccount == "" {
		errs = append(errs, errors.New("args: LogsAccount is empty"))
	}

	if a.ManagementProvider == nil {
		errs = append(errs, errors.New("args: ManagementProvider is nil"))
	}

	if a.LogsProvider == nil {
		errs = append(errs, errors.New("args: LogsProvider is nil"))
	}

	errs = append(errs, a.checkIdentity()...)
	errs = append(errs, a.checkKey()...)
	errs = append(errs, a.checkRetention()...)
	errs = append(errs, a.checkNames("")...)

	return errors.Join(errs...)
}

func (a *Args) checkIdentity() []error {
	var errs []error

	if a.ManagementAccountID == nil {
		errs = append(errs, errors.New("args: ManagementAccountID is unset"))
	} else if v, ok := literal(a.ManagementAccountID); ok && !accountIDRe.MatchString(v) {
		errs = append(errs, errors.New("args: ManagementAccountID is not a 12-digit account id"))
	}

	if a.OrganizationID == nil {
		errs = append(errs, errors.New("args: OrganizationID is unset"))
	} else if v, ok := literal(a.OrganizationID); ok && !orgIDRe.MatchString(v) {
		errs = append(errs, fmt.Errorf("args: OrganizationID %q is not an organisation id (o-...)", v))
	}

	switch {
	case a.TrailName == "":
		errs = append(errs, errors.New("args: TrailName is empty"))
	case !trailNameRe.MatchString(a.TrailName):
		errs = append(errs, fmt.Errorf("args: TrailName %q is not a CloudTrail name (3-128 of letters, digits, '.', '_', '-')", a.TrailName))
	}

	switch {
	case a.Region == "":
		errs = append(errs, errors.New("args: Region is empty"))
	case !regionRe.MatchString(a.Region):
		errs = append(errs, fmt.Errorf("args: Region %q is not a region name", a.Region))
	}

	if a.Partition != "" && !partitionRe.MatchString(a.Partition) {
		errs = append(errs, fmt.Errorf("args: Partition %q is not a partition name", a.Partition))
	}

	if a.Bucket == nil {
		errs = append(errs, errors.New("args: Bucket is unset"))
	}

	return errs
}

func (a *Args) checkKey() []error {
	var errs []error

	switch {
	case a.KeyAlias == "":
		errs = append(errs, errors.New("args: KeyAlias is empty"))
	case !strings.HasPrefix(a.KeyAlias, "alias/"):
		errs = append(errs, fmt.Errorf("args: KeyAlias %q lacks the alias/ prefix", a.KeyAlias))
	}

	if len(a.KeyAdministrators) == 0 {
		errs = append(errs, errors.New("args: KeyAdministrators is empty"))
	}

	for i, p := range a.KeyAdministrators {
		if p == nil {
			errs = append(errs, fmt.Errorf("args: KeyAdministrators[%d] is unset", i))
		}
	}

	for i, p := range a.Readers {
		if p == nil {
			errs = append(errs, fmt.Errorf("args: Readers[%d] is unset", i))
		}
	}

	return errs
}

func (a *Args) checkRetention() []error {
	var errs []error

	if a.RetentionDays <= 0 {
		errs = append(errs, fmt.Errorf("args: RetentionDays is %d, want a positive number", a.RetentionDays))
	}

	switch a.RetentionMode {
	case Governance, Compliance:
	default:
		errs = append(errs, fmt.Errorf("args: RetentionMode %q is neither %s nor %s", a.RetentionMode, Governance, Compliance))
	}

	if a.RetentionMode == Governance && len(a.BypassGovernancePrincipals) == 0 {
		errs = append(errs, errors.New("args: BypassGovernancePrincipals is empty under GOVERNANCE: nobody could repair a mistake"))
	}

	for _, p := range a.BypassGovernancePrincipals {
		if err := checkARNPattern(p); err != nil {
			errs = append(errs, err)
		}
	}

	switch {
	case a.GlacierAfterDays < 0:
		errs = append(errs, fmt.Errorf("args: GlacierAfterDays is %d, want 0 or a positive number", a.GlacierAfterDays))
	case a.GlacierAfterDays > 0 && a.RetentionDays > 0 && a.GlacierAfterDays >= a.RetentionDays:
		errs = append(errs, fmt.Errorf("args: GlacierAfterDays (%d) is not before RetentionDays (%d)", a.GlacierAfterDays, a.RetentionDays))
	}

	return errs
}

// checkARNPattern refuses a BypassGovernancePrincipals entry that is not an
// ARN, possibly with wildcards: "arn:<partition>:<service>:<region>:<account>:<resource>".
func checkARNPattern(p string) error {
	parts := strings.SplitN(p, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] == "" || parts[2] == "" || parts[5] == "" || strings.ContainsAny(p, " \t\n") {
		return fmt.Errorf("args: BypassGovernancePrincipals entry %q is not an ARN pattern", p)
	}

	return nil
}

// checkNames refuses a naming hook that returns an empty or repeated name.
func (a *Args) checkNames(component string) []error {
	names := a.Names
	if names == nil {
		names = DefaultName
	}

	var errs []error

	seen := map[string]Kind{}

	for _, k := range kinds {
		n := names(Child{Component: component, Kind: k, ManagementAccount: a.ManagementAccount, LogsAccount: a.LogsAccount})

		if n == "" {
			errs = append(errs, fmt.Errorf("args: Names returned an empty name for %s", k))

			continue
		}

		if prev, dup := seen[n]; dup {
			errs = append(errs, fmt.Errorf("args: Names returned %q for both %s and %s", n, prev, k))
		}

		seen[n] = k
	}

	return errs
}

// partition returns the partition, "aws" when none is set.
func (a *Args) partition() string {
	if a.Partition == "" {
		return DefaultPartition
	}

	return a.Partition
}

// builder registers the children of one component.
type builder struct {
	ctx   *pulumi.Context
	name  string
	names NameFunc
	args  *Args
	comp  *OrgTrail
}

func (b *builder) child(k Kind) string {
	return b.names(Child{Component: b.name, Kind: k, ManagementAccount: b.args.ManagementAccount, LogsAccount: b.args.LogsAccount})
}

func (b *builder) opts(p pulumi.ProviderResource, extra ...pulumi.ResourceOption) []pulumi.ResourceOption {
	return append([]pulumi.ResourceOption{pulumi.Parent(b.comp), pulumi.Provider(p)}, extra...)
}

// New registers the component and its children. It returns an error,
// registering nothing, when args.Validate does or when Names returns an empty
// or repeated name.
//
// The providers come from Args, not from pulumi.Providers.
func New(ctx *pulumi.Context, name string, args *Args, opts ...pulumi.ResourceOption) (*OrgTrail, error) {
	if args == nil {
		return nil, errors.New("orgtrail: args is nil")
	}

	if err := args.Validate(); err != nil {
		return nil, fmt.Errorf("orgtrail %s: %w", name, err)
	}

	if err := errors.Join(args.checkNames(name)...); err != nil {
		return nil, fmt.Errorf("orgtrail %s: %w", name, err)
	}

	names := args.Names
	if names == nil {
		names = DefaultName
	}

	comp := &OrgTrail{}
	if err := ctx.RegisterComponentResource(TypeToken, name, comp, opts...); err != nil {
		return nil, err
	}

	b := &builder{ctx: ctx, name: name, names: names, args: args, comp: comp}

	key, err := b.newKey()
	if err != nil {
		return nil, err
	}

	bucket, deps, err := b.newBucket(key)
	if err != nil {
		return nil, err
	}

	// The trail is created in the management account, after everything it
	// needs in the logs account is in place: CloudTrail checks the bucket
	// policy and the key when the trail is created.
	tr, err := cloudtrail.NewTrail(ctx, b.child(KindTrail), &cloudtrail.TrailArgs{
		Name:                       pulumi.String(args.TrailName),
		S3BucketName:               bucket.ID(),
		KmsKeyId:                   key.Arn,
		IsOrganizationTrail:        pulumi.Bool(true),
		IsMultiRegionTrail:         pulumi.Bool(true),
		EnableLogFileValidation:    pulumi.Bool(true),
		IncludeGlobalServiceEvents: pulumi.Bool(true),
		// Management events only: no data resources.
		EventSelectors: cloudtrail.TrailEventSelectorArray{
			&cloudtrail.TrailEventSelectorArgs{
				ReadWriteType:           pulumi.String("All"),
				IncludeManagementEvents: pulumi.Bool(true),
			},
		},
	}, b.opts(args.ManagementProvider, pulumi.DependsOn(append([]pulumi.Resource{bucket, key}, deps...)))...)
	if err != nil {
		return nil, fmt.Errorf("create trail in %s: %w", args.ManagementAccount, err)
	}

	comp.BucketName = bucket.Bucket
	comp.BucketArn = bucket.Arn
	comp.KeyArn = key.Arn
	comp.TrailArn = tr.Arn

	if err := ctx.RegisterResourceOutputs(comp, pulumi.Map{
		"bucketName": comp.BucketName,
		"bucketArn":  comp.BucketArn,
		"keyArn":     comp.KeyArn,
		"trailArn":   comp.TrailArn,
	}); err != nil {
		return nil, err
	}

	return comp, nil
}

// trailARN returns the ARN of the trail the policies name.
func (a *Args) trailARN(accountID string) string {
	return fmt.Sprintf("arn:%s:cloudtrail:%s:%s:trail/%s", a.partition(), a.Region, accountID, a.TrailName)
}

// checkResolved refuses an account or organisation id that was computed and so
// could not be checked by Validate.
func checkResolved(accountID, orgID string) error {
	var errs []error

	if !accountIDRe.MatchString(accountID) {
		errs = append(errs, errors.New("ManagementAccountID is not a 12-digit account id"))
	}

	if !orgIDRe.MatchString(orgID) {
		errs = append(errs, fmt.Errorf("OrganizationID %q is not an organisation id (o-...)", orgID))
	}

	return errors.Join(errs...)
}

// stringsOf resolves a list of inputs to one output.
func stringsOf(in []pulumi.StringInput) pulumi.StringArrayOutput {
	arr := make(pulumi.StringArray, 0, len(in))
	for _, i := range in {
		arr = append(arr, i)
	}

	return arr.ToStringArrayOutput()
}

func (b *builder) newKey() (*kms.Key, error) {
	a := b.args

	policy := pulumi.All(a.ManagementAccountID, a.OrganizationID, stringsOf(a.KeyAdministrators), stringsOf(a.Readers)).
		ApplyT(func(v []any) (string, error) {
			if err := checkResolved(v[0].(string), v[1].(string)); err != nil {
				return "", fmt.Errorf("key policy: %w", err)
			}

			return keyPolicy(a.partition(), a.trailARN(v[0].(string)), v[0].(string), v[2].([]string), v[3].([]string))
		}).(pulumi.StringOutput)

	key, err := kms.NewKey(b.ctx, b.child(KindKey), &kms.KeyArgs{
		Description:       pulumi.String("Organisation trail encryption key"),
		Policy:            policy,
		EnableKeyRotation: pulumi.Bool(true),
	}, b.opts(a.LogsProvider)...)
	if err != nil {
		return nil, fmt.Errorf("create KMS key in %s: %w", a.LogsAccount, err)
	}

	if _, err := kms.NewAlias(b.ctx, b.child(KindKeyAlias), &kms.AliasArgs{
		Name:        pulumi.String(a.KeyAlias),
		TargetKeyId: key.KeyId,
	}, b.opts(a.LogsProvider)...); err != nil {
		return nil, fmt.Errorf("create KMS alias in %s: %w", a.LogsAccount, err)
	}

	return key, nil
}

// newBucket creates the log bucket and its configuration. It returns the
// bucket and the resources the trail must wait for: the bucket policy and the
// Object Lock configuration.
func (b *builder) newBucket(key *kms.Key) (*s3.Bucket, []pulumi.Resource, error) {
	a := b.args
	acct := a.LogsAccount

	bucket, err := s3.NewBucket(b.ctx, b.child(KindBucket), &s3.BucketArgs{
		Bucket: a.Bucket,
		// Object Lock can only be enabled when the bucket is created; there is
		// no later switch, so a bucket made without it must be replaced.
		ObjectLockEnabled: pulumi.Bool(true),
	}, b.opts(a.LogsProvider)...)
	if err != nil {
		return nil, nil, fmt.Errorf("create bucket in %s: %w", acct, err)
	}

	// Object Lock requires versioning.
	versioning, err := s3.NewBucketVersioningV2(b.ctx, b.child(KindBucketVersioning), &s3.BucketVersioningV2Args{
		Bucket: bucket.ID(),
		VersioningConfiguration: &s3.BucketVersioningV2VersioningConfigurationArgs{
			Status: pulumi.String("Enabled"),
		},
	}, b.opts(a.LogsProvider)...)
	if err != nil {
		return nil, nil, fmt.Errorf("enable bucket versioning in %s: %w", acct, err)
	}

	lock, err := s3.NewBucketObjectLockConfigurationV2(b.ctx, b.child(KindBucketObjectLock), &s3.BucketObjectLockConfigurationV2Args{
		Bucket: bucket.ID(),
		Rule: &s3.BucketObjectLockConfigurationV2RuleArgs{
			DefaultRetention: &s3.BucketObjectLockConfigurationV2RuleDefaultRetentionArgs{
				Mode: pulumi.String(a.RetentionMode),
				Days: pulumi.Int(a.RetentionDays),
			},
		},
	}, b.opts(a.LogsProvider, pulumi.DependsOn([]pulumi.Resource{versioning}))...)
	if err != nil {
		return nil, nil, fmt.Errorf("configure bucket object lock in %s: %w", acct, err)
	}

	pab, err := s3.NewBucketPublicAccessBlock(b.ctx, b.child(KindBucketPublicAccessBlock), &s3.BucketPublicAccessBlockArgs{
		Bucket:                bucket.ID(),
		BlockPublicAcls:       pulumi.Bool(true),
		BlockPublicPolicy:     pulumi.Bool(true),
		IgnorePublicAcls:      pulumi.Bool(true),
		RestrictPublicBuckets: pulumi.Bool(true),
	}, b.opts(a.LogsProvider)...)
	if err != nil {
		return nil, nil, fmt.Errorf("create bucket public access block in %s: %w", acct, err)
	}

	if _, err := s3.NewBucketServerSideEncryptionConfigurationV2(b.ctx, b.child(KindBucketEncryption),
		&s3.BucketServerSideEncryptionConfigurationV2Args{
			Bucket: bucket.ID(),
			Rules: s3.BucketServerSideEncryptionConfigurationV2RuleArray{
				&s3.BucketServerSideEncryptionConfigurationV2RuleArgs{
					ApplyServerSideEncryptionByDefault: &s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs{
						SseAlgorithm:   pulumi.String("aws:kms"),
						KmsMasterKeyId: key.Arn,
					},
					BucketKeyEnabled: pulumi.Bool(true),
				},
			},
		}, b.opts(a.LogsProvider)...); err != nil {
		return nil, nil, fmt.Errorf("create bucket encryption in %s: %w", acct, err)
	}

	ownership, err := s3.NewBucketOwnershipControls(b.ctx, b.child(KindBucketOwnership), &s3.BucketOwnershipControlsArgs{
		Bucket: bucket.ID(),
		Rule: &s3.BucketOwnershipControlsRuleArgs{
			ObjectOwnership: pulumi.String("BucketOwnerEnforced"),
		},
	}, b.opts(a.LogsProvider)...)
	if err != nil {
		return nil, nil, fmt.Errorf("set bucket ownership in %s: %w", acct, err)
	}

	if _, err := s3.NewBucketLifecycleConfigurationV2(b.ctx, b.child(KindBucketLifecycle), &s3.BucketLifecycleConfigurationV2Args{
		Bucket: bucket.ID(),
		Rules:  s3.BucketLifecycleConfigurationV2RuleArray{lifecycleRule(a)},
	}, b.opts(a.LogsProvider, pulumi.DependsOn([]pulumi.Resource{versioning}))...); err != nil {
		return nil, nil, fmt.Errorf("create bucket lifecycle in %s: %w", acct, err)
	}

	policy := pulumi.All(bucket.Arn, a.ManagementAccountID, a.OrganizationID, stringsOf(a.Readers)).
		ApplyT(func(v []any) (string, error) {
			if err := checkResolved(v[1].(string), v[2].(string)); err != nil {
				return "", fmt.Errorf("bucket policy: %w", err)
			}

			return bucketPolicy(bucketPolicyParams{
				bucketARN: v[0].(string),
				trailARN:  a.trailARN(v[1].(string)),
				mgmtID:    v[1].(string),
				orgID:     v[2].(string),
				readers:   v[3].([]string),
				mode:      a.RetentionMode,
				bypass:    a.BypassGovernancePrincipals,
			})
		}).(pulumi.StringOutput)

	// The policy goes in after the public access block and the ownership
	// controls: S3 refuses concurrent changes to one bucket's settings.
	bp, err := s3.NewBucketPolicy(b.ctx, b.child(KindBucketPolicy), &s3.BucketPolicyArgs{
		Bucket: bucket.ID(),
		Policy: policy,
	}, b.opts(a.LogsProvider, pulumi.DependsOn([]pulumi.Resource{pab, ownership}))...)
	if err != nil {
		return nil, nil, fmt.Errorf("create bucket policy in %s: %w", acct, err)
	}

	return bucket, []pulumi.Resource{bp, lock}, nil
}

// lifecycleRule returns the one lifecycle rule. Objects stay protected by
// Object Lock until retention ends; the rule only cleans up after.
func lifecycleRule(a *Args) *s3.BucketLifecycleConfigurationV2RuleArgs {
	rule := &s3.BucketLifecycleConfigurationV2RuleArgs{
		Id:     pulumi.String("expire-after-retention"),
		Status: pulumi.String("Enabled"),
		Filter: &s3.BucketLifecycleConfigurationV2RuleFilterArgs{},
		Expiration: &s3.BucketLifecycleConfigurationV2RuleExpirationArgs{
			Days: pulumi.Int(a.RetentionDays),
		},
		NoncurrentVersionExpiration: &s3.BucketLifecycleConfigurationV2RuleNoncurrentVersionExpirationArgs{
			NoncurrentDays: pulumi.Int(noncurrentDays),
		},
		AbortIncompleteMultipartUpload: &s3.BucketLifecycleConfigurationV2RuleAbortIncompleteMultipartUploadArgs{
			DaysAfterInitiation: pulumi.Int(abortMultipartDays),
		},
	}

	if a.GlacierAfterDays > 0 {
		rule.Transitions = s3.BucketLifecycleConfigurationV2RuleTransitionArray{
			&s3.BucketLifecycleConfigurationV2RuleTransitionArgs{
				Days:         pulumi.Int(a.GlacierAfterDays),
				StorageClass: pulumi.String("GLACIER"),
			},
		}
	}

	return rule
}

type statement struct {
	Sid       string `json:"Sid"`
	Effect    string `json:"Effect"`
	Principal any    `json:"Principal"`
	Action    any    `json:"Action"`
	Resource  any    `json:"Resource"`
	Condition any    `json:"Condition,omitempty"`
}

type document struct {
	Version   string      `json:"Version"`
	Statement []statement `json:"Statement"`
}

func render(what string, st []statement) (string, error) {
	b, err := json.Marshal(document{Version: policyVersion, Statement: st})
	if err != nil {
		return "", fmt.Errorf("marshal %s: %w", what, err)
	}

	return string(b), nil
}

// keyPolicy renders the key policy. The statement and field order is fixed:
// the document is a resource input, and a change in layout is an update.
//
// There is no statement for the account root. The administrators are named
// principals; the reader statement is present only when there are readers.
func keyPolicy(partition, trailARN, mgmtID string, admins, readers []string) (string, error) {
	st := []statement{
		{
			Sid:       "AllowKeyAdministration",
			Effect:    "Allow",
			Principal: map[string][]string{"AWS": admins},
			Action:    "kms:*",
			Resource:  "*",
		},
		{
			Sid:       "AllowCloudTrailGenerateDataKey",
			Effect:    "Allow",
			Principal: map[string]string{"Service": cloudTrailSvc},
			Action:    "kms:GenerateDataKey*",
			Resource:  "*",
			Condition: map[string]any{
				"StringEquals": map[string]string{"aws:SourceArn": trailARN},
				"StringLike": map[string]string{
					"kms:EncryptionContext:aws:cloudtrail:arn": fmt.Sprintf("arn:%s:cloudtrail:*:%s:trail/*", partition, mgmtID),
				},
			},
		},
		{
			Sid:       "AllowCloudTrailDescribe",
			Effect:    "Allow",
			Principal: map[string]string{"Service": cloudTrailSvc},
			Action:    "kms:DescribeKey",
			Resource:  "*",
			Condition: map[string]any{
				"StringEquals": map[string]string{"aws:SourceArn": trailARN},
			},
		},
	}

	if len(readers) > 0 {
		st = append(st, statement{
			Sid:       "AllowReadersDecrypt",
			Effect:    "Allow",
			Principal: map[string][]string{"AWS": readers},
			Action:    []string{"kms:Decrypt", "kms:DescribeKey"},
			Resource:  "*",
		})
	}

	return render("key policy", st)
}

type bucketPolicyParams struct {
	bucketARN, trailARN, mgmtID, orgID string
	readers                            []string
	mode                               string
	bypass                             []string
}

// bucketPolicy renders the bucket policy: CloudTrail may read the ACL and put
// objects for the one trail, the readers may read, everything must use TLS
// and, under GOVERNANCE, only the named principals may bypass the lock.
func bucketPolicy(p bucketPolicyParams) (string, error) {
	trailCond := map[string]string{"aws:SourceArn": p.trailARN}

	st := []statement{
		{
			Sid:       "AllowCloudTrailGetBucketAcl",
			Effect:    "Allow",
			Principal: map[string]string{"Service": cloudTrailSvc},
			Action:    "s3:GetBucketAcl",
			Resource:  p.bucketARN,
			Condition: map[string]any{"StringEquals": trailCond},
		},
		{
			Sid:       "AllowCloudTrailPutObject",
			Effect:    "Allow",
			Principal: map[string]string{"Service": cloudTrailSvc},
			Action:    "s3:PutObject",
			Resource: []string{
				p.bucketARN + "/AWSLogs/" + p.mgmtID + "/*",
				p.bucketARN + "/AWSLogs/" + p.orgID + "/*",
			},
			Condition: map[string]any{
				"StringEquals": map[string]string{
					"s3:x-amz-acl":  "bucket-owner-full-control",
					"aws:SourceArn": p.trailARN,
				},
			},
		},
	}

	if len(p.readers) > 0 {
		st = append(st, statement{
			Sid:       "AllowReadersRead",
			Effect:    "Allow",
			Principal: map[string][]string{"AWS": p.readers},
			Action:    []string{"s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket", "s3:GetBucketLocation"},
			Resource:  []string{p.bucketARN, p.bucketARN + "/*"},
		})
	}

	st = append(st, statement{
		Sid:       "DenyInsecureTransport",
		Effect:    "Deny",
		Principal: "*",
		Action:    "s3:*",
		Resource:  []string{p.bucketARN, p.bucketARN + "/*"},
		Condition: map[string]any{
			"Bool": map[string]string{"aws:SecureTransport": "false"},
		},
	})

	// Under COMPLIANCE nothing can bypass the lock, so the statement would
	// say nothing.
	if p.mode == Governance {
		st = append(st, statement{
			Sid:       "DenyBypassGovernanceRetention",
			Effect:    "Deny",
			Principal: "*",
			Action:    "s3:BypassGovernanceRetention",
			Resource:  p.bucketARN + "/*",
			Condition: map[string]any{
				"ArnNotLike": map[string][]string{"aws:PrincipalArn": p.bypass},
			},
		})
	}

	return render("bucket policy", st)
}
