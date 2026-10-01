package trail

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/cloudtrail"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/iam"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/kms"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/s3"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// TypeToken is the Pulumi type of the component.
const TypeToken = "truvity:aws-structure:AccountTrail"

const (
	policyVersion = "2012-10-17"
	cloudTrailSvc = "cloudtrail.amazonaws.com"
	s3Svc         = "s3.amazonaws.com"
)

// Kind names which child a logical name is for.
type Kind string

const (
	// KindKey is the KMS key of the trail.
	KindKey Kind = "key"
	// KindKeyAlias is the alias of the KMS key.
	KindKeyAlias Kind = "key-alias"

	// KindTrailBucket is the bucket the trail writes to.
	KindTrailBucket Kind = "trail-bucket"
	// KindTrailBucketPolicy is the policy of the trail bucket.
	KindTrailBucketPolicy Kind = "trail-bucket-policy"
	// KindTrailBucketPublicAccessBlock blocks public access to the trail bucket.
	KindTrailBucketPublicAccessBlock Kind = "trail-bucket-public-access-block"
	// KindTrailBucketEncryption is the default encryption of the trail bucket.
	KindTrailBucketEncryption Kind = "trail-bucket-encryption"
	// KindTrailBucketLifecycle is the lifecycle of the trail bucket.
	KindTrailBucketLifecycle Kind = "trail-bucket-lifecycle"
	// KindTrailBucketLogging turns on access logging of the trail bucket.
	KindTrailBucketLogging Kind = "trail-bucket-logging"
	// KindTrailBucketVersioning is the versioning of the trail bucket.
	KindTrailBucketVersioning Kind = "trail-bucket-versioning"
	// KindTrailBucketReplication is the replication configuration of the
	// trail bucket.
	KindTrailBucketReplication Kind = "trail-bucket-replication"

	// KindLogBucket is the bucket that receives the access logs.
	KindLogBucket Kind = "log-bucket"
	// KindLogBucketOwnership is the ownership controls of the log bucket.
	KindLogBucketOwnership Kind = "log-bucket-ownership"
	// KindLogBucketPublicAccessBlock blocks public access to the log bucket.
	KindLogBucketPublicAccessBlock Kind = "log-bucket-public-access-block"
	// KindLogBucketEncryption is the default encryption of the log bucket.
	KindLogBucketEncryption Kind = "log-bucket-encryption"
	// KindLogBucketPolicy is the policy of the log bucket.
	KindLogBucketPolicy Kind = "log-bucket-policy"
	// KindLogBucketLifecycle is the lifecycle of the log bucket.
	KindLogBucketLifecycle Kind = "log-bucket-lifecycle"

	// KindReplicaBucket is the replica bucket.
	KindReplicaBucket Kind = "replica-bucket"
	// KindReplicaBucketVersioning is the versioning of the replica bucket.
	KindReplicaBucketVersioning Kind = "replica-bucket-versioning"
	// KindReplicaBucketEncryption is the default encryption of the replica bucket.
	KindReplicaBucketEncryption Kind = "replica-bucket-encryption"
	// KindReplicaBucketPublicAccessBlock blocks public access to the replica bucket.
	KindReplicaBucketPublicAccessBlock Kind = "replica-bucket-public-access-block"
	// KindReplicaBucketPolicy is the policy of the replica bucket.
	KindReplicaBucketPolicy Kind = "replica-bucket-policy"
	// KindReplicaBucketLifecycle is the lifecycle of the replica bucket.
	KindReplicaBucketLifecycle Kind = "replica-bucket-lifecycle"

	// KindReplicationRole is the role S3 assumes to replicate.
	KindReplicationRole Kind = "replication-role"
	// KindReplicationRolePolicy is the inline policy of the replication role.
	KindReplicationRolePolicy Kind = "replication-role-policy"

	// KindTrail is the trail.
	KindTrail Kind = "trail"
)

// suffix is the tail of each child's DefaultName.
var suffix = map[Kind]string{
	KindKey:                            "kms-key",
	KindKeyAlias:                       "kms-alias",
	KindTrailBucket:                    "bucket",
	KindTrailBucketPolicy:              "bucket-policy",
	KindTrailBucketPublicAccessBlock:   "public-access-block",
	KindTrailBucketEncryption:          "sse",
	KindTrailBucketLifecycle:           "lifecycle",
	KindTrailBucketLogging:             "logging",
	KindTrailBucketVersioning:          "versioning",
	KindTrailBucketReplication:         "replication",
	KindLogBucket:                      "access-log-bucket",
	KindLogBucketOwnership:             "access-log-ownership",
	KindLogBucketPublicAccessBlock:     "access-log-public-access-block",
	KindLogBucketEncryption:            "access-log-sse",
	KindLogBucketPolicy:                "access-log-bucket-policy",
	KindLogBucketLifecycle:             "access-log-lifecycle",
	KindReplicaBucket:                  "replica-bucket",
	KindReplicaBucketVersioning:        "replica-versioning",
	KindReplicaBucketEncryption:        "replica-sse",
	KindReplicaBucketPublicAccessBlock: "replica-public-access-block",
	KindReplicaBucketPolicy:            "replica-bucket-policy",
	KindReplicaBucketLifecycle:         "replica-lifecycle",
	KindReplicationRole:                "replication-role",
	KindReplicationRolePolicy:          "replication-policy",
	KindTrail:                          "trail",
}

// kinds lists every child in registration order.
var kinds = []Kind{
	KindKey, KindKeyAlias,
	KindTrailBucket, KindTrailBucketPolicy, KindTrailBucketPublicAccessBlock, KindTrailBucketEncryption, KindTrailBucketLifecycle,
	KindLogBucket, KindLogBucketOwnership, KindLogBucketPublicAccessBlock, KindLogBucketEncryption, KindLogBucketPolicy,
	KindLogBucketLifecycle, KindTrailBucketLogging,
	KindTrailBucketVersioning,
	KindReplicaBucket, KindReplicaBucketVersioning, KindReplicaBucketEncryption, KindReplicaBucketPublicAccessBlock,
	KindReplicaBucketPolicy, KindReplicaBucketLifecycle,
	KindReplicationRole, KindReplicationRolePolicy, KindTrailBucketReplication,
	KindTrail,
}

// Child identifies one child for a NameFunc.
type Child struct {
	// Component is the logical name the component was registered with.
	Component string
	Kind      Kind
	// Account is Args.Account.
	Account string
}

// NameFunc returns the Pulumi logical name of a child. The returned name must
// be unique among the component's children; it is part of the child's URN.
type NameFunc func(Child) string

// DefaultName names a child "<c>-<tail>": "<c>-kms-key", "<c>-kms-alias",
// "<c>-bucket", "<c>-bucket-policy", "<c>-public-access-block", "<c>-sse",
// "<c>-lifecycle", "<c>-logging", "<c>-versioning", "<c>-replication",
// "<c>-access-log-bucket", "<c>-access-log-ownership",
// "<c>-access-log-public-access-block", "<c>-access-log-sse",
// "<c>-access-log-bucket-policy", "<c>-access-log-lifecycle",
// "<c>-replica-bucket", "<c>-replica-versioning", "<c>-replica-sse",
// "<c>-replica-public-access-block", "<c>-replica-bucket-policy",
// "<c>-replica-lifecycle", "<c>-replication-role", "<c>-replication-policy"
// and "<c>-trail". These names are API.
func DefaultName(c Child) string {
	return c.Component + "-" + suffix[c.Kind]
}

// Buckets are the physical names of the three buckets. Bucket names are
// global to AWS, so the caller owns them.
type Buckets struct {
	// Trail receives the trail's log files.
	Trail pulumi.StringInput
	// AccessLog receives the S3 access logs of the trail bucket.
	AccessLog pulumi.StringInput
	// Replica is the cross-region copy of the trail bucket.
	Replica pulumi.StringInput
}

// ReplicationRole is the role S3 assumes to copy the trail bucket to the
// replica bucket.
type ReplicationRole struct {
	// Name is the role's name.
	Name string
	// PermissionsBoundary is the ARN of the boundary policy set on the role.
	// Required: a role without a boundary can grow past it.
	PermissionsBoundary pulumi.StringInput
}

// Args configures the component.
type Args struct {
	// Account is the account's name. Required; it only feeds Child.Account.
	Account string

	// Buckets are the bucket names.
	Buckets Buckets
	// KeyAlias is the alias of the KMS key, "alias/<name>".
	KeyAlias string
	// KeyAdministrator is the ARN of the principal the key policy lets manage
	// the key with kms:* (the account root).
	KeyAdministrator pulumi.StringInput
	// TrailARN is the ARN, wildcards allowed, of the trails the key policy
	// lets use the key (every trail of the account in the region).
	TrailARN pulumi.StringInput
	// DataEventResource is the value of the trail's S3 data-event selector:
	// the S3 ARN whose object events are logged. The ARN of every S3 object
	// logs them all.
	DataEventResource string
	// ReplicationRole is the role replication runs as.
	ReplicationRole ReplicationRole

	// Provider is the AWS provider of the account in the trail's region. It
	// creates everything except the replica bucket and what hangs on it.
	// Required.
	Provider pulumi.ProviderResource
	// ReplicaProvider is the AWS provider of the account in the replica's
	// region. Required.
	ReplicaProvider pulumi.ProviderResource

	// Names overrides the logical names of the children. Nil uses
	// DefaultName.
	Names NameFunc
	// LegacyTopLevel makes every child carry an alias from the URN it has
	// when it is registered directly under the stack (no parent), with the
	// same type and the name Names gives it. Set it when adopting resources
	// that were created before they were wrapped in this component.
	LegacyTopLevel bool
}

// AccountTrail is the component.
type AccountTrail struct {
	pulumi.ResourceState
}

// Validate reports every problem with args at once, or returns nil.
func (a *Args) Validate() error {
	var errs []error

	if a.Account == "" {
		errs = append(errs, errors.New("args: Account is empty"))
	}

	if a.Provider == nil {
		errs = append(errs, errors.New("args: Provider is nil"))
	}

	if a.ReplicaProvider == nil {
		errs = append(errs, errors.New("args: ReplicaProvider is nil"))
	}

	if a.Buckets.Trail == nil {
		errs = append(errs, errors.New("args: Buckets.Trail is unset"))
	}

	if a.Buckets.AccessLog == nil {
		errs = append(errs, errors.New("args: Buckets.AccessLog is unset"))
	}

	if a.Buckets.Replica == nil {
		errs = append(errs, errors.New("args: Buckets.Replica is unset"))
	}

	switch {
	case a.KeyAlias == "":
		errs = append(errs, errors.New("args: KeyAlias is empty"))
	case !strings.HasPrefix(a.KeyAlias, "alias/"):
		errs = append(errs, fmt.Errorf("args: KeyAlias %q lacks the alias/ prefix", a.KeyAlias))
	}

	if a.KeyAdministrator == nil {
		errs = append(errs, errors.New("args: KeyAdministrator is unset"))
	}

	if a.TrailARN == nil {
		errs = append(errs, errors.New("args: TrailARN is unset"))
	}

	if a.DataEventResource == "" {
		errs = append(errs, errors.New("args: DataEventResource is empty"))
	}

	if a.ReplicationRole.Name == "" {
		errs = append(errs, errors.New("args: ReplicationRole.Name is empty"))
	}

	if a.ReplicationRole.PermissionsBoundary == nil {
		errs = append(errs, errors.New("args: ReplicationRole.PermissionsBoundary is unset"))
	}

	errs = append(errs, a.checkNames("")...)

	return errors.Join(errs...)
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
		n := names(Child{Component: component, Kind: k, Account: a.Account})

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

// builder registers the children of one component.
type builder struct {
	ctx   *pulumi.Context
	name  string
	names NameFunc
	args  *Args
	comp  *AccountTrail
}

func (b *builder) child(k Kind) string {
	return b.names(Child{Component: b.name, Kind: k, Account: b.args.Account})
}

func (b *builder) opts(p pulumi.ProviderResource, extra ...pulumi.ResourceOption) []pulumi.ResourceOption {
	o := []pulumi.ResourceOption{pulumi.Parent(b.comp), pulumi.Provider(p)}
	if b.args.LegacyTopLevel {
		o = append(o, pulumi.Aliases([]pulumi.Alias{{NoParent: pulumi.Bool(true)}}))
	}

	return append(o, extra...)
}

// New registers the component and its children. It returns an error,
// registering nothing, when args.Validate does or when Names returns an empty
// or repeated name.
//
// The providers come from Args, not from pulumi.Providers.
func New(ctx *pulumi.Context, name string, args *Args, opts ...pulumi.ResourceOption) (*AccountTrail, error) {
	if args == nil {
		return nil, errors.New("trail: args is nil")
	}

	if err := args.Validate(); err != nil {
		return nil, fmt.Errorf("trail %s: %w", name, err)
	}

	if err := errors.Join(args.checkNames(name)...); err != nil {
		return nil, fmt.Errorf("trail %s: %w", name, err)
	}

	names := args.Names
	if names == nil {
		names = DefaultName
	}

	comp := &AccountTrail{}
	if err := ctx.RegisterComponentResource(TypeToken, name, comp, opts...); err != nil {
		return nil, err
	}

	b := &builder{ctx: ctx, name: name, names: names, args: args, comp: comp}

	key, err := b.newKey()
	if err != nil {
		return nil, err
	}

	bucket, policy, err := b.newTrailBucket(key)
	if err != nil {
		return nil, err
	}

	if err := b.newAccessLogging(bucket); err != nil {
		return nil, err
	}

	if err := b.newReplication(bucket); err != nil {
		return nil, err
	}

	if _, err := cloudtrail.NewTrail(ctx, b.child(KindTrail), &cloudtrail.TrailArgs{
		S3BucketName:               bucket.ID(),
		KmsKeyId:                   key.Arn,
		IsMultiRegionTrail:         pulumi.Bool(true),
		EnableLogFileValidation:    pulumi.Bool(true),
		IncludeGlobalServiceEvents: pulumi.Bool(true),
		IsOrganizationTrail:        pulumi.Bool(false),
		EventSelectors: cloudtrail.TrailEventSelectorArray{
			&cloudtrail.TrailEventSelectorArgs{
				ReadWriteType:           pulumi.String("All"),
				IncludeManagementEvents: pulumi.Bool(true),
				DataResources: cloudtrail.TrailEventSelectorDataResourceArray{
					&cloudtrail.TrailEventSelectorDataResourceArgs{
						Type:   pulumi.String("AWS::S3::Object"),
						Values: pulumi.StringArray{pulumi.String(args.DataEventResource)},
					},
				},
			},
		},
	}, b.opts(args.Provider, pulumi.DependsOn([]pulumi.Resource{bucket, policy}))...); err != nil {
		return nil, fmt.Errorf("create trail in %s: %w", args.Account, err)
	}

	if err := ctx.RegisterResourceOutputs(comp, pulumi.Map{}); err != nil {
		return nil, err
	}

	return comp, nil
}

func (b *builder) newKey() (*kms.Key, error) {
	a := b.args

	policy := pulumi.All(a.KeyAdministrator, a.TrailARN).ApplyT(func(v []any) (string, error) {
		return keyPolicy(v[0].(string), v[1].(string))
	}).(pulumi.StringOutput)

	key, err := kms.NewKey(b.ctx, b.child(KindKey), &kms.KeyArgs{
		Description:       pulumi.String("CloudTrail encryption key"),
		Policy:            policy,
		EnableKeyRotation: pulumi.Bool(true),
	}, b.opts(a.Provider)...)
	if err != nil {
		return nil, fmt.Errorf("create KMS key in %s: %w", a.Account, err)
	}

	if _, err := kms.NewAlias(b.ctx, b.child(KindKeyAlias), &kms.AliasArgs{
		Name:        pulumi.String(a.KeyAlias),
		TargetKeyId: key.KeyId,
	}, b.opts(a.Provider)...); err != nil {
		return nil, fmt.Errorf("create KMS alias in %s: %w", a.Account, err)
	}

	return key, nil
}

func publicAccessBlock(bucketID pulumi.StringInput) *s3.BucketPublicAccessBlockArgs {
	return &s3.BucketPublicAccessBlockArgs{
		Bucket:                bucketID,
		BlockPublicAcls:       pulumi.Bool(true),
		BlockPublicPolicy:     pulumi.Bool(true),
		IgnorePublicAcls:      pulumi.Bool(true),
		RestrictPublicBuckets: pulumi.Bool(true),
	}
}

func aes256(bucketID pulumi.StringInput) *s3.BucketServerSideEncryptionConfigurationV2Args {
	return &s3.BucketServerSideEncryptionConfigurationV2Args{
		Bucket: bucketID,
		Rules: s3.BucketServerSideEncryptionConfigurationV2RuleArray{
			&s3.BucketServerSideEncryptionConfigurationV2RuleArgs{
				ApplyServerSideEncryptionByDefault: &s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs{
					SseAlgorithm: pulumi.String("AES256"),
				},
			},
		},
	}
}

func versioning(bucketID pulumi.StringInput) *s3.BucketVersioningV2Args {
	return &s3.BucketVersioningV2Args{
		Bucket: bucketID,
		VersioningConfiguration: &s3.BucketVersioningV2VersioningConfigurationArgs{
			Status: pulumi.String("Enabled"),
		},
	}
}

func (b *builder) newTrailBucket(key *kms.Key) (*s3.Bucket, *s3.BucketPolicy, error) {
	a := b.args
	acct := a.Account

	bucket, err := s3.NewBucket(b.ctx, b.child(KindTrailBucket), &s3.BucketArgs{
		Bucket: a.Buckets.Trail,
	}, b.opts(a.Provider)...)
	if err != nil {
		return nil, nil, fmt.Errorf("create trail bucket in %s: %w", acct, err)
	}

	policy, err := s3.NewBucketPolicy(b.ctx, b.child(KindTrailBucketPolicy), &s3.BucketPolicyArgs{
		Bucket: bucket.ID(),
		Policy: bucket.Arn.ApplyT(trailBucketPolicy).(pulumi.StringOutput),
	}, b.opts(a.Provider)...)
	if err != nil {
		return nil, nil, fmt.Errorf("create trail bucket policy in %s: %w", acct, err)
	}

	if _, err := s3.NewBucketPublicAccessBlock(b.ctx, b.child(KindTrailBucketPublicAccessBlock),
		publicAccessBlock(bucket.ID()), b.opts(a.Provider)...); err != nil {
		return nil, nil, fmt.Errorf("create trail bucket public access block in %s: %w", acct, err)
	}

	if _, err := s3.NewBucketServerSideEncryptionConfigurationV2(b.ctx, b.child(KindTrailBucketEncryption),
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
		}, b.opts(a.Provider)...); err != nil {
		return nil, nil, fmt.Errorf("create trail bucket encryption in %s: %w", acct, err)
	}

	if _, err := s3.NewBucketLifecycleConfigurationV2(b.ctx, b.child(KindTrailBucketLifecycle),
		&s3.BucketLifecycleConfigurationV2Args{
			Bucket: bucket.ID(),
			Rules: s3.BucketLifecycleConfigurationV2RuleArray{
				&s3.BucketLifecycleConfigurationV2RuleArgs{
					Id:     pulumi.String("cloudtrail-archive"),
					Status: pulumi.String("Enabled"),
					Transitions: s3.BucketLifecycleConfigurationV2RuleTransitionArray{
						&s3.BucketLifecycleConfigurationV2RuleTransitionArgs{
							Days:         pulumi.Int(90),
							StorageClass: pulumi.String("GLACIER"),
						},
					},
					Expiration: &s3.BucketLifecycleConfigurationV2RuleExpirationArgs{
						Days: pulumi.Int(365),
					},
				},
			},
		}, b.opts(a.Provider)...); err != nil {
		return nil, nil, fmt.Errorf("create trail bucket lifecycle in %s: %w", acct, err)
	}

	return bucket, policy, nil
}

func (b *builder) newAccessLogging(bucket *s3.Bucket) error {
	a := b.args
	acct := a.Account

	logBucket, err := s3.NewBucket(b.ctx, b.child(KindLogBucket), &s3.BucketArgs{
		Bucket: a.Buckets.AccessLog,
	}, b.opts(a.Provider)...)
	if err != nil {
		return fmt.Errorf("create access log bucket in %s: %w", acct, err)
	}

	// BucketOwnerEnforced ownership: required for S3 access log delivery.
	if _, err := s3.NewBucketOwnershipControls(b.ctx, b.child(KindLogBucketOwnership), &s3.BucketOwnershipControlsArgs{
		Bucket: logBucket.ID(),
		Rule: &s3.BucketOwnershipControlsRuleArgs{
			ObjectOwnership: pulumi.String("BucketOwnerEnforced"),
		},
	}, b.opts(a.Provider)...); err != nil {
		return fmt.Errorf("set access log bucket ownership in %s: %w", acct, err)
	}

	if _, err := s3.NewBucketPublicAccessBlock(b.ctx, b.child(KindLogBucketPublicAccessBlock),
		publicAccessBlock(logBucket.ID()), b.opts(a.Provider)...); err != nil {
		return fmt.Errorf("block access log bucket public access in %s: %w", acct, err)
	}

	if _, err := s3.NewBucketServerSideEncryptionConfigurationV2(b.ctx, b.child(KindLogBucketEncryption),
		aes256(logBucket.ID()), b.opts(a.Provider)...); err != nil {
		return fmt.Errorf("configure access log bucket encryption in %s: %w", acct, err)
	}

	if _, err := s3.NewBucketPolicy(b.ctx, b.child(KindLogBucketPolicy), &s3.BucketPolicyArgs{
		Bucket: logBucket.ID(),
		Policy: logBucket.Arn.ApplyT(httpsOnlyBucketPolicy).(pulumi.StringOutput),
	}, b.opts(a.Provider)...); err != nil {
		return fmt.Errorf("create access log bucket policy in %s: %w", acct, err)
	}

	if _, err := s3.NewBucketLifecycleConfigurationV2(b.ctx, b.child(KindLogBucketLifecycle),
		&s3.BucketLifecycleConfigurationV2Args{
			Bucket: logBucket.ID(),
			Rules: s3.BucketLifecycleConfigurationV2RuleArray{
				&s3.BucketLifecycleConfigurationV2RuleArgs{
					Id:     pulumi.String("expire-logs"),
					Status: pulumi.String("Enabled"),
					Expiration: &s3.BucketLifecycleConfigurationV2RuleExpirationArgs{
						Days: pulumi.Int(365),
					},
				},
			},
		}, b.opts(a.Provider)...); err != nil {
		return fmt.Errorf("configure access log bucket lifecycle in %s: %w", acct, err)
	}

	if _, err := s3.NewBucketLoggingV2(b.ctx, b.child(KindTrailBucketLogging), &s3.BucketLoggingV2Args{
		Bucket:       bucket.ID(),
		TargetBucket: logBucket.ID(),
		TargetPrefix: pulumi.String("cloudtrail/"),
	}, b.opts(a.Provider)...); err != nil {
		return fmt.Errorf("enable trail bucket logging in %s: %w", acct, err)
	}

	return nil
}

func (b *builder) newReplication(source *s3.Bucket) error {
	a := b.args
	acct := a.Account

	sourceVersioning, err := s3.NewBucketVersioningV2(b.ctx, b.child(KindTrailBucketVersioning),
		versioning(source.ID()), b.opts(a.Provider)...)
	if err != nil {
		return fmt.Errorf("enable trail bucket versioning in %s: %w", acct, err)
	}

	replica, err := s3.NewBucket(b.ctx, b.child(KindReplicaBucket), &s3.BucketArgs{
		Bucket: a.Buckets.Replica,
	}, b.opts(a.ReplicaProvider)...)
	if err != nil {
		return fmt.Errorf("create replica bucket in %s: %w", acct, err)
	}

	replicaVersioning, err := s3.NewBucketVersioningV2(b.ctx, b.child(KindReplicaBucketVersioning),
		versioning(replica.ID()), b.opts(a.ReplicaProvider)...)
	if err != nil {
		return fmt.Errorf("enable replica bucket versioning in %s: %w", acct, err)
	}

	if _, err := s3.NewBucketServerSideEncryptionConfigurationV2(b.ctx, b.child(KindReplicaBucketEncryption),
		aes256(replica.ID()), b.opts(a.ReplicaProvider)...); err != nil {
		return fmt.Errorf("configure replica bucket encryption in %s: %w", acct, err)
	}

	if _, err := s3.NewBucketPublicAccessBlock(b.ctx, b.child(KindReplicaBucketPublicAccessBlock),
		publicAccessBlock(replica.ID()), b.opts(a.ReplicaProvider)...); err != nil {
		return fmt.Errorf("block replica bucket public access in %s: %w", acct, err)
	}

	if _, err := s3.NewBucketPolicy(b.ctx, b.child(KindReplicaBucketPolicy), &s3.BucketPolicyArgs{
		Bucket: replica.ID(),
		Policy: replica.Arn.ApplyT(httpsOnlyBucketPolicy).(pulumi.StringOutput),
	}, b.opts(a.ReplicaProvider)...); err != nil {
		return fmt.Errorf("create replica bucket policy in %s: %w", acct, err)
	}

	// Glacier Instant Retrieval at once, expire after 365 days.
	if _, err := s3.NewBucketLifecycleConfigurationV2(b.ctx, b.child(KindReplicaBucketLifecycle),
		&s3.BucketLifecycleConfigurationV2Args{
			Bucket: replica.ID(),
			Rules: s3.BucketLifecycleConfigurationV2RuleArray{
				&s3.BucketLifecycleConfigurationV2RuleArgs{
					Id:     pulumi.String("glacier-ir-transition"),
					Status: pulumi.String("Enabled"),
					Transitions: s3.BucketLifecycleConfigurationV2RuleTransitionArray{
						&s3.BucketLifecycleConfigurationV2RuleTransitionArgs{
							Days:         pulumi.Int(0),
							StorageClass: pulumi.String("GLACIER_IR"),
						},
					},
					Expiration: &s3.BucketLifecycleConfigurationV2RuleExpirationArgs{
						Days: pulumi.Int(365),
					},
				},
			},
		}, b.opts(a.ReplicaProvider)...); err != nil {
		return fmt.Errorf("configure replica bucket lifecycle in %s: %w", acct, err)
	}

	role, err := b.newReplicationRole(source, replica)
	if err != nil {
		return err
	}

	if _, err := s3.NewBucketReplicationConfig(b.ctx, b.child(KindTrailBucketReplication), &s3.BucketReplicationConfigArgs{
		Bucket: source.ID(),
		Role:   role.Arn,
		Rules: s3.BucketReplicationConfigRuleArray{
			&s3.BucketReplicationConfigRuleArgs{
				Id:     pulumi.String("replicate-all"),
				Status: pulumi.String("Enabled"),
				Filter: &s3.BucketReplicationConfigRuleFilterArgs{},
				DeleteMarkerReplication: &s3.BucketReplicationConfigRuleDeleteMarkerReplicationArgs{
					Status: pulumi.String("Enabled"),
				},
				Destination: &s3.BucketReplicationConfigRuleDestinationArgs{
					Bucket:       replica.Arn,
					StorageClass: pulumi.String("STANDARD"),
				},
			},
		},
	}, b.opts(a.Provider, pulumi.DependsOn([]pulumi.Resource{sourceVersioning, replicaVersioning}))...); err != nil {
		return fmt.Errorf("configure replication in %s: %w", acct, err)
	}

	return nil
}

func (b *builder) newReplicationRole(source, replica *s3.Bucket) (*iam.Role, error) {
	a := b.args

	trust, err := json.Marshal(map[string]any{
		"Version": policyVersion,
		"Statement": []map[string]any{{
			"Effect":    "Allow",
			"Principal": map[string]any{"Service": s3Svc},
			"Action":    "sts:AssumeRole",
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal replication trust policy: %w", err)
	}

	role, err := iam.NewRole(b.ctx, b.child(KindReplicationRole), &iam.RoleArgs{
		Name:                pulumi.String(a.ReplicationRole.Name),
		AssumeRolePolicy:    pulumi.String(string(trust)),
		PermissionsBoundary: a.ReplicationRole.PermissionsBoundary,
	}, b.opts(a.Provider)...)
	if err != nil {
		return nil, fmt.Errorf("create replication role in %s: %w", a.Account, err)
	}

	doc := pulumi.All(source.Arn, replica.Arn).ApplyT(func(v []any) (string, error) {
		return replicationPolicy(v[0].(string), v[1].(string))
	}).(pulumi.StringOutput)

	if _, err := iam.NewRolePolicy(b.ctx, b.child(KindReplicationRolePolicy), &iam.RolePolicyArgs{
		Role:   role.Name,
		Policy: doc,
	}, b.opts(a.Provider)...); err != nil {
		return nil, fmt.Errorf("create replication role policy in %s: %w", a.Account, err)
	}

	return role, nil
}

// replicationPolicy renders the inline policy of the replication role.
func replicationPolicy(src, dst string) (string, error) {
	doc, err := json.Marshal(map[string]any{
		"Version": policyVersion,
		"Statement": []map[string]any{
			{
				"Effect":   "Allow",
				"Action":   []string{"s3:GetReplicationConfiguration", "s3:ListBucket"},
				"Resource": src,
			},
			{
				"Effect": "Allow",
				"Action": []string{
					"s3:GetObjectVersionForReplication",
					"s3:GetObjectVersionAcl",
					"s3:GetObjectVersionTagging",
				},
				"Resource": src + "/*",
			},
			{
				"Effect": "Allow",
				"Action": []string{
					"s3:ReplicateObject",
					"s3:ReplicateDelete",
					"s3:ReplicateTags",
					"s3:ObjectOwnerOverrideToBucketOwner",
				},
				"Resource": dst + "/*",
			},
		},
	})

	return string(doc), err
}

// keyPolicy renders the key policy. The statement and field order is fixed:
// the document is a resource input, and a change in layout is an update.
func keyPolicy(administrator, trailARN string) (string, error) {
	type (
		statement struct {
			Sid       string            `json:"Sid"`
			Effect    string            `json:"Effect"`
			Principal map[string]string `json:"Principal"`
			Action    any               `json:"Action"`
			Resource  string            `json:"Resource"`
			Condition map[string]any    `json:"Condition,omitempty"`
		}
		document struct {
			Version   string      `json:"Version"`
			Statement []statement `json:"Statement"`
		}
	)

	b, err := json.Marshal(document{
		Version: policyVersion,
		Statement: []statement{
			{
				Sid:       "AllowRootKeyManagement",
				Effect:    "Allow",
				Principal: map[string]string{"AWS": administrator},
				Action:    "kms:*",
				Resource:  "*",
			},
			{
				Sid:       "AllowCloudTrailEncryptDecrypt",
				Effect:    "Allow",
				Principal: map[string]string{"Service": cloudTrailSvc},
				Action:    []string{"kms:GenerateDataKey*", "kms:Decrypt"},
				Resource:  "*",
				Condition: map[string]any{
					"StringLike": map[string]string{
						"kms:EncryptionContext:aws:cloudtrail:arn": trailARN,
					},
				},
			},
			{
				Sid:       "AllowCloudTrailDescribe",
				Effect:    "Allow",
				Principal: map[string]string{"Service": cloudTrailSvc},
				Action:    "kms:DescribeKey",
				Resource:  "*",
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("marshal key policy: %w", err)
	}

	return string(b), nil
}

// trailBucketPolicy renders the trail bucket's policy: CloudTrail may read
// the ACL and put objects, and everything must use HTTPS.
func trailBucketPolicy(bucketARN string) (string, error) {
	type (
		statement struct {
			Sid       string `json:"Sid"`
			Effect    string `json:"Effect"`
			Principal any    `json:"Principal"`
			Action    any    `json:"Action"`
			Resource  any    `json:"Resource"`
			Condition any    `json:"Condition,omitempty"`
		}
		document struct {
			Version   string      `json:"Version"`
			Statement []statement `json:"Statement"`
		}
	)

	b, err := json.Marshal(document{
		Version: policyVersion,
		Statement: []statement{
			{
				Sid:       "AllowCloudTrailGetBucketAcl",
				Effect:    "Allow",
				Principal: map[string]string{"Service": cloudTrailSvc},
				Action:    "s3:GetBucketAcl",
				Resource:  bucketARN,
			},
			{
				Sid:       "AllowCloudTrailPutObject",
				Effect:    "Allow",
				Principal: map[string]string{"Service": cloudTrailSvc},
				Action:    "s3:PutObject",
				Resource:  bucketARN + "/*",
				Condition: map[string]any{
					"StringEquals": map[string]string{"s3:x-amz-acl": "bucket-owner-full-control"},
				},
			},
			{
				Sid:       "DenyInsecureTransport",
				Effect:    "Deny",
				Principal: "*",
				Action:    "s3:*",
				Resource:  []string{bucketARN, bucketARN + "/*"},
				Condition: map[string]any{
					"Bool": map[string]string{"aws:SecureTransport": "false"},
				},
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("marshal trail bucket policy: %w", err)
	}

	return string(b), nil
}

// httpsOnlyBucketPolicy renders a policy that denies all non-HTTPS traffic,
// used for the access-log and replica buckets.
func httpsOnlyBucketPolicy(bucketARN string) (string, error) {
	type (
		statement struct {
			Sid       string `json:"Sid"`
			Effect    string `json:"Effect"`
			Principal string `json:"Principal"`
			Action    string `json:"Action"`
			Resource  any    `json:"Resource"`
			Condition any    `json:"Condition,omitempty"`
		}
		document struct {
			Version   string      `json:"Version"`
			Statement []statement `json:"Statement"`
		}
	)

	b, err := json.Marshal(document{
		Version: policyVersion,
		Statement: []statement{
			{
				Sid:       "DenyInsecureTransport",
				Effect:    "Deny",
				Principal: "*",
				Action:    "s3:*",
				Resource:  []string{bucketARN, bucketARN + "/*"},
				Condition: map[string]any{
					"Bool": map[string]string{"aws:SecureTransport": "false"},
				},
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("marshal HTTPS-only bucket policy: %w", err)
	}

	return string(b), nil
}
