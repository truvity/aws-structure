package backend

import (
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/iam"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/kms"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/s3"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

const (
	namePrefix = "pulumi-state"

	// noncurrentDays is how long a noncurrent version of a state object stays.
	noncurrentDays = 30
)

var accountIDPattern = regexp.MustCompile(`^\d{12}$`)

// Bucket describes one state bucket.
type Bucket struct {
	// Account is the account's name. Required; it scopes every logical name
	// and output of the bucket.
	Account string
	// AccountID is the 12-digit id of the account. Required unless
	// DynamicName is set; it only feeds the naming helpers and Validate.
	AccountID string
	// Name is the bucket's name. Required unless DynamicName is set.
	Name string
	// DynamicName overrides Name when the name is a Pulumi output.
	DynamicName pulumi.StringInput
	// KMSAlias is the alias of the key, with its "alias/" prefix. Required.
	KMSAlias string
	// ExistingKeyARN is the ARN of a key that already exists in the bucket's
	// account and region (an EKS cluster's, say). Empty: NewBucket creates the
	// bucket's own key, as it always did. Set: no key is created, KMSAlias
	// points at this key, the bucket encrypts with it and the replication role
	// may decrypt with it. The key's policy is the caller's; it must let the
	// bucket's writers, the replication role and the readers use the key
	// through S3. The replica bucket keeps its own key in ReplicaRegion.
	ExistingKeyARN string
	// LegacyKeyAlias is used with ExistingKeyARN. It keeps the key the bucket
	// had (logical names unchanged: "<prefix>/kms-key") instead of letting
	// Pulumi delete it, marks it retain-on-delete and gives it this alias
	// (with its "alias/" prefix), so objects and data keys still encrypted
	// under it stay readable by anything that names a key by alias. Empty with
	// ExistingKeyARN: the old key leaves the program, and, being retained, is
	// not deleted by Pulumi; schedule its deletion yourself. A permission
	// boundary that denies kms:ScheduleKeyDeletion would fail a Pulumi delete.
	LegacyKeyAlias string
	// Region is the bucket's region. Required.
	Region string
	// ReplicaRegion is the region of the replica. Required by NewReplication.
	ReplicaRegion string
	// ReplicaName is the replica bucket's name. Required by NewReplication.
	ReplicaName string
	// ReplicaTags are the tags of the replica bucket.
	ReplicaTags map[string]string
}

// Result holds what NewBucket created, for NewReplication.
type Result struct {
	Bucket *s3.Bucket
	// KMSKey is the key this library declares: the bucket's own key, or, with
	// Bucket.ExistingKeyARN and Bucket.LegacyKeyAlias, the retained old key.
	// Nil with ExistingKeyARN and no LegacyKeyAlias.
	KMSKey *kms.Key
	// KMSKeyArn is the ARN of the key the bucket encrypts with.
	KMSKeyArn pulumi.StringOutput
}

// BucketName returns the name a state bucket of accountID in region has:
// "pulumi-state-<accountID>-<region>".
func BucketName(accountID, region string) string {
	return fmt.Sprintf("%s-%s-%s", namePrefix, accountID, region)
}

// KMSAlias returns the alias a state bucket's key has: "alias/pulumi-state".
func KMSAlias() string {
	return "alias/" + namePrefix
}

// URL returns the Pulumi backend URL of a state bucket.
func URL(accountID, region, profile string) string {
	return fmt.Sprintf("s3://%s?awssdk=v2&region=%s&profile=%s", BucketName(accountID, region), region, profile)
}

// Validate refuses a Bucket that cannot be deployed, all problems at once.
func (b Bucket) Validate() error {
	var errs []error

	if b.Account == "" {
		errs = append(errs, errors.New("account name must not be empty"))
	}

	if b.Region == "" {
		errs = append(errs, errors.New("region must not be empty"))
	}

	if b.KMSAlias == "" {
		errs = append(errs, errors.New("KMS alias must not be empty"))
	}

	if b.DynamicName == nil {
		if !accountIDPattern.MatchString(b.AccountID) {
			errs = append(errs, fmt.Errorf("account ID must be 12 digits, got: %q", b.AccountID))
		}

		if want := BucketName(b.AccountID, b.Region); b.Name != want {
			errs = append(errs, fmt.Errorf("bucket name %q does not match expected %q", b.Name, want))
		}
	}

	errs = append(errs, b.validateKey()...)

	return errors.Join(errs...)
}

var keyARNPattern = regexp.MustCompile(`^arn:([a-z-]+):kms:([a-z0-9-]+):(\d{12}):key/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)

// validateKey checks ExistingKeyARN and LegacyKeyAlias.
func (b Bucket) validateKey() []error {
	var errs []error

	if b.ExistingKeyARN == "" {
		if b.LegacyKeyAlias != "" {
			errs = append(errs, errors.New("LegacyKeyAlias needs ExistingKeyARN"))
		}

		return errs
	}

	m := keyARNPattern.FindStringSubmatch(b.ExistingKeyARN)
	switch {
	case m == nil:
		errs = append(errs, fmt.Errorf("existing key ARN must be a single-region key ARN (key/<uuid>), got: %q", b.ExistingKeyARN))
	case b.Region != "" && m[2] != b.Region:
		errs = append(errs, fmt.Errorf("existing key is in %s, the bucket in %s", m[2], b.Region))
	case b.DynamicName == nil && b.AccountID != "" && m[3] != b.AccountID:
		errs = append(errs, fmt.Errorf("existing key is in account %s, the bucket in %s", m[3], b.AccountID))
	}

	if b.LegacyKeyAlias != "" {
		switch {
		case !strings.HasPrefix(b.LegacyKeyAlias, "alias/") || strings.HasPrefix(b.LegacyKeyAlias, "alias/aws/"):
			errs = append(errs, fmt.Errorf("legacy key alias must start with alias/ and not alias/aws/, got: %q", b.LegacyKeyAlias))
		case b.LegacyKeyAlias == b.KMSAlias:
			errs = append(errs, errors.New("legacy key alias must differ from KMSAlias"))
		}
	}

	return errs
}

// ValidateSet refuses a set of buckets that repeat an account or a bucket name,
// on top of each bucket's own refusals.
func ValidateSet(buckets []Bucket) error {
	seenAccounts := make(map[string]struct{}, len(buckets))
	seenNames := make(map[string]struct{}, len(buckets))

	for i := range buckets {
		b := &buckets[i]

		if err := b.Validate(); err != nil {
			return fmt.Errorf("bucket[%d] (%s): %w", i, b.Account, err)
		}

		if _, dup := seenAccounts[b.Account]; dup {
			return fmt.Errorf("duplicate account name: %q", b.Account)
		}

		seenAccounts[b.Account] = struct{}{}

		if _, dup := seenNames[b.Name]; dup {
			return fmt.Errorf("duplicate bucket name: %q", b.Name)
		}

		seenNames[b.Name] = struct{}{}
	}

	return nil
}

type replicaBucket struct {
	bucket     *s3.Bucket
	kmsKey     *kms.Key
	versioning *s3.BucketVersioning
}

// newKMSKeyWithAlias creates a KMS key with automatic rotation and an alias.
// Resource names: {prefix}/kms-key, {prefix}/kms-alias.
func newKMSKeyWithAlias(
	c *pulumi.Context,
	prefix string,
	description pulumi.StringInput,
	alias string,
	provider *aws.Provider,
) (*kms.Key, error) {
	kmsKey, err := kms.NewKey(c, prefix+"/kms-key", &kms.KeyArgs{
		Description:       description,
		EnableKeyRotation: pulumi.Bool(true),
	}, pulumi.Provider(provider))
	if err != nil {
		return nil, fmt.Errorf("create KMS key (%s): %w", prefix, err)
	}

	_, err = kms.NewAlias(c, prefix+"/kms-alias", &kms.AliasArgs{
		Name:        pulumi.String(alias),
		TargetKeyId: kmsKey.KeyId,
	}, pulumi.Provider(provider))
	if err != nil {
		return nil, fmt.Errorf("create KMS alias (%s): %w", prefix, err)
	}

	return kmsKey, nil
}

// stateKeyDescription is the description of a state bucket's own key.
func stateKeyDescription(account string) pulumi.StringInput {
	return pulumi.Sprintf("KMS key for Pulumi state bucket (%s)", account)
}

// newStateKey returns the key the bucket encrypts with, as an ARN, and the key
// this library declares for it (see Result.KMSKey).
//
// Without Bucket.ExistingKeyARN it creates the key and its alias. With it,
// there is no new key: the alias {prefix}/kms-alias points at the existing
// key, and the key the bucket had is kept under Bucket.LegacyKeyAlias, or left
// to go. The logical names are those of the first case, so the alias moves
// rather than being replaced.
func newStateKey(
	c *pulumi.Context,
	prefix string,
	b Bucket,
	provider *aws.Provider,
) (*kms.Key, pulumi.StringOutput, error) {
	if b.ExistingKeyARN == "" {
		key, err := newKMSKeyWithAlias(c, prefix, stateKeyDescription(b.Account), b.KMSAlias, provider)
		if err != nil {
			return nil, pulumi.StringOutput{}, err
		}

		return key, key.Arn, nil
	}

	var legacy *kms.Key

	if b.LegacyKeyAlias != "" {
		key, err := kms.NewKey(c, prefix+"/kms-key", &kms.KeyArgs{
			Description:       stateKeyDescription(b.Account),
			EnableKeyRotation: pulumi.Bool(true),
		}, pulumi.Provider(provider), pulumi.RetainOnDelete(true))
		if err != nil {
			return nil, pulumi.StringOutput{}, fmt.Errorf("keep legacy KMS key (%s): %w", prefix, err)
		}

		_, err = kms.NewAlias(c, prefix+"/kms-legacy-alias", &kms.AliasArgs{
			Name:        pulumi.String(b.LegacyKeyAlias),
			TargetKeyId: key.KeyId,
		}, pulumi.Provider(provider))
		if err != nil {
			return nil, pulumi.StringOutput{}, fmt.Errorf("create legacy KMS alias (%s): %w", prefix, err)
		}

		legacy = key
	}

	_, err := kms.NewAlias(c, prefix+"/kms-alias", &kms.AliasArgs{
		Name:        pulumi.String(b.KMSAlias),
		TargetKeyId: pulumi.String(b.ExistingKeyARN),
	}, pulumi.Provider(provider))
	if err != nil {
		return nil, pulumi.StringOutput{}, fmt.Errorf("create KMS alias (%s): %w", prefix, err)
	}

	return legacy, pulumi.String(b.ExistingKeyARN).ToStringOutput(), nil
}

// applyBucketBaseline enables versioning, configures SSE-KMS encryption with
// bucket key, blocks all public access and refuses non-TLS requests.
// Resource names: {prefix}/bucket-versioning, /bucket-encryption, /bucket-pab,
// /bucket-https-policy. Returns the versioning resource (replication depends
// on it).
func applyBucketBaseline(
	c *pulumi.Context,
	prefix string,
	bucket *s3.Bucket,
	keyARN pulumi.StringInput,
	provider *aws.Provider,
) (*s3.BucketVersioning, error) {
	versioning, err := s3.NewBucketVersioning(c, prefix+"/bucket-versioning", &s3.BucketVersioningArgs{
		Bucket: bucket.ID(),
		VersioningConfiguration: &s3.BucketVersioningVersioningConfigurationArgs{
			Status: pulumi.String("Enabled"),
		},
	}, pulumi.Provider(provider))
	if err != nil {
		return nil, fmt.Errorf("enable bucket versioning (%s): %w", prefix, err)
	}

	_, err = s3.NewBucketServerSideEncryptionConfigurationV2(
		c, prefix+"/bucket-encryption",
		&s3.BucketServerSideEncryptionConfigurationV2Args{
			Bucket: bucket.ID(),
			Rules: s3.BucketServerSideEncryptionConfigurationV2RuleArray{
				&s3.BucketServerSideEncryptionConfigurationV2RuleArgs{
					ApplyServerSideEncryptionByDefault: &s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs{
						SseAlgorithm:   pulumi.String("aws:kms"),
						KmsMasterKeyId: keyARN,
					},
					BucketKeyEnabled: pulumi.Bool(true),
				},
			},
		}, pulumi.Provider(provider))
	if err != nil {
		return nil, fmt.Errorf("configure bucket encryption (%s): %w", prefix, err)
	}

	_, err = s3.NewBucketPublicAccessBlock(c, prefix+"/bucket-pab", &s3.BucketPublicAccessBlockArgs{
		Bucket:                bucket.ID(),
		BlockPublicAcls:       pulumi.Bool(true),
		BlockPublicPolicy:     pulumi.Bool(true),
		IgnorePublicAcls:      pulumi.Bool(true),
		RestrictPublicBuckets: pulumi.Bool(true),
	}, pulumi.Provider(provider))
	if err != nil {
		return nil, fmt.Errorf("block public access (%s): %w", prefix, err)
	}

	// Enforce HTTPS-only access (deny non-TLS requests).
	_, err = s3.NewBucketPolicy(c, prefix+"/bucket-https-policy", &s3.BucketPolicyArgs{
		Bucket: bucket.ID(),
		Policy: pulumi.All(bucket.Arn).ApplyT(func(args []any) string {
			bucketARN := args[0].(string)
			return fmt.Sprintf(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyNonHTTPS",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [%q, "%s/*"],
      "Condition": {
        "Bool": {"aws:SecureTransport": "false"}
      }
    }
  ]
}`, bucketARN, bucketARN)
		}).(pulumi.StringOutput),
	}, pulumi.Provider(provider))
	if err != nil {
		return nil, fmt.Errorf("enforce HTTPS-only policy (%s): %w", prefix, err)
	}

	return versioning, nil
}

// applyBucketLifecycle expires noncurrent versions after noncurrentDays.
// Resource name: {prefix}/bucket-lifecycle.
func applyBucketLifecycle(c *pulumi.Context, prefix string, bucket *s3.Bucket, provider *aws.Provider) error {
	_, err := s3.NewBucketLifecycleConfigurationV2(
		c, prefix+"/bucket-lifecycle",
		&s3.BucketLifecycleConfigurationV2Args{
			Bucket: bucket.ID(),
			Rules: s3.BucketLifecycleConfigurationV2RuleArray{
				&s3.BucketLifecycleConfigurationV2RuleArgs{
					Id:     pulumi.String("cleanup-old-versions"),
					Status: pulumi.String("Enabled"),
					NoncurrentVersionExpiration: &s3.BucketLifecycleConfigurationV2RuleNoncurrentVersionExpirationArgs{
						NoncurrentDays: pulumi.Int(noncurrentDays),
					},
				},
			},
		}, pulumi.Provider(provider))
	if err != nil {
		return fmt.Errorf("configure bucket lifecycle (%s): %w", prefix, err)
	}

	return nil
}

// NewBucket creates the state bucket and its key in the account of provider,
// and exports "<account>-backend-url", "<account>-bucket-name" and
// "<account>-kms-key-arn".
func NewBucket(c *pulumi.Context, logger *slog.Logger, b Bucket, provider *aws.Provider) (*Result, error) {
	var (
		ctx    = c.Context()
		prefix = fmt.Sprintf("%s-%s", namePrefix, b.Account)
	)

	logger.InfoContext(ctx, "deploying scoped state bucket",
		slog.String("account", b.Account),
		slog.String("bucket", b.Name),
		slog.String("kms_alias", b.KMSAlias),
		slog.String("account_id", b.AccountID),
	)

	kmsKey, keyARN, err := newStateKey(c, prefix, b, provider)
	if err != nil {
		return nil, err
	}

	var name pulumi.StringInput = pulumi.String(b.Name)
	if b.DynamicName != nil {
		name = b.DynamicName
	}

	bucket, err := s3.NewBucket(c, prefix+"/bucket", &s3.BucketArgs{
		Bucket: name,
	}, pulumi.Provider(provider))
	if err != nil {
		return nil, fmt.Errorf("create S3 bucket (%s): %w", b.Account, err)
	}

	if _, err := applyBucketBaseline(c, prefix, bucket, keyARN, provider); err != nil {
		return nil, err
	}

	if err := applyBucketLifecycle(c, prefix, bucket, provider); err != nil {
		return nil, err
	}

	c.Export(fmt.Sprintf("%s-backend-url", b.Account),
		pulumi.Sprintf("s3://%s?awssdk=v2&region=%s", bucket.Bucket, b.Region))
	c.Export(fmt.Sprintf("%s-bucket-name", b.Account), bucket.Bucket)
	c.Export(fmt.Sprintf("%s-kms-key-arn", b.Account), keyARN)

	return &Result{Bucket: bucket, KMSKey: kmsKey, KMSKeyArn: keyARN}, nil
}

// Replication configures NewReplication.
type Replication struct {
	// Profile is the AWS profile of the replica provider (the same credentials
	// as the source, another region).
	Profile string
	// AssumeRoleARN is the role the replica provider assumes. Nil: none.
	AssumeRoleARN pulumi.StringInput
	// Partition is the ARN partition, for the permissions boundary ARN.
	// Required.
	Partition string
	// BoundaryName is the name of the permissions boundary policy set on the
	// replication role; it must exist in the account. Required.
	BoundaryName string
}

// NewReplication creates cross-region replication of the bucket: the replica
// provider, key and bucket, the replication role with its policy, and the
// replication configuration on the source.
func NewReplication(
	c *pulumi.Context,
	logger *slog.Logger,
	b Bucket,
	src *Result,
	provider *aws.Provider,
	r Replication,
) error {
	var (
		ctx    = c.Context()
		prefix = fmt.Sprintf("%s-%s-replica", namePrefix, b.Account)
	)

	if b.ReplicaRegion == "" {
		return fmt.Errorf("replica region not configured for %s", b.Account)
	}

	if b.ReplicaName == "" {
		return fmt.Errorf("replica bucket name not configured for %s", b.Account)
	}

	if r.Partition == "" || r.BoundaryName == "" {
		return fmt.Errorf("replication of %s needs a partition and a boundary name", b.Account)
	}

	logger.InfoContext(ctx, "deploying cross-region replication",
		slog.String("account", b.Account),
		slog.String("source_region", b.Region),
		slog.String("replica_region", b.ReplicaRegion),
	)

	replicaProvider, err := newReplicaProvider(c, prefix, b, r)
	if err != nil {
		return err
	}

	replica, err := newReplicaBucket(c, prefix, b, replicaProvider)
	if err != nil {
		return err
	}

	if err := newReplicationResources(c, prefix, b.Account, src, replica, provider, r); err != nil {
		return err
	}

	logger.InfoContext(ctx, "cross-region replication deployed",
		slog.String("account", b.Account),
		slog.String("source_bucket", b.Name),
		slog.String("replica_bucket", b.ReplicaName),
	)

	return nil
}

func newReplicaProvider(c *pulumi.Context, prefix string, b Bucket, r Replication) (*aws.Provider, error) {
	args := &aws.ProviderArgs{
		Region:  pulumi.String(b.ReplicaRegion),
		Profile: pulumi.String(r.Profile),
	}

	if r.AssumeRoleARN != nil {
		args.AssumeRoles = aws.ProviderAssumeRoleArray{
			&aws.ProviderAssumeRoleArgs{
				RoleArn: r.AssumeRoleARN,
			},
		}
	}

	provider, err := aws.NewProvider(c, prefix+"-provider", args)
	if err != nil {
		return nil, fmt.Errorf("create replica provider (%s): %w", b.Account, err)
	}

	return provider, nil
}

func newReplicaBucket(c *pulumi.Context, prefix string, b Bucket, replicaProvider *aws.Provider) (*replicaBucket, error) {
	key, err := newKMSKeyWithAlias(
		c, prefix,
		pulumi.Sprintf("KMS key for Pulumi state replica bucket (%s, %s)", b.Account, b.ReplicaRegion),
		b.KMSAlias,
		replicaProvider,
	)
	if err != nil {
		return nil, err
	}

	var tags pulumi.StringMap
	if len(b.ReplicaTags) > 0 {
		tags = make(pulumi.StringMap, len(b.ReplicaTags))
		for k, v := range b.ReplicaTags {
			tags[k] = pulumi.String(v)
		}
	}

	bucket, err := s3.NewBucket(c, prefix+"/bucket", &s3.BucketArgs{
		Bucket: pulumi.String(b.ReplicaName),
		Tags:   tags,
	}, pulumi.Provider(replicaProvider))
	if err != nil {
		return nil, fmt.Errorf("create replica bucket (%s): %w", b.Account, err)
	}

	versioning, err := applyBucketBaseline(c, prefix, bucket, key.Arn, replicaProvider)
	if err != nil {
		return nil, err
	}

	return &replicaBucket{bucket: bucket, kmsKey: key, versioning: versioning}, nil
}

func newReplicationResources(
	c *pulumi.Context,
	prefix, account string,
	src *Result,
	replica *replicaBucket,
	provider *aws.Provider,
	r Replication,
) error {
	const assumeRolePolicy = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Service": "s3.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }
  ]
}`

	callerIdentity, err := aws.GetCallerIdentity(c, nil, pulumi.Provider(provider))
	if err != nil {
		return fmt.Errorf("get caller identity (%s): %w", account, err)
	}

	boundaryARN := fmt.Sprintf("arn:%s:iam::%s:policy/%s", r.Partition, callerIdentity.AccountId, r.BoundaryName)

	role, err := iam.NewRole(c, prefix+"/replication-role", &iam.RoleArgs{
		Name:                pulumi.Sprintf("pulumi-state-replication-%s", account),
		AssumeRolePolicy:    pulumi.String(assumeRolePolicy),
		PermissionsBoundary: pulumi.StringPtr(boundaryARN),
	}, pulumi.Provider(provider))
	if err != nil {
		return fmt.Errorf("create replication role (%s): %w", account, err)
	}

	// Read the source and decrypt with its key; write the replica and encrypt
	// with its key.
	_, err = iam.NewRolePolicy(c, prefix+"/replication-policy", &iam.RolePolicyArgs{
		Name: pulumi.Sprintf("pulumi-state-replication-%s-policy", account),
		Role: role.Name,
		Policy: pulumi.All(src.Bucket.Arn, replica.bucket.Arn, src.KMSKeyArn, replica.kmsKey.Arn, srcOldKeyARN(src)).
			ApplyT(func(args []any) string {
				srcBucketARN := args[0].(string)
				dstBucketARN := args[1].(string)
				srcKMSARN := args[2].(string)
				dstKMSARN := args[3].(string)
				srcDecrypt := fmt.Sprintf("%q", srcKMSARN)

				// A retained old key: its objects may still be replicated or
				// retried, so the role may decrypt with it too.
				if old := args[4].(string); old != "" && old != srcKMSARN {
					srcDecrypt = fmt.Sprintf("[%q, %q]", srcKMSARN, old)
				}

				return fmt.Sprintf(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetReplicationConfiguration",
        "s3:ListBucket"
      ],
      "Resource": %q
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObjectVersionForReplication",
        "s3:GetObjectVersionAcl",
        "s3:GetObjectVersionTagging"
      ],
      "Resource": "%s/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:ReplicateObject",
        "s3:ReplicateDelete",
        "s3:ReplicateTags"
      ],
      "Resource": "%s/*"
    },
    {
      "Effect": "Allow",
      "Action": ["kms:Decrypt"],
      "Resource": %s
    },
    {
      "Effect": "Allow",
      "Action": ["kms:Encrypt"],
      "Resource": %q
    }
  ]
}`, srcBucketARN, srcBucketARN, dstBucketARN, srcDecrypt, dstKMSARN)
			}).(pulumi.StringOutput),
	}, pulumi.Provider(provider))
	if err != nil {
		return fmt.Errorf("create replication policy (%s): %w", account, err)
	}

	_, err = s3.NewBucketReplicationConfig(c, prefix+"/replication-config", &s3.BucketReplicationConfigArgs{
		Bucket: src.Bucket.ID(),
		Role:   role.Arn,
		Rules: s3.BucketReplicationConfigRuleArray{
			&s3.BucketReplicationConfigRuleArgs{
				Id:     pulumi.String("replicate-all"),
				Status: pulumi.String("Enabled"),
				Destination: &s3.BucketReplicationConfigRuleDestinationArgs{
					Bucket: replica.bucket.Arn,
					EncryptionConfiguration: &s3.BucketReplicationConfigRuleDestinationEncryptionConfigurationArgs{
						ReplicaKmsKeyId: replica.kmsKey.Arn,
					},
					StorageClass: pulumi.String("STANDARD"),
				},
				SourceSelectionCriteria: &s3.BucketReplicationConfigRuleSourceSelectionCriteriaArgs{
					SseKmsEncryptedObjects: &s3.BucketReplicationConfigRuleSourceSelectionCriteriaSseKmsEncryptedObjectsArgs{
						Status: pulumi.String("Enabled"),
					},
				},
			},
		},
	}, pulumi.Provider(provider), pulumi.DependsOn([]pulumi.Resource{replica.versioning}))
	if err != nil {
		return fmt.Errorf("create replication config (%s): %w", account, err)
	}

	return nil
}

// srcOldKeyARN is the ARN of the key the source bucket had besides the one it
// encrypts with, or "".
func srcOldKeyARN(src *Result) pulumi.StringInput {
	if src.KMSKey == nil {
		return pulumi.String("")
	}

	return src.KMSKey.Arn
}
