# Reference

`pkg/registry`. Every key below is strict: an unknown key anywhere is an
error. Types are in `pkg/registry/types.go`; refusals in
`pkg/registry/validate.go`.

## Loading

- `registry.Parse(data []byte) (*Registry, error)` — parse and validate.
- `registry.Load(fsys fs.FS, name string) (*Registry, error)` — read a file
  (typically from an `embed.FS`), then `Parse`.
- `(*Registry).Validate() error` — every problem, joined.

## The file

| Key | Meaning |
| --- | --- |
| `organization` | `id` (`o-...`), `root_id` (`r-...`), `management_account` (an account name). `manage: true` is refused in v1 |
| `ous[]` | `name`, `parent` (empty is the root), `id` (adopted OU), `scps[]`, `reason` (required) |
| `accounts[]` | `name`, `id` (12 digits, once it exists), `email`, `ou` (required), `scps[]`, `tags`, `baseline_exempt` (a reason) |
| `scp_enforcement` | `dormant` (default); `enforced` is refused in v1 |
| `scps[]` | `name`, `description`, `document` (JSON, at most 5120 bytes) |
| `identity_center` | `instance_arn`, `identity_store_id`, `groups[]`, `permission_sets[]`, `assignments[]` |
| `identity_center.groups[]` | `name`, `source` (`manual` default, or `sync` for an externally filled group) |
| `identity_center.permission_sets[]` | `name`, `description`, `session_duration` (`PT8H`), `managed_policies[]`, `inline_policy` (JSON, at most 10240 bytes), `includes[]` (no cycles) |
| `identity_center.assignments[]` | `principal`, `principal_type` (`group` default, or `user`), `permission_set`, `accounts[]` and/or `ous[]` (at least one) |
| `baseline` | `password_policy`, `ebs_default_encryption` (needs `regions`), `regions[]`, `access_analyzer`, `auditor_role` (`name`, `trusted_account`), `boundaries[]` (`name`, `document`) |

See [safety.md](safety.md) for what each refusal protects against.

## `pkg/engine/baseline`

`truvity:aws-structure:AccountBaseline` deploys the baseline controls of one
account from a `registry.Baseline`. One component per account.

```go
b, err := baseline.New(ctx, "baseline-"+account, &baseline.Args{
	Account:         account,
	Baseline:        registry.Baseline{EBSDefaultEncryption: true, Regions: []string{"region-a"}, AccessAnalyzer: true},
	AnalyzerRegions: []string{"region-a", "region-b"}, // empty: Baseline.Regions
	Providers:       providersByRegion,                // this account's provider per region
	Names:           func(c baseline.Child) string { /* the names your stack already uses */ },
	LegacyTopLevel:  true,                             // adopting resources created without a parent
})
```

Children (all registered under the component, each with the provider of its
region, none protected):

| Child | Type | Default name | Created when |
| --- | --- | --- | --- |
| EBS default encryption | `aws:ebs/encryptionByDefault:EncryptionByDefault` | `<c>-ebs-<region>` | `Baseline.EBSDefaultEncryption`, one per `Baseline.Regions` |
| Access Analyzer | `aws:accessanalyzer/analyzer:Analyzer` | `<c>-analyzer-<region>` | `Baseline.AccessAnalyzer`, one per `AnalyzerRegions` (or `Baseline.Regions`); analyzer name `account-analyzer`, type `ACCOUNT` |

`Names` receives a `Child{Component, Kind, Account, Region}`; the names it
returns are part of the URNs and must be unique. With `LegacyTopLevel` every
child carries one alias with `noParent`, the same type and the name `Names`
gives it, so adopting existing resources is not a replace.

Refused before anything is registered, all reported at once: no `Account`; no
provider for a region the component needs; an empty or repeated region; EBS
encryption without regions; a naming hook returning an empty or repeated name;
and `Baseline.PasswordPolicy`, `AuditorRole` or `Boundaries`, which this
component does not implement (refused by name rather than ignored): they belong
to `pkg/engine/iam`.

## `pkg/engine/iam`

`truvity:aws-structure:AccountIAM` deploys the IAM controls of one account:
the password policy, boundary policies and an auditor role. One component per
account. It is separate from `AccountBaseline` because IAM is global to the
account (one provider, no regions) while the baseline is per region, and
because an estate may deploy the two from different stacks, where one
component cannot span both.

```go
c, err := iam.New(ctx, "iam-"+account, &iam.Args{
	Account:        account,
	PasswordPolicy: &registry.PasswordPolicy{MinimumLength: 14, MaxAgeDays: 90, ReusePrevention: 24 /* ... */},
	Boundaries:     []registry.Boundary{{Name: "boundary-a", Document: docA}},
	AuditorRole: &iam.AuditorRole{
		Name:                "auditor",
		TrustedPrincipal:    principalARN, // who may assume it
		ExternalID:          externalID,   // optional
		ManagedPolicies:     []string{managedARN},
		Policy:              &iam.Policy{Name: "AuditorExtra", Document: doc}, // optional
		PermissionsBoundary: boundaryARN,
	},
	Provider:         provider,         // this account's provider
	BoundaryProvider: boundaryProvider, // optional: nil means Provider
	Names:            func(c iam.Child) string { /* the names your stack already uses */ },
	LegacyTopLevel:   true,             // adopting resources created without a parent
})
```

The component carries no policy document, ARN or account id of its own: every
one is a caller input. Each of `PasswordPolicy`, `Boundaries` and
`AuditorRole` is optional.

Children (all registered under the component, none protected):

| Child | Type | Default name | Created when |
| --- | --- | --- | --- |
| Password policy | `aws:iam/accountPasswordPolicy:AccountPasswordPolicy` | `<c>-password-policy` | `PasswordPolicy` set; users may change their own password |
| Boundary | `aws:iam/policy:Policy` | `<c>-boundary-<name>` | one per `Boundaries` entry, created with `BoundaryProvider` |
| Auditor policy | `aws:iam/policy:Policy` | `<c>-auditor-policy` | `AuditorRole.Policy` set |
| Auditor role | `aws:iam/role:Role` | `<c>-auditor-role` | `AuditorRole` set; trust policy names `TrustedPrincipal` and, when set, `sts:ExternalId` |
| Managed attachment | `aws:iam/rolePolicyAttachment:RolePolicyAttachment` | `<c>-auditor-managed-<last element of the ARN>` | one per `AuditorRole.ManagedPolicies` |
| Policy attachment | `aws:iam/rolePolicyAttachment:RolePolicyAttachment` | `<c>-auditor-policy-attachment` | `AuditorRole.Policy` set |

`Names` receives a `Child{Component, Kind, Account, Name}`; `Name` is the
boundary name, the policy name, the role name or the managed-policy ARN,
depending on `Kind`. The names it returns are part of the URNs and must be
unique. With `LegacyTopLevel` every child carries one alias with `noParent`, the
same type and the name `Names` gives it, so adopting existing resources is not
a replace.

`AuditorRole` is not `registry.AuditorRole`: that one names an account of the
organization, while the principal of an auditor is often an outside party and
needs an ARN, an external id and policies the registry cannot carry.

Refused before anything is registered, all reported at once: no `Account` or
`Provider`; a password policy outside minimum length 8..128, age 0..1095 days
or reuse 0..24; a boundary without a name, with a repeated name or with a
document that is not JSON; an auditor role without a name, trusted principal or
permissions boundary, with an empty or repeated managed policy, or with a
policy lacking a name or a JSON document; and a naming hook returning an empty
or repeated name.

## `pkg/engine/trail`

`truvity:aws-structure:AccountTrail` deploys the audit trail of one account:
a KMS key, the trail bucket with its access-log and cross-region replica
buckets, the replication role and a multi-region trail that logs the account
itself. One component per account. It is a per-account trail, not an
organization trail: `IsOrganizationTrail` is false.

```go
c, err := trail.New(ctx, "trail-"+account, &trail.Args{
	Account: account,
	Buckets: trail.Buckets{Trail: trailBucket, AccessLog: logBucket, Replica: replicaBucket},
	KeyAlias:          "alias/trail",
	KeyAdministrator:  rootARN,     // may manage the key (kms:*)
	TrailARN:          trailARNs,   // trails that may use the key; wildcards allowed
	DataEventResource: s3ARN,       // S3 data events the trail logs
	ReplicationRole: trail.ReplicationRole{
		Name:                "replication",
		PermissionsBoundary: boundaryARN,
	},
	Provider:        provider,        // the account, in the trail's region
	ReplicaProvider: replicaProvider, // the account, in the replica's region
	Names:           func(c trail.Child) string { /* the names your stack already uses */ },
	LegacyTopLevel:  true,            // adopting resources created without a parent
})
```

The component carries no ARN, bucket name or account id of its own: every one
is a caller input. The retention periods are fixed (see the table).

Children (all registered under the component, none protected or retained):

| Child | Type | Default name | Provider |
| --- | --- | --- | --- |
| Key | `aws:kms/key:Key` | `<c>-kms-key` | Provider; rotation on |
| Key alias | `aws:kms/alias:Alias` | `<c>-kms-alias` | Provider |
| Trail bucket | `aws:s3/bucket:Bucket` | `<c>-bucket` | Provider |
| Trail bucket policy | `aws:s3/bucketPolicy:BucketPolicy` | `<c>-bucket-policy` | Provider; CloudTrail may read the ACL and put objects, HTTPS only |
| Trail bucket public access block | `aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock` | `<c>-public-access-block` | Provider |
| Trail bucket encryption | `aws:s3/bucketServerSideEncryptionConfigurationV2:BucketServerSideEncryptionConfigurationV2` | `<c>-sse` | Provider; KMS with the key |
| Trail bucket lifecycle | `aws:s3/bucketLifecycleConfigurationV2:BucketLifecycleConfigurationV2` | `<c>-lifecycle` | Provider; Glacier after 90 days, expire after 365 |
| Access-log bucket | `aws:s3/bucket:Bucket` | `<c>-access-log-bucket` | Provider |
| Access-log ownership | `aws:s3/bucketOwnershipControls:BucketOwnershipControls` | `<c>-access-log-ownership` | Provider; `BucketOwnerEnforced` |
| Access-log public access block | `aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock` | `<c>-access-log-public-access-block` | Provider |
| Access-log encryption | `aws:s3/bucketServerSideEncryptionConfigurationV2:BucketServerSideEncryptionConfigurationV2` | `<c>-access-log-sse` | Provider; AES256 |
| Access-log bucket policy | `aws:s3/bucketPolicy:BucketPolicy` | `<c>-access-log-bucket-policy` | Provider; HTTPS only |
| Access-log lifecycle | `aws:s3/bucketLifecycleConfigurationV2:BucketLifecycleConfigurationV2` | `<c>-access-log-lifecycle` | Provider; expire after 365 days |
| Trail bucket logging | `aws:s3/bucketLoggingV2:BucketLoggingV2` | `<c>-logging` | Provider; prefix `cloudtrail/` |
| Trail bucket versioning | `aws:s3/bucketVersioningV2:BucketVersioningV2` | `<c>-versioning` | Provider |
| Replica bucket | `aws:s3/bucket:Bucket` | `<c>-replica-bucket` | ReplicaProvider |
| Replica versioning | `aws:s3/bucketVersioningV2:BucketVersioningV2` | `<c>-replica-versioning` | ReplicaProvider |
| Replica encryption | `aws:s3/bucketServerSideEncryptionConfigurationV2:BucketServerSideEncryptionConfigurationV2` | `<c>-replica-sse` | ReplicaProvider; AES256 |
| Replica public access block | `aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock` | `<c>-replica-public-access-block` | ReplicaProvider |
| Replica bucket policy | `aws:s3/bucketPolicy:BucketPolicy` | `<c>-replica-bucket-policy` | ReplicaProvider; HTTPS only |
| Replica lifecycle | `aws:s3/bucketLifecycleConfigurationV2:BucketLifecycleConfigurationV2` | `<c>-replica-lifecycle` | ReplicaProvider; Glacier Instant Retrieval at once, expire after 365 days |
| Replication role | `aws:iam/role:Role` | `<c>-replication-role` | Provider; `ReplicationRole.PermissionsBoundary` |
| Replication role policy | `aws:iam/rolePolicy:RolePolicy` | `<c>-replication-policy` | Provider |
| Replication configuration | `aws:s3/bucketReplicationConfig:BucketReplicationConfig` | `<c>-replication` | Provider; depends on both versionings |
| Trail | `aws:cloudtrail/trail:Trail` | `<c>-trail` | Provider; multi-region, log file validation, global service events, management events and `DataEventResource` data events; depends on the trail bucket and its policy |

`Names` receives a `Child{Component, Kind, Account}`. The names it returns are
part of the URNs and must be unique. With `LegacyTopLevel` every child carries
one alias with `noParent`, the same type and the name `Names` gives it, so
adopting existing resources is not a replace.

Refused before anything is registered, all reported at once: no `Account`,
`Provider` or `ReplicaProvider`; a missing bucket name, key administrator,
trail ARN, data-event resource, replication role name or permissions boundary;
a key alias that is empty or lacks the `alias/` prefix; and a naming hook
returning an empty or repeated name.
