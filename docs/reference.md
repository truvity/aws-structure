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
| `accounts[]` | `name`, `id` (12 digits, once it exists), `email`, `ou` (required; `root` for an account directly under the organization root), `scps[]`, `tags`, `baseline_exempt` (a reason), `closed` (true: the account was closed and AWS keeps it SUSPENDED until it is purged) |
| `scp_enforcement` | `dormant` (default); `enforced` is refused in v1 |
| `scps[]` | `name`, `description`, `document` (JSON, at most 5120 bytes) |
| `identity_center` | `instance_arn`, `identity_store_id`, `groups[]`, `permission_sets[]`, `assignments[]`, `break_glass` |
| `identity_center.groups[]` | `name`, `source` (`manual` default, or `sync` for an externally filled group) |
| `identity_center.permission_sets[]` | `name`, `description`, `session_duration` (`PT8H`), `managed_policies[]`, `inline_policy` (JSON, at most 10240 bytes), `includes[]` (no cycles) |
| `identity_center.assignments[]` | `principal`, `principal_type` (`group` default, or `user`), `permission_set`, `accounts[]` and/or `ous[]` (at least one) |
| `identity_center.break_glass` | `principal`, `principal_type` (`group` default, or `user`), `permission_set`: the way back into every account. Both must be declared. The preflight refuses a registry without it, or with an account no assignment of it reaches |
| `waivers[]` | `guard` (`scp-on-management`), `target` (an OU or account name, or `root`), `reason` and `exit_condition` (both required), `expires` (`YYYY-MM-DD`, optional; the last day it counts). One waiver per guard and target |
| `baseline` | `password_policy`, `ebs_default_encryption` (needs `regions`), `regions[]`, `access_analyzer`, `auditor_role` (`name`, `trusted_account`), `boundaries[]` (`name`, `document`) |

See [safety.md](safety.md) for what each refusal protects against.

## `pkg/preflight`

The guard to run before an apply. Pure functions over the registry and the
steps of a `pulumi preview`; `Run` wires them to an automation-API stack.

```go
findings, err := preflight.Run(ctx, stack, preflight.Opts{
	Registry:   reg,                                   // loaded, validated
	BreakGlass: &preflight.BreakGlassAssignment{       // optional: the plan half of the guard
		PermissionSetARN: bgSetARN, PrincipalID: bgGroupID,
	},
})
if err != nil {
	return err // the preview failed
}
if err := preflight.Err(findings); err != nil {
	return err // refuse the apply
}
```

Without the automation API, write the events with
`pulumi preview --event-log events.jsonl` and judge them with
`preflight.Check(preflight.StepsFromEvents(preflight.ReadEventLog(f)), opts)`.

| Guard | Refuses |
| --- | --- |
| `irreplaceable` | a replace (`replace`, `create-replacement`, `delete-replaced`, ...) or a delete of an `Account`, `OrganizationalUnit`, `PermissionSet` or `Organization` |
| `break-glass` (plan) | a delete or replace of an `AccountAssignment` whose `permissionSetArn` and `principalId` are the break-glass ones |
| `break-glass` (registry) | no `identity_center.break_glass`, or an account that no assignment of it reaches, directly or through an OU at any depth |
| `scp-on-management` (plan) | a `PolicyAttachment` created, updated or replaced onto the root, the management account or an OU above it (`ProtectedTargets`: those with an id in the registry) without a waiver for that target |
| `scp-on-management` (registry) | `scps` on the management account or an OU above it without a waiver |
| `waiver-expired` | a waiver past its `expires` day, or one for a target that carries no policy or is not above the management account (a `root` waiver only applies to plans) |

`Lockout(reg, now)`, `Plan(steps, PlanOpts)`, `ProtectedTargets(reg)` and
`Waived(reg, now)` are the parts; `Check` runs both halves. When the
break-glass assignment is declared by `sso.DeployBreakGlass`, use
`LockoutWith(reg, now, &BreakGlassBuilder{Skip: skip})` or
`Opts.BreakGlassBuilder`.
## `pkg/drift`

A read-only read of the organization and Identity Center, compared with the
registry, and the access-roles map. Every AWS call is a List or Describe.

```go
live, err := drift.Read(ctx, drift.Clients{
	Organizations: organizations.NewFromConfig(mgmtCfg),
	SSOAdmin:      ssoadmin.NewFromConfig(idcCfg), // the instance's region
	IdentityStore: identitystore.NewFromConfig(idcCfg),
	InstanceARN:   reg.IdentityCenter.InstanceARN,
	IdentityStoreID: reg.IdentityCenter.IdentityStoreID,
})
for _, f := range drift.Compare(reg, live) {
	fmt.Println(f) // "<kind> <what> <subject>: <detail>"
}
```

| Kind | Meaning |
| --- | --- |
| `unmanaged` | in AWS, not in the registry: an account, OU, permission set or assignment made by hand, or a service control policy attached while the registry is dormant (AWS's own `FullAWSAccess` excepted) |
| `missing` | in the registry, not in AWS: an id that is gone, a permission set or assignment not there, or an account or OU without an id not yet created |
| `moved` | an account or OU under a different parent than declared |
| `edited` | an OU's name or an account's email differs, or an account declared `closed` is active again |
| `unrecorded-id` | it exists (an OU by name and parent, an account by email), but the registry has no id for it yet |
| `not-active` | a declared account that is suspended or closed and not declared `closed` |

Accounts are matched by id, or by email when the registry has none. OUs by id,
or by name under their parent. Assignments are compared by account, permission
set, principal type and principal name, and only in managed accounts.

`drift.AccessRoles(ctx, accounts, clientFor)` lists, per account (name to id),
the roles Identity Center provisioned (`/aws-reserved/sso.amazonaws.com/`,
`AWSReservedSSO_<set>_<suffix>`) through the IAM client `clientFor` returns for
that account. `drift.RenderAccessRoles(set, header)` writes them as YAML:

```yaml
accounts:
  <account>:
    account_id: "<id>"
    roles:
      <permission set>:
        permission_set: <permission set>
        role_name: AWSReservedSSO_<set>_<suffix>
        role_arn: <the ARN, with its path>
        role_arn_pathless: <the ARN without the path>
```

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
policy := registry.ISO27001PasswordPolicy() // or your own registry.PasswordPolicy

c, err := iam.New(ctx, "iam-"+account, &iam.Args{
	Account:        account,
	PasswordPolicy: &policy,
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
one is a caller input. `registry.ISO27001PasswordPolicy()` is a preset of the
policy an ISO 27001 audit expects (length 14, 90 days, 24 remembered, every
character class). Each of `PasswordPolicy`, `Boundaries` and
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
	// DataEventExclusions: []string{bucketARN + "/"}, // optional, see below
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

`DataEventExclusions` (optional) lists S3 object ARN prefixes (`<bucket ARN>/`
plus an optional key prefix) whose object events the trail does not log, for a
bucket that is read at a volume that makes the events cost more than they are
worth. Empty, the trail keeps its classic event selector. Set, the trail uses
advanced event selectors: management events (all) and S3 object events with
`resources.ARN` NotStartsWith the exclusions. `fleet.TrailArgs` takes the same
as a map from account name to prefixes. The trail is updated in place.

Refused before anything is registered, all reported at once: no `Account`,
`Provider` or `ReplicaProvider`; a missing bucket name, key administrator,
trail ARN, data-event resource, replication role name or permissions boundary;
a `DataEventExclusions` entry that is not an S3 object ARN prefix; a key alias that is empty or lacks the `alias/` prefix; and a naming hook
returning an empty or repeated name.

## `pkg/engine/guardduty`

`truvity:aws-structure:AccountRegionGuardDuty` deploys the alerting for
GuardDuty findings of one account in one region: an enabled detector and an
EventBridge rule that publishes every finding to an SNS topic through a role.
One component per account per region, because the detector, the rule and the
role's policy are regional and the topic is a per-region input. It creates
nothing at the organization level (no delegated administrator, organization
configuration, member accounts, protection plans or publishing destinations).

```go
c, err := guardduty.New(ctx, "guardduty-"+account+"-"+region, &guardduty.Args{
	Account:             account,
	Region:              region,        // feeds the role and rule names
	SNSTopicARN:         topicARN,      // may be in another account
	PermissionsBoundary: boundaryARN,   // set on the EventBridge role
	Provider:            provider,      // the account, in Region
	FindingPublishingFrequency: "FIFTEEN_MINUTES", // optional; empty = provider default
	Names:               func(c guardduty.Child) string { /* the names your stack already uses */ },
	LegacyTopLevel:      true,          // adopting resources created without a parent
})
```

The component carries no ARN or account id of its own: the topic and the
boundary are caller inputs. The topic's policy, which must let the account
publish, is the caller's.

Children (all registered under the component, none protected or retained, all
created with Provider):

| Child | Type | Default name | Notes |
| --- | --- | --- | --- |
| Detector | `aws:guardduty/detector:Detector` | `<c>-detector` | enabled; `FindingPublishingFrequency` (`FIFTEEN_MINUTES`, `ONE_HOUR` or `SIX_HOURS`) when set, else the provider default (AWS: `SIX_HOURS`) |
| EventBridge role | `aws:iam/role:Role` | `<c>-eventbridge-role` | named `eventbridge-sns-<region>`; trusts `events.amazonaws.com`; `PermissionsBoundary` |
| Role policy | `aws:iam/rolePolicy:RolePolicy` | `<c>-eventbridge-policy` | `sns-publish`: `sns:Publish` on `SNSTopicARN` |
| Rule | `aws:cloudwatch/eventRule:EventRule` | `<c>-rule` | named `guardduty-findings-<region>`; matches `aws.guardduty` / `GuardDuty Finding` |
| Target | `aws:cloudwatch/eventTarget:EventTarget` | `<c>-target` | target id `security-alerts-sns`; `SNSTopicARN` with the role |
| Detector features | `aws:guardduty/detectorFeature:DetectorFeature` | `<c>-feature-<name>` (lower case, `_` as `-`; not run through `Names`) | only for each entry of `DisabledFeatures` (such as `S3_DATA_EVENTS`): status `DISABLED`; none are created when it is empty; `New` only, not `NewImported` |

`Names` receives a `Child{Component, Kind, Account, Region}`. The names it
returns are part of the URNs and must be unique. With `LegacyTopLevel` every
child carries one alias with `noParent`, the same type and the name `Names`
gives it, so adopting existing resources is not a replace.

Refused before anything is registered, all reported at once: no `Account`,
`Region` or `Provider`; no `SNSTopicARN` or `PermissionsBoundary`; a
`FindingPublishingFrequency` that is none of the three values; and a naming
hook returning an empty or repeated name.

## `pkg/engine/sso`

IAM Identity Center access, as two components and two lookups. The boundary is
the unit that is created, kept and reviewed together: a permission set with its
policies is one component (`PermissionSet`), and the assignments on one target
account are one component (`AccountAssignments`). Neither spans the instance, so
a stack may manage some sets or some accounts only. Groups a directory sync
fills are looked up, never created; there is no group component.

The instance ARN, every principal id, every account id, every permission set
ARN and every AWS-managed policy ARN are caller inputs: the package carries
none. The provider is the caller's too (the region the instance lives in); it
is never defaulted.

### `truvity:aws-structure:PermissionSet`

```go
ps, err := sso.NewPermissionSet(ctx, "ps-"+key, &sso.PermissionSetArgs{
	InstanceARN:        instanceARN,           // the Identity Center instance
	Set:                registry.PermissionSet{Name: "set-a", SessionDuration: "PT8H", ManagedPolicies: managedARNs},
	BoundaryPolicyName: "boundary-a",          // optional: a customer managed policy, by name
	Provider:           provider,
	Names:              func(c sso.SetChild) string { /* the names your stack already uses */ },
	LegacyTopLevel:     true,                  // adopting resources created without a parent
})
// ps.Arn and ps.Set are what AccountAssignments takes.
```

Children (all registered under the component with Provider):

| Child | Type | Default name | Notes |
| --- | --- | --- | --- |
| Permission set | `aws:ssoadmin/permissionSet:PermissionSet` | `<c>-set` | `Set.Name`; `Set.SessionDuration` and `Set.Description` only when non-empty. **Protected and retained on delete** |
| Managed policy | `aws:ssoadmin/managedPolicyAttachment:ManagedPolicyAttachment` | `<c>-managed-policy-<i>` | one per `Set.ManagedPolicies`, in order; depends on the set |
| Inline policy | `aws:ssoadmin/permissionSetInlinePolicy:PermissionSetInlinePolicy` | `<c>-inline-policy` | when `Set.InlinePolicy` is non-empty; depends on the set |
| Boundary | `aws:ssoadmin/permissionsBoundaryAttachment:PermissionsBoundaryAttachment` | `<c>-boundary` | when `BoundaryPolicyName` is non-empty: a customer managed policy reference by name; depends on the set |

`Set.Includes` is not read: whoever builds the assignments expands it. Only the
permission set is protected and retained; deleting one revokes everyone's
access, and the attachments are recreated from it.

`Names` receives a `SetChild{Component, Kind, Name, Index}` (`Index` is the
policy's position for `SetKindManagedPolicy`). The names it returns are part of
the URNs and must be unique. With `LegacyTopLevel` every child carries one alias
with `noParent`, the same type and the name `Names` gives it.

Refused before anything is registered, all reported at once: no `InstanceARN`
or `Provider`; no `Set.Name`; a `Set.SessionDuration` that is not `PT..H..M`; an
empty or repeated managed policy; an inline policy that is not JSON or is over
10240 bytes; and a naming hook returning an empty or repeated name.

### `truvity:aws-structure:AccountAssignments`

```go
a, err := sso.NewAccountAssignments(ctx, "assignments-"+account, &sso.AccountAssignmentsArgs{
	Account:     account,                      // feeds names only
	InstanceARN: instanceARN,
	TargetID:    accountID,                    // the target account's id
	Assignments: []sso.Assignment{{
		Principal:        "group-a",            // feeds names only
		PrincipalType:    "group",              // or "user"; empty is group
		PrincipalID:      groupIDs["group-a"],  // from sso.LookupGroupIDs
		PermissionSet:    "set-a",              // feeds names only
		PermissionSetARN: ps.Arn,               // or sso.LookupPermissionSetARN for a hand-made set
		LegacyNames:      []string{"older-name"},
	}},
	Provider:       provider,
	Names:          func(c sso.AssignmentChild) string { /* the names your stack already uses */ },
	LegacyTopLevel: true,
})
```

An `Assignment` is a resolved `registry.Assignment`: the registry names accounts
and OUs, and the caller resolves each to one target and every reference to an id
or ARN. One `ssoadmin.AccountAssignment` per assignment, named
`<c>-<permission set>-<principal>` (with `-user` for a user) by default, with
`PrincipalType` `GROUP` or `USER`, `TargetType` `AWS_ACCOUNT`. Nothing is
protected or retained.

Each `LegacyNames` entry becomes an alias with that name, so a renamed
assignment is a rename in state and not a replace; with `LegacyTopLevel` it is
the name under the stack (`noParent`), exactly as the plain `noParent` alias
that `LegacyTopLevel` adds to every assignment.

Refused before anything is registered, all reported at once: no `Account`,
`InstanceARN`, `TargetID` or `Provider`; an assignment without `Principal`,
`PrincipalID`, `PermissionSet` or `PermissionSetARN`; a `PrincipalType` that is
neither `group` nor `user`; a repeated (permission set, principal, type); an
empty `LegacyNames` entry; and a naming hook returning an empty or repeated
name.

### Break-glass: `sso.DeployBreakGlass`

```go
deployed, err := sso.DeployBreakGlass(ctx, logger, sso.BreakGlassArgs{
	Registry:         reg,                  // identity_center.break_glass and the accounts
	InstanceARN:      instanceARN,
	PrincipalID:      groupIDs["admins"],   // the break-glass principal's id
	PermissionSetARN: adminSet.Arn,         // the break-glass permission set's ARN
	Provider:         provider,
	Skip:             func(account string) bool { return inMyMatrix(account) },
})
```

Declares one `AccountAssignment` of the break-glass principal and permission
set on every account that is not `closed` and has an id (`Registry.BreakGlassTargets`),
wherever it sits, `ou: root` included. Each account is one `AccountAssignments`
component named `sso-break-glass-<account>` with one child named
`break-glass-<account>-<permission set>-<principal>` (`-user` for a user), or
by `Names`; `LegacyTopLevel` and `LegacyNames[account]` add aliases as for any
assignment. It returns the accounts it declared.

It adds break-glass beside the caller's other assignments. AWS holds a
(principal, permission set, account) once, so **`Skip(account)` must return true
for every account on which the caller's own assignments already grant the same
principal and set**; those accounts get nothing here. Names are checked before
anything is registered; a missing break-glass, instance, principal id,
permission set ARN or provider, or an empty or repeated name, is refused.

For the registry guard (`break-glass` below), pass
`preflight.Opts{BreakGlassBuilder: &preflight.BreakGlassBuilder{Skip: skip}}`
(or `preflight.LockoutWith`) with the same `skip`: the accounts the builder
reaches then count as reached, and the skipped ones must still be reached by the
registry's own assignments.

### Lookups

- `sso.LookupGroupIDs(ctx, identityStoreID, displayNames, provider)` reads each
  group's Identity Store id by display name (repeated names once) and returns a
  map from display name to id. Every group that cannot be read is reported
  together.
- `sso.LookupPermissionSetARN(ctx, instanceARN, name, provider)` reads the ARN
  of an existing permission set by name: for a set made by hand that this
  package does not manage.

## `pkg/engine/org`

The organizational structure, as one component per organizational unit, plus the
service control policy documents, which are rendered and never attached. The
boundary is the OU: an account is created inside exactly one OU and takes its id
as its parent, so the unit and its member accounts are created, protected and
reviewed together. An account is not its own component, and nothing spans the
organization, so a stack may manage some units only.

The organization is never managed. `org.LookupRootID(ctx, provider)` reads it
and returns the id of its root, the parent of a top-level unit; the package has
no resource for the organization and none is planned until the legacy owner of
it is decommissioned. The parent id, every unit and account name, every email,
the partition, the management account id, the regions and the bucket patterns
are caller inputs: the package carries none. The provider is the
management account's and is never defaulted.

### `truvity:aws-structure:OrganizationalUnit`

```go
rootID, err := org.LookupRootID(ctx, provider)
u, err := org.New(ctx, "unit-"+name, &org.Args{
	Unit:     registry.OU{Name: "unit-a"},
	ParentID: pulumi.String(rootID),               // the root's id, or another unit's id
	Accounts: []registry.Account{{Name: "acct-a", Email: "a@example.test"}},
	Provider: provider,
	Names:    func(c org.Child) string { /* the names your stack already uses */ },
	LegacyTopLevel: true,                           // adopting resources created without a parent
})
// u.Unit is the OU resource (its ID is a nested unit's ParentID); u.Accounts is by name.
```

Children (all registered under the component with Provider):

| Child | Type | Default name | Notes |
| --- | --- | --- | --- |
| Unit | `aws:organizations/organizationalUnit:OrganizationalUnit` | `<c>-ou` | `Unit.Name` under `ParentID`. **Protected and retained on delete** |
| Account | `aws:organizations/account:Account` | `<c>-account-<name>` | one per `Accounts`, in order; `Name`, `Email`, parent is the unit, `Tags` only when non-empty; depends on the unit. **Protected and retained on delete** |

`Names` receives a `Child{Component, Kind, Unit, Account}` (`Account` is empty
for the unit). The names it returns are part of the URNs and must be unique.
With `LegacyTopLevel` every child carries one alias with `noParent`, the same
type and the name `Names` gives it.

Unit and accounts are protected and retained on delete, as before the
extraction; nothing else is. `Unit.Parent`, `Unit.Reason` and
`Account.BaselineExempt` are not read.

Refused before anything is registered, all reported at once: no `Unit.Name`,
`ParentID` or `Provider`; an account without `Name` or `Email`; a repeated
account name; an account whose `OU` is another unit; a unit or account with an
`ID` (adoption by import is not built) or with `SCPs` (they are dormant); and a
naming hook returning an empty or repeated name.

### Service control policies (dormant)

`org.SCPs(org.SCPParams{...})` returns eight `registry.SCP`, in a fixed order:
`deny-leave-org`, `protect-cloudtrail`, `protect-audit-logs`, `deny-root-user`,
`restrict-regions`, `deny-data-export`, `require-encryption` and
`deny-public-access`. Each document is built from typed values and rendered as
indented JSON, then checked to be valid JSON of at most 5120 bytes
(`registry.MaxSCPBytes`).

`SCPParams` is all caller input and all required: `Partition` (the word after
`arn:`), `ManagementAccountID` (the one account allowed to change CloudTrail),
`AllowedRegions` (written in the order given), `ReplicationExemptBuckets` and
`PublicAccessBlockExemptBuckets` (S3 bucket name patterns). Every problem is
reported at once.

Nothing here creates a policy or an attachment: no component takes SCPs, and an
OU or account that lists some is refused. The scope the policies had in the
estate they were extracted from, for whoever activates them (behind the lockout
check of docs/decisions/0002-safety.md, on a test OU first): the organization
root for `deny-leave-org`, `protect-cloudtrail`, `protect-audit-logs` and
`restrict-regions`; every unit but the management one for `deny-root-user`; the
customer unit alone for `deny-data-export`, `require-encryption` and
`deny-public-access`.

## `pkg/backend`

The storage a Pulumi state backend lives in, per account. Plain resources, no
component: the logical names are the API.

```go
b := backend.Bucket{
	Account: "acct", AccountID: id, Name: backend.BucketName(id, "region-a"),
	KMSAlias: backend.KMSAlias(), Region: "region-a",
	ReplicaRegion: "region-b", ReplicaName: backend.BucketName(id, "region-b"),
}
res, err := backend.NewBucket(ctx, logger, b, provider)
err = backend.NewReplication(ctx, logger, b, res, provider, backend.Replication{
	Profile: profile, AssumeRoleARN: roleOrNil, Partition: "aws", BoundaryName: "boundary",
})
```

| Logical name | Type |
| --- | --- |
| `pulumi-state-<account>/kms-key`, `/kms-alias` | KMS key (rotation on), alias |
| `pulumi-state-<account>/bucket` | S3 bucket |
| `.../bucket-versioning`, `/bucket-encryption`, `/bucket-pab`, `/bucket-https-policy` | versioning, SSE-KMS with bucket key, public access block, TLS-only policy |
| `.../bucket-lifecycle` | noncurrent versions expire after 30 days |
| `pulumi-state-<account>-replica-provider` | provider of the replica region |
| `pulumi-state-<account>-replica/{kms-key,kms-alias,bucket,bucket-*}` | the replica and its baseline |
| `pulumi-state-<account>-replica/{replication-role,replication-policy,replication-config}` | replication |

Outputs: `<account>-backend-url`, `<account>-bucket-name`, `<account>-kms-key-arn`.

URLs for a stack's `Pulumi.<stack>.yaml` and `pulumi login`:
`backend.URL(accountID, region, profile)` is the backend
(`s3://pulumi-state-<accountID>-<region>?awssdk=v2&region=…&profile=…`), and
`backend.SecretsProviderURL(region, profile, opts...)` the secrets provider
(`awskms://alias/pulumi-state?awssdk=v2&region=…&profile=…`).
`backend.WithContextPurpose(p)` appends `&context_purpose=<p>`, for a key whose
policy allows Pulumi only with the encryption context `{purpose: <p>}`.

## `pkg/awsprofile`

AWS access by named profile, cached per `awsprofile.Manager` (`NewManager(logger)`):

| Method | Returns |
| --- | --- |
| `GetAWSConfig(ctx, profile)` | AWS SDK v2 config, region from the profile |
| `GetAWSConfigWithRegion(ctx, profile, region)` | AWS SDK v2 config in that region |
| `GetAccountID(ctx, profile)` | the account id of the profile's credentials (STS) |
| `GetAWSProvider(ctx, profile)` | Pulumi provider `provider/aws/<profile>`, region from the profile |
| `GetAWSProviderWithRegion(ctx, profile, region)` | Pulumi provider `provider/aws/<profile>/<region>`, shared by every Manager of the same program run |

The provider names are API: a stack's state holds them.

## `pkg/dns`

Route 53 zones, delegation and records. Plain resources: the logical names are
the API.

| Function | Creates |
| --- | --- |
| `NewPublicZone`, `NewPrivateZone`, `Deploy` | `<prefix>/<zone>/zone`, and `<prefix>/<zone>/delegation` (NS in the parent) when a parent is named. `Import: true` adopts an existing zone and its NS record instead |
| `AssociateZone` | `<resource>/assoc`, preceded by `<resource>/auth` when the VPC is in another account |
| `DeployRootZone` | a root private zone; exports `root-private-zone-{id,name,name-servers}` |
| `DeployEnvironmentZone` | a child private zone delegated from the root (`private-zone-{id,name,name-servers}`) and, across accounts, the parent zone's association with the child's VPC |
| `DeployPrivateEntryRecords` | `private-entry-<slug>` (A) and `cross-cluster-<slug>` (CNAME at the load balancer found by `LoadBalancerTag`); the slug function is the caller's |
| `NewDeviceRecord` | one A record at the IPv4 of the live device among the candidates (`PickDevice`: newest `LastSeen` wins, a tie is refused) |
| `LookupZoneIDByName` | an SDK lookup, private zones without a VPC association included |

## `pkg/alerting`

`alerting.Security(ctx, logger, alerting.Args{...})` deploys, in the management
account, per region: `alerting-provider-<region>`, `security-alerts-<region>`
(topic), `security-alerts-policy-<region>`, `alert-ingress-subscription-<region>`;
in the primary region also `alert-ingress-heartbeat-rule` and
`alert-ingress-heartbeat-target`; and once `alerting-provider-iam`,
`chatbot-slack-role`, `chatbot-readonly-access` and `security-alerts-chatbot`.
It returns the topic ARN of each region. `alerting.DeliveryPolicy()` is the
subscription delivery policy.

`guardduty.NewImported` (in `pkg/engine/guardduty`) adopts an existing detector
and routes its findings: `<prefix>-detector` (imported, retained),
`<prefix>-rule`, `<prefix>-eventbridge-role`, `<prefix>-eventbridge-policy`,
`<prefix>-target`.
`guardduty.NewManagement` runs `NewImported` for the management account in
every region it is given, with the detector ids as inputs: provider
`guardduty-management-provider-<region>`, prefix `guardduty-management-<region>`,
rule `guardduty-findings-<region>` (`ManagementRuleName`), target id
`guardduty-management-sns`. It refuses a region without a detector id or a topic,
and a detector id for a region it was not asked to adopt.

## `pkg/cost`

`cost.Deploy(ctx, logger, cost.Args{...})`, in the payer account: `cost-alerts-provider`;
`cost-budgets-topic`, `cost-anomalies-topic` with `-policy` and the subscriptions
`cost-budgets-alert-ingress`, `cost-anomalies-alert-ingress`; `cost-budget-total`
and `cost-budget-<account>`; `cost-anomaly-monitor-services` (imported, protected,
retained), `cost-anomaly-monitor-<account>` (when `PerAccountMonitors`) and
`cost-anomaly-subscription`; `compute-optimizer-enrollment`,
`cost-allocation-tag-<key>` and `cost-category-<name>` when the spec asks.

## `pkg/ssosync`

`ssosync.Deploy(ctx, logger, ssosync.Args{...})`: `ssosync-lambda-role`, `ssosync-lambda-basic`,
`ssosync-lambda-sso-policy`, `ssosync-log-group`, `ssosync-lambda`, `ssosync-scheduler-role`,
`ssosync-scheduler-invoke-policy`, `ssosync-schedule`. Exports `ssosync_lambda_arn`.
## `pkg/engine/sso` planning, `pkg/boundary`

`sso.DeploySets` registers `sso-ps-<key>` (children `ps-<key>`, `ps-<key>-policy-<i>`,
`ps-<key>-boundary`); `sso.DeployAssignments` registers `sso-assignments-<scope>` (children
`assignment-<scope>-<set name>-<principal>`); `sso.DeployLegacyAssignments` registers
`sso-legacy-assignments-<account>` (children `legacy-assignment-...`).
`boundary.Policies(boundary.Spec{...})` returns the `registry.Boundary` list in the order admin,
viewer, default, ACK IAM, CAPA, EKS Auto Mode node, deploy, project, audit.
## `pkg/fleet`

`fleet.Fleet{...}` with `Providers(ctx, prefix, regions)` (`<prefix>-<account>-<region>`),
`Baseline`, `Trail`, `GuardDuty`, `IAM`; `fleet.DeployUnits`. Component names are
`baseline-<account>`, `cloudtrail-<account>`, `guardduty-<account>-<region>`, `iam-<account>`,
`iam-root`, `orgunit-<ou>`; the IAM boundary providers are `provider-<account>`.

## `pkg/bootstrap`

Composes the cloud-init user-data of an instance from fragments. Pure Go, no
Pulumi or AWS import. Design: [decisions/0003-bootstrap.md](decisions/0003-bootstrap.md).

```go
p, err := bootstrap.New(bootstrap.Options{
	Lifecycle: &bootstrap.Lifecycle{ASGName: asg, HookName: hook}, // abandon on a failed download
	Objects:   &bootstrap.ObjectStore{Bucket: bucket, Prefix: "appliance"},
})
err = p.Add(
	bootstrap.Compose("base", bootstrap.Package{Name: "jq"}, bootstrap.File{Path: "/etc/app.conf", Content: conf}),
	connector.Fragment("connector", bootstrap.RunAuto), // a UnitFragment
)
r, err := p.Render() // r.UserData, r.Objects (upload them), r.SSMParameters (role policy)
```

| Item | Becomes |
| --- | --- |
| `Package{Name}` | `packages:` (sorted, repeats collapse) |
| `File{Path, Mode, Owner, Content, Encoding, Delivery, Defer}` | `write_files:` entry, or an S3 object fetched at first boot. `Delivery`: `DeliveryAuto` (inline unless the size gates move it), `DeliveryInline`, `DeliveryObject` |
| `Artifact{URL, SHA256, Dest, Mode, Run}` | first-boot download, `sha256sum -c`, install, optionally run; five attempts, then the boot stops |
| `Binary{Name, Dest, PerArch}` | the same, with the build for the instance's `uname -m` (`amd64`, `arm64`) |
| `Unit{Name, Content, DropIn, Enable, Start}` | the unit file (or `<name>.d/10-bootstrap.conf`), one `daemon-reload`, then `systemctl enable`/`start` |
| `SSMSecret{Parameter, Dest, Mode, Owner, Format, Var, Units, FirstBootOnly}` | reads the SecureString into a file under `/run` (dir 0700, file 0600 or 0400), `FormatRaw` or `FormatEnv`, on **every boot** by default (see below); the value is never in the user-data and the name is in `Rendered.SSMParameters` |
| `Step{Name, Phase, Order, Script}` | `runcmd` (`PhaseInstall`, first boot) or `bootcmd` (`PhaseBoot`, every boot, before the network), run by `bash -ec` |

Steps run in (phase, order, registration) order. Generated steps use object
fetch -1000, artifacts and binaries -200, first-boot-only secrets -100, `daemon-reload` -50, the secret loader -40
and unit enable/start 100; a user step defaults to 0. The `set -e` that heads
each list makes a failing step stop the sequence.

Size: `Options.Limit` (hard, default 16384), `Options.SoftLimit` (default
12288), `Options.Gzip` (`GzipAuto`, `GzipNever`, `GzipAlways`). Past the soft
limit the text is gzipped, then `DeliveryAuto` files go to objects largest
first, until the result fits; over the hard limit `Render` fails.
`Object.Key` is `<Prefix>/<Dir>/<sha256>.<ext>` (`Dir` defaults to `config`).
The caller uploads the objects and lets the instance role `s3:GetObject` them.

Refusals: a path or unit written by two fragments; secret material (private
keys, AWS access keys, GitHub, GitLab and Slack tokens) in a file, unit, step
or verbatim text; a non-https, credentialed or presigned download URL; a
download without a lower-case sha256; a secret file outside a directory below
`/run`; `DeliveryObject` without `Options.Objects`; an unsafe path, mode,
owner, package or parameter name.

### Secrets load on every boot

`/run` is empty after every stop and start, and a warm-pool resume is one.
So a secret is loaded on every boot by default. When the plan has an
`SSMSecret` (without `FirstBootOnly`) or a `UnitFragment` with `LoadToken`
under `RunAuto`, the composer writes three kinds of file inline:

- `/usr/local/lib/bootstrap/secrets.sh`: one `bash -e` block per secret, five
  attempts each with growing sleeps, then a `systemctl start --no-block` of
  each `UnitFragment` unit.
- `/etc/systemd/system/bootstrap-secrets.service`: `Type=oneshot`,
  `RemainAfterExit=yes`, `Wants=` and `After=network-online.target`,
  `Before=` the consuming units, `WantedBy=multi-user.target`. A first-boot
  step enables and starts it, after `daemon-reload`.
- `/etc/systemd/system/<unit>.d/20-bootstrap-secrets.conf` for each consumer
  (`SSMSecret.Units`, or the unit of a `UnitFragment`): `Requires=` and
  `After=bootstrap-secrets.service`, so a consumer does not start without its
  secret.

### The lifecycle contract (with `Options.Lifecycle`)

Auto Scaling runs the launch lifecycle hook twice for a warm-pool instance:
at `Warmed:Pending:Wait` when it launches into the pool, and again at
`Pending:Wait` when it leaves the pool and starts. An instance launched
straight into the group has only the second. A plain reboot has neither.
([Use lifecycle hooks with a warm pool](https://docs.aws.amazon.com/autoscaling/ec2/userguide/warm-pool-instance-lifecycle.html).)
cloud-init `runcmd` runs once, so the composer reports on every boot from
systemd units instead:

- **Who completes CONTINUE.** `bootstrap-ready.service` (`ready.sh`), a
  oneshot generated whenever `Options.Lifecycle` is set, enabled on the first
  boot and run on every boot. It is `After=` and `Wants=` the secret loader
  and every unit the plan starts or enables (`Unit{Enable|Start}`,
  `SSMSecret.Units`, a `UnitFragment` under `RunAuto`), so it runs once their
  start jobs have finished. **Ready means:** each of those units is
  `systemctl is-active`. A unit that is not active makes it abandon (below)
  instead of continuing. Units the caller starts some other way
  (`RunManual`, a `Step`) are not waited for; the caller orders its own work
  before, or runs its own `complete-lifecycle-action`.
- **When.** On every boot where a launch action is pending: the first boot
  (into the pool or the group) and the resume from the pool. On a boot where
  none is pending, `complete-lifecycle-action` is refused. Sending CONTINUE is
  best effort: it is tried three times, every error (a missing action
  included) is only written to the journal with AWS's message, and the script
  exits 0. The composer does not parse the error text. A missed CONTINUE on a
  real pending action falls to the hook's `DefaultResult`, so **set the hook's
  `DefaultResult` to `ABANDON`**: then the instance is replaced only when an
  action really was pending. (`pkg/appliance` does.)
- **Failure.** A secret that cannot be loaded or an inactive unit runs `complete-lifecycle-action ... ABANDON`
  and, only if that call is refused (nothing pending), `set-instance-health
  --health-status Unhealthy`. Either way the group replaces the instance. No
  marker file decides which. The generated first-boot download and fetch
  steps ABANDON only (they run only while the first-boot action is pending).
- **IAM.** The instance role needs `autoscaling:CompleteLifecycleAction`
  (on its group), `autoscaling:SetInstanceHealth`, and `ssm:GetParameter` on
  `Rendered.SSMParameters`.

The paths above are
generated: a `File` at one of them is refused. `SSMSecret.FirstBootOnly` is
the opt-in to one load in the first-boot steps (no loader, no `Units`). A
`File` or `Artifact` under `/run` is refused for the same reason; so is a
`UnitFragment` whose `LoadToken` belongs to a unit outside
`/etc/systemd/system/`. A free-form `Step` that writes under `/run` is the
caller's to make `PhaseBoot`.

`UnitFragment{Install, Unit, UnitPath, LoadToken, Start, SSMParameters}` has
the field set of `truvity/edge`'s `instanceconnector.Fragment`.
`.Fragment(name, bootstrap.RunAuto)` runs Install, writes the unit and runs
Start at first boot, and loads the token on every boot as above; `RunManual`
stops after Install and the unit file.

`bootstrap.Verbatim(userData, limit)` returns already-rendered user-data
unchanged (no header, no compression), gated on size and secrets only. It is
the zero-diff first step of adopting the package.

## `pkg/appliance`

The EC2 appliance next to `pkg/bootstrap`: an Auto Scaling group, launch
template, optional warm pool, launch lifecycle hook, least-privilege role,
security group, the plan's S3 objects and optional alarms. Design:
[decisions/0004-appliance.md](decisions/0004-appliance.md).

```go
res := appliance.Names{}.Resolve("router")            // physical names, before the plan is rendered
plan, _ := bootstrap.New(bootstrap.Options{Lifecycle: res.Lifecycle(), Objects: &bootstrap.ObjectStore{Bucket: bucket, Prefix: "router"}})
_ = plan.Add(fragments...)
ud, _ := plan.Render()

a, err := appliance.New(ctx, "router", &appliance.Args{
	UserData: ud,
	Objects:  appliance.ObjectsArgs{Bucket: bucket},
	Image:    appliance.ImageArgs{NameFilter: "al2023-ami-2023.*-kernel-6.1-arm64", Architecture: "arm64"},
	Instance: appliance.InstanceArgs{Type: "t4g.small"},
	Group:    appliance.GroupArgs{SubnetIDs: subnets},
	Hook:     &appliance.HookArgs{},       // ABANDON by default
	WarmPool: &appliance.WarmPoolArgs{},   // optional; needs Hook
	Refresh:  &appliance.RefreshArgs{},    // roll on a launch template change
	Security: appliance.SecurityArgs{VPCID: vpc},
})
```

| Input | Notes |
| --- | --- |
| `Names` | `Base` (default: the logical name), `Group`, `LaunchTemplate`, `Role`, `InstanceProfile`, `Hook` (default `<group>-launch`), `SecurityGroup` (fixed name; default: generated with prefix `<group>-`). `Names.Resolve(name)` returns them, and `.Lifecycle()` is what `bootstrap.Options.Lifecycle` needs. |
| `UserData` | A `*bootstrap.Rendered`: `Plan.Render()` or `bootstrap.Verbatim`. Its `Objects` are uploaded to `Objects.Bucket` (`aws.s3.BucketObjectv2`, AES256 or the given KMS key) and the launch template and group depend on them. |
| `Image` | Exactly one of `ID`, `NameFilter` (+ `Owners`, default `amazon`; `Architecture`) and `SSMParameter`. Resolved at deploy time and pinned in the launch template. |
| `Instance` | `Type`, `HopLimit` (default 1; IMDSv2 is always required), `RootVolume` (encrypted), `PublicIP` (nil: no network interface block), `ExtraSecurityGroupIDs`. |
| `Group` | `Min`/`Max`/`Desired` (default 1), `SubnetIDs`, `HealthCheckType`, `GracePeriodSeconds`, `EnabledMetrics`. |
| `Hook` | nil: none. `Mode` `HookInline` (default, on the group, so it exists before the first launch) or `HookSeparate`; `HeartbeatTimeoutSeconds` (900); `DefaultResult` `ABANDON`, or `CONTINUE` only with `UnsafeDefaultContinue`. |
| `WarmPool`, `Refresh` | nil: none. A warm pool without a hook is refused. |
| `IAM` | `PermissionsBoundary`, `ManagedPolicyARNs`, `PolicyName` (default `appliance`), `SSMParameters`/`ObjectKeys` (extra grants), `Statements`, `StatementsFunc`, `ExtraInlinePolicies`, and `Policy`, which replaces the generated document. |
| `Security` | `VPCID` or `ExistingGroups`; `Style` `RulesInline` (default), `RulesSeparate` (`aws.vpc.*Rule`) or `RulesLegacy` (`aws.ec2.SecurityGroupRule`); `Ingress` (a world-open rule needs `World: true`); `Egress` (nil: allow all; empty slice: none); `DeleteTimeout`. |
| `Alarms` | `ActionARNs`, `OKActionARNs` and `Alarms[]` (`Suffix`, namespace, metric, statistic, comparison, threshold, period); dimensions default to the group. |
| `Contribution` | What `appliance.Collect(modules...)` returns: fragments, statements, parameters, object keys, ingress rules and managed policies from optional modules. `Contribution.AddTo(plan)` feeds the fragments to the plan before rendering. |
| `Compat` | `ComponentType`, `Flat`, `Names` (logical names), `Aliases` (by `Kind`), `ComponentAliases`, `GroupTagsExcludeCommon`. |

The generated policy (`appliance.BootstrapStatements`, `appliance.Document`):
`ssm:GetParameter` on exactly the parameters of `UserData.SSMParameters` and
`IAM.SSMParameters` (Sid `ReadParameters`), `s3:GetObject` on exactly the plan's
object keys (`ReadObjects`) and, with a hook, `autoscaling:CompleteLifecycleAction`
and `autoscaling:SetInstanceHealth` on the group (`OwnGroup`), then the caller's
statements. Lists are sorted and de-duplicated; the JSON field order is fixed.

Logical names, by default (`<name>` is the `New` name): component
`truvity:aws-structure:Appliance` `<name>`; children `<name>` for the role,
instance profile, security group, launch template and group; `<name>-hook`
(separate hook); `<name>-managed-<i>`; `<name>-ingress-<i>[-<j>]` and
`<name>-egress-<i>[-<j>]` (separate rules); `<name>-object-<first 12 of the
sha256>`; `<name>-alarm-<suffix>`. Every one is a `Compat` hook.

Refusals, all at once and before anything is registered: no user-data; objects
without a bucket; not exactly one image source; a bad instance type, hop limit,
group size or name; no subnet; a warm pool without a hook or with a cap below
the group maximum; a `CONTINUE` default without the acknowledgement; a bad
boundary, parameter or object key; a statement with a bare `*` action or no
resource; `IAM.Policy` together with generated grants; an ingress rule open to
the world without `World`; a non-canonical CIDR; a metric alarm on a group
metric that is not enabled; `Flat` with a component type.

### Adopting an existing appliance without a replace

Step A: pass the old user-data through `bootstrap.Verbatim`, the old policy
through `IAM.Policy`, and the old logical names, component type and physical
names through `Compat` and `Names`; the preview is empty. Step B: pass the
composed plan and drop `IAM.Policy`: the launch template gets one new version
(an instance refresh rolls it out) and the role's policy is tightened in
place. `pkg/appliance/statusbox_test.go` proves step A against the resource
set of the status box (`testdata/statusbox-resources.golden.json`).
