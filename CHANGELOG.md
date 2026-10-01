# Changelog

Entries are written for someone deciding whether to bump: what changed for
them, and for anything breaking, what to do.

## v0.6.0

- `pkg/engine/sso`: IAM Identity Center access as Pulumi components.
  `truvity:aws-structure:PermissionSet` is one permission set with its AWS
  managed policy attachments, optional inline policy and optional permissions
  boundary (a customer managed policy reference by name); the permission set
  is protected and retained on delete, nothing else is.
  `truvity:aws-structure:AccountAssignments` is the assignments of groups
  and users to permission sets on one target account. `LookupGroupIDs`
  and `LookupPermissionSetARN` read groups filled by a directory sync and
  permission sets made by hand. The instance ARN, principal ids, account ids,
  permission set ARNs, managed policy ARNs and the provider come from the
  caller, so no ARN or account id lives in the package. Names from a hook;
  `LegacyTopLevel` adds a `noParent` alias per child, and an assignment's
  `LegacyNames` add earlier-name aliases. Refusals are reported together.

## v0.5.0

- `pkg/engine/guardduty`: `truvity:aws-structure:AccountRegionGuardDuty`, the
  GuardDuty finding alerting of one account in one region as a Pulumi
  component: an enabled detector, the role EventBridge assumes (with the
  caller's permissions boundary), its `sns:Publish` policy, an EventBridge rule
  matching GuardDuty findings and the rule's target. The provider, the topic
  ARN and the permissions boundary ARN come from the caller, so no ARN or
  account id lives in the package. Names from a hook; `LegacyTopLevel` adds a
  `noParent` alias per child. Nothing is protected or retained. It does nothing
  at the organization level: no delegated administrator, organization
  configuration, member accounts, protection plans or publishing destinations.

## v0.4.0

- `pkg/engine/trail`: `truvity:aws-structure:AccountTrail`, the audit trail of
  one account as a Pulumi component: a KMS key with rotation and an alias, the
  trail bucket (policy, public access block, KMS encryption, lifecycle,
  versioning, access logging, cross-region replication), its access-log and
  replica buckets, the replication role and a multi-region trail with log file
  validation and S3 data events. Providers (the account's, and the replica
  region's) come from the caller; bucket names, the key alias, the key
  administrator and trail ARNs, the data-event resource and the replication
  role's name and permissions boundary are inputs, so no ARN or account id lives
  in the package. Names from a hook; `LegacyTopLevel` adds a `noParent` alias
  per child. Nothing is protected or retained. It is a per-account trail, not
  an organization trail.

## v0.3.0

- `pkg/engine/iam`: `truvity:aws-structure:AccountIAM`, the per-account
  IAM controls as a Pulumi component: the account password policy
  (`registry.PasswordPolicy`), boundary policies (`registry.Boundary`) and an
  auditor role with its trust policy, AWS-managed attachments and an optional
  customer-managed policy. The provider comes from the caller (boundaries may
  take their own); names from a hook; `LegacyTopLevel` adds a `noParent` alias
  per child. No document or ARN lives in the package. `AccountBaseline` still
  refuses these fields and now points at the new component.

## v0.2.0

- `pkg/engine/baseline`: `truvity:aws-structure:AccountBaseline`, the
  per-account baseline as a Pulumi component: EBS default encryption and
  IAM Access Analyzers per region, from a `registry.Baseline`. Providers
  come from the caller; names from a hook; `LegacyTopLevel` adds a
  `noParent` alias per child. Password policy, auditor role and boundaries
  are refused until implemented.

## v0.1.0

- `pkg/registry`: the registry schema for the v1 scope (organization,
  OUs, accounts, SCPs, Identity Center permission sets, groups and
  assignments, per-account baseline), a strict loader (`Parse`, `Load`:
  unknown keys, a second document and an empty file are errors) and
  `Registry.Validate`, which reports every problem at once.
- Refusals: duplicate names, an account without an OU, an unknown
  reference, a parent cycle between OUs, an SCP over 5120 bytes or not
  JSON, permission-set include cycles, `organization.manage: true` and
  `scp_enforcement: enforced` (both unsupported in v1).
- No engine, preflight, drift, `aws.ini` renderer or CLI yet.
