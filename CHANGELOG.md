# Changelog

Entries are written for someone deciding whether to bump: what changed for
them, and for anything breaking, what to do.

## v0.12.0

- `pkg/ssosync`: the Google Workspace to Identity Center sync. `Deploy` creates the
  Lambda's role, log group and function (awslabs/ssosync, arm64), the EventBridge
  scheduler role and a schedule that runs it every 15 minutes. The SCIM endpoint
  and token are read from SSM Parameter Store; the artifact, the SSM names, the
  Google credentials, the group query and the partition are caller inputs.
  `Args.Validate` refuses a bad set before anything is registered.

## v0.13.0

- `pkg/engine/sso`: `SetSpec`, `DeploySets` (one PermissionSet per spec, named
  `sso-ps-<key>`), `Effective` (inheritance, one level deep), `DeployAssignments`
  (grants expanded by identity (scope, set, group), emitted in sorted order, one
  AccountAssignments per scope, with the pre-identity names as aliases),
  `DeployLegacyAssignments` (hand-made permission sets assigned by name) and
  `LookupInstance`.
- `pkg/boundary`: the permissions boundary policy documents of an organization
  (admin, deploy, default and viewer, audit, project, and the ACK IAM, CAPA and
  EKS Auto Mode provisioners) built from a caller hierarchy of who may delegate
  to whom. Names, prefix and partition are caller inputs.
- `pkg/engine/iam`: `VantaAuditorRole`, the auditor role of an account for a
  Vanta integration, from the vendor account, external id and names.

## v0.11.0

- `pkg/alerting`: the central security alerting of an organization.
  `Security` creates one SNS topic per region in the management account with a
  topic policy that admits the organization's `eventbridge-sns-<region>`
  roles, an HTTPS subscription to the receiver (with a retry and throttle
  policy, `DeliveryPolicy`), a heartbeat schedule with its own policy
  statement in the primary region, the Chatbot role (bounded, read-only) and
  the Slack channel configuration over every topic. It returns the topic ARNs
  by region. The organization id, Slack ids, endpoint, topic and role names,
  partition and boundary name are caller inputs.
- `pkg/engine/guardduty`: `NewImported` adopts the existing GuardDuty detector
  of an account that is not a member (the management account): the detector is
  imported and retained on delete, a rule matches every finding and its target
  publishes to the topic as the account's `eventbridge-sns-<region>` role,
  which it creates, bounded by the boundary the caller names.
- `pkg/cost`: the cost alerting of the payer account. `Deploy` creates the
  budgets and anomaly topics (each with a policy for one service principal and
  an HTTPS subscription to the receiver), one monthly budget for the whole
  organization and one per linked account, the adopted services anomaly
  monitor with an optional custom monitor per account and one immediate
  anomaly subscription, and, when the spec has them, Compute Optimizer
  enrollment, the cost allocation tags and the cost category that splits one
  account. The payer, accounts, amounts, monitor, category rules, topic names,
  endpoint and partition are caller inputs; `Args.Validate` refuses a bad spec
  before anything is registered.

## v0.10.0

- `pkg/dns`: Route 53 zones, delegation and the records an estate keeps in
  them, as plain Pulumi resources. `NewPublicZone`, `NewPrivateZone` and
  `Deploy` create or adopt zones (roots first) with the NS record that
  delegates a child from its parent; a child private zone in another account
  than its parent gets the parent zone associated with its VPC
  (`AssociateZone`). `DeployRootZone` and `DeployEnvironmentZone` are the two
  shapes an estate uses. `DeployPrivateEntryRecords` writes A records at a
  pinned address and CNAMEs at a load balancer found by tag, refusing
  wildcards and names outside the zone; `NewDeviceRecord` and `PickDevice`
  write an A record at the live device among candidates, refusing a tie.
  `LookupZoneIDByName` finds a zone through the AWS SDK, private zones
  without a VPC association included. Adds the AWS SDK v2 `config` and
  `route53` modules to go.mod. Logical names are `<prefix>/<zone>/{zone,
  delegation,parent-assoc}`; zone names, accounts, profiles and hostnames are
  caller inputs.

## v0.9.0

- `pkg/backend`: the storage of a Pulumi state backend. `NewBucket` creates
  one account's state bucket (KMS key with rotation and alias, versioning,
  SSE-KMS, public access blocked, TLS-only policy, 30-day noncurrent
  expiry); `NewReplication` adds a cross-region replica (provider, key,
  bucket, replication role and policy, replication configuration). Logical
  names are `pulumi-state-<account>/...` and `pulumi-state-<account>-replica/...`,
  so a stack that already holds these resources adopts the package with an
  empty preview. Bucket names, the key alias, regions, the partition and the
  name of the permissions boundary are caller inputs; `Bucket.Validate` and
  `ValidateSet` refuse a bad set before anything is registered.

## v0.8.0

- `pkg/engine/guardduty`: new optional `Args.FindingPublishingFrequency`
  (`FIFTEEN_MINUTES`, `ONE_HOUR` or `SIX_HOURS`) sets how often updates of an
  existing finding are published to EventBridge. Empty keeps the provider
  default, so existing callers see no change; the detector is updated in
  place when the value is set. Any other value is refused.

## v0.7.0

- `pkg/engine/org`: `truvity:aws-structure:OrganizationalUnit`, one
  organizational unit with its member accounts as a Pulumi component. The unit
  and every account are protected and retained on delete; nothing else is. The
  organization is only read (`LookupRootID`), never managed. The parent id,
  names, emails and the provider come from the caller. Names from a hook;
  `LegacyTopLevel` adds a `noParent` alias per child. A unit or account that
  carries an id or SCPs is refused. Refusals are reported together.
  `SCPs` renders the eight service control policy documents from typed values
  as valid JSON under 5120 bytes, built from the caller's partition,
  management account id, allowed regions and bucket patterns. They stay
  dormant: nothing creates or attaches a policy.

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
