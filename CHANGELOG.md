# Changelog

Entries are written for someone deciding whether to bump: what changed for
them, and for anything breaking, what to do.

## Unreleased

- **`pkg/engine/sso`: the permissions boundary attachment of a permission set is always `RetainOnDelete`.** `aws:ssoadmin/PermissionsBoundaryAttachment` has only ForceNew properties and its id is the permission set's ARN, so renaming the resource or changing the boundary name is a replace whose delete removes whatever boundary the set holds, including the one the create just put (a window with no boundary until the next provisioning). The delete is now a state-only forget, so a replace can no longer strip a live boundary. Nothing changes in AWS; the option is recorded on the next update of the stack. To remove a boundary on purpose, call `aws sso-admin delete-permissions-boundary-from-permission-set`, provision the set to its accounts, and drop the resource from the program. A caller that carries its own transform for this can drop it, but a state entry created before this release gets the flag only once the program runs with it.

## v0.28.1

- **`pkg/boundary`: the builder boundaries (`ProjectACK`, `EmployeeACK`) allow creating a key with tags.** Creating a KMS key with `Tags` is authorized as `kms:TagResource` on a key that has no tag yet, which the builder document allowed only under `aws:ResourceTag/project`, so tagged creation could be refused. `AllowCreateKey` now also allows `kms:TagResource` under the same `aws:RequestTag/project` condition and only where the key has no `project` tag, so a key of another project is never retagged. There is deliberately no Deny on untagged keys: AWS authorizes the tagging of `CreateKey` against the new, still untagged key, so such a Deny would block every tagged creation. Keeping an untagged key from being claimed by tagging it with a builder's project is the account owner's rule: every customer-managed key carries a `project` tag (`platform` for the platform's own). Only a caller that names `ProjectACK` or `EmployeeACK` sees the two documents change. Fix.

## v0.28.0

- **`pkg/boundary`: the role, controller and project boundaries, beside the old ones.** Additive: a `Spec` that names only the old shapes renders exactly the nine documents it rendered before, byte for byte. New `Names` fields name a second generation, all or nothing (a half-named generation is refused): `RoleAdmin`, `RoleDeployer`, `RoleAuditor`; `ACKControllerIAM`, `ACKControllerEKS`, `ACKControllerS3`, `ACKControllerKMS`, `ACKControllerDynamoDB`; `ProjectACK`, `EmployeeACK`, `ProjectWorkload`. `Default` and `EKSAutoNode` are shared. `Policies` returns the old documents (when named), then the new ones, so both generations can exist in an account while roles move over. New `Spec` fields: `ProjectBucketPrefix`, `ACK` (`ACKScope`: `BuilderRoles`, `IAMNamespace`, `IAMRoleSlugs`, `PodIdentityRoleSlugs`, `Buckets`; every platform-specific name is an input, none is written in the package) and `LegacyProjectNames`.
  - **`RoleAdmin`, `RoleAuditor`:** the admin and audit documents under the new names, including the `OrgAdmin` variants. The admin document lists each delegated boundary by its exact name (and itself): `Spec.ClassPrefix` and its wildcard apply only to the old `Names.Admin`. Adding a boundary to the hierarchy is a reviewed edit of the admin document; an unlisted `<prefix>tech-...` boundary is out of reach.
  - **`RoleDeployer`:** the deploy document plus a name rule: a role is created as `<cluster>-<project>.*` from its own request tags, and only under the boundaries its hierarchy entry delegates (give it `ProjectWorkload` alone for the final form).
  - **`ACKController*`:** allowlists sized to what each ACK controller does as itself, since with an IAMRoleSelector it assumes the namespace's builder role (`ACK.BuilderRoles`) and acts as that. IAM: create and manage roles named `*-<slug>-*` for `ACK.IAMRoleSlugs` that carry ACK's `services.k8s.aws/namespace` tag `ACK.IAMNamespace`, under the delegated boundary, inline policies only; EKS: Pod Identity associations and `iam:PassRole` for those slugs and `ACK.PodIdentityRoleSlugs` only (`iam:PassedToService` as `StringEqualsIfExists`); S3: `s3:*` on the buckets `ACK.Buckets` and no objects; KMS and DynamoDB: reads.
  - **`ProjectACK`, `EmployeeACK`:** the boundary of a project's builder role (and, under its own name, an employee sandbox's). One document for every account and project: it reads the principal's own `project` and `cluster` role tags. A builder creates, tags, passes and deletes only roles named `<cluster>-<project>.*` that carry its own project tag, bound by the one delegated boundary (`ProjectWorkload`); attaches only its own policies; binds Pod Identity associations only in its own cluster; administers only its own buckets (`<ProjectBucketPrefix><cluster>-<project>-*`, bucket-level actions only) and KMS aliases; and creates keys only with its own `project` tag, which fixes a builder that could never create one. It denies setting `project` or `cluster` to another value and removing either (the tags are what the workload boundary keys on), scheduling a key's deletion or disabling it, and never allows key policies, grants, object access, SSM, DynamoDB, SQS, users or OIDC providers. A hierarchy entry for a builder must delegate exactly `ProjectWorkload`, or `Validate` refuses it.
  - **`ProjectWorkload`:** data actions only, keyed on the role's own tags: KMS use of keys tagged with its project, objects and listing in its buckets, ECR pull from `<project>/...`; explicit deny of `iam:*`, so the delegation chain ends here.
  - **`LegacyProjectNames`:** the transition form. `ProjectACK` and `ProjectWorkload` also accept `<cluster>-*<project>-*` for roles and policies and `<prefix><cluster>-*<project>-*` for buckets, `ProjectACK` denies the platform roles those patterns reach (`<cluster>-<slug>-*`), and `RoleDeployer` drops its name rule. Setting it back to false is a policy-version update of the same names, so nothing is re-attached. `EmployeeACK` ignores it. For `RoleAdmin` the transition is the hierarchy: list the old boundaries as delegates until the last role that uses one is gone.
  - **`Validate`** also refuses: a delegate or boundary name that is a pattern, a name given to two shapes, `Default` or `EKSAutoNode` empty, a builder that delegates anything but `ProjectWorkload`, an IAM controller or deployer without a delegate, and a spec that names no shape. Every rendered document is checked in the tests to stay within IAM's 6,144-character limit (the largest, the transition builder, is within 300 characters of it); each has a golden file in `pkg/boundary/testdata/current`.

  Nothing is removed. The old shapes and `Names.Viewer` stay until their last role is gone; a later release drops them. A caller that does not set the new names sees no change.

## v0.27.1

- **`pkg/boundary`: `OrgAdminManagement` no longer denies changes to the reserved roles of Identity Center.** In the management account Identity Center provisions a permission set's inline policy, managed-policy attachments and boundary onto the `AWSReservedSSO_*` roles with the caller's IAM permissions, so the inherited `DenyChangePermissionsSetsRoles` deny of `iam:PutRolePolicy` and the other role actions on `role/aws-reserved/sso.amazonaws.com/*` stopped a role-admin session from provisioning any permission-set change to that account. In the management variant that statement now lists only `role/AWSServiceRoleFor*`, which stays denied. `OrgAdminOff` and `OrgAdminMember` are byte for byte as before (member accounts are provisioned through the service-linked role). Only a caller that set `OrgAdmin: OrgAdminManagement` sees the boundary change. Fix.

## v0.27.0

- **`pkg/boundary`, `pkg/engine/sso`: one admin permission set for the whole organization (opt-in).** Identity Center permission sets are organization-wide and a set's customer-managed boundary is resolved by name in each account, so the boundary of that name may differ per account. `boundary.Spec.OrgAdmin` (`OrgAdminMode`) selects the admin boundary's variant: `OrgAdminManagement` explicitly allows `organizations:*`, `account:*`, `sso:*`, `sso-directory:*` and `identitystore:*` and the editing of the account's boundary policies (making the admin there equivalent to a full administrator, by design) and keeps the rest of the deny list; `OrgAdminMember` denies those actions, carving out the reads PowerUserAccess grants (the six of PowerUserAccess v12, `boundary.OrgAdminReadCarveOuts()`), so a member account's admin keeps what it has today. `sso.OrgAdminActions`, `sso.OrgAdminStatement` and `sso.OrgAdminInlinePolicy(base)` build the matching inline policy for the admin set; the caller decides whether to attach it. The zero value, `OrgAdminOff`, renders every boundary byte for byte as before, so nothing changes unless a caller opts in. `pkg/preflight` needs no waiver for the update. Additive.

## v0.26.0

- **`pkg/engine/sso`: `DeployBreakGlass`, break-glass added beside the normal grants.** A scope matrix built into `DeployAssignments` can only replace the set on an account, so it could not add the registry's `identity_center.break_glass` alongside it. `DeployBreakGlass(ctx, logger, BreakGlassArgs)` declares one `AccountAssignment` of that principal and permission set (ids and ARNs are inputs) on every account that is not `closed` and has an id, including accounts directly under the organization root, as one `AccountAssignments` component `sso-break-glass-<account>` per account; `Names`, `LegacyTopLevel` and `LegacyNames` keep URNs stable. `Skip(account)` leaves out the accounts the caller's own assignments already grant it on. Also `Registry.BreakGlassTargets()`, and in `pkg/preflight` `LockoutWith`, `BreakGlassBuilder` and `Opts.BreakGlassBuilder`, so the registry guard counts the builder's accounts as reached (`Lockout` is unchanged). Additive.
- **`pkg/registry`: an account may sit directly under the organization root.** `Account.OU` takes `registry.OURoot` (`root`), as the management account of an organization usually does; before, every account had to name a declared OU, so a registry could not describe such an organization without the drift check reporting that account as `unmanaged`. No OU may be named `root`. `pkg/drift` compares an account at `root` with the live root. Additive.
- **`pkg/registry`: `Account.Closed`, the flag that an account was closed.** AWS keeps a closed account in the organization, SUSPENDED, until it is purged, so a registry could only call it undeclared (`unmanaged`) or declared (`not-active`) and drift was never clean. With `closed: true` the account is declared and expected not to be active: `pkg/drift` reports it only if it is active again (`edited`), no assignment is expected on it, and the break-glass reach guard of `pkg/preflight` does not ask for a way into it. Additive.
- **`awsorgctl access-roles`: `-accounts`, and closed accounts are skipped.** `-accounts a,b` lists only the named accounts (an undeclared, id-less or closed name is refused); without it the command reads every account that has an id and is not `closed`, where before it tried to assume a role in each, closed ones too, and failed on the first. Additive.

## v0.25.0

- **`awsorgctl`: the command line.** Nothing it runs writes to AWS. Release archives for linux and darwin (amd64, arm64), or `go install github.com/truvity/aws-structure/cmd/awsorgctl@<tag>`. Commands:
  - `validate`: load and validate a registry.
  - `preflight`: `pkg/preflight` over a `pulumi preview --event-log` file and the registry; exits 1 on a refusal. `-break-glass-set`/`-break-glass-principal` turn on the plan half of the break-glass guard.
  - `drift`: `pkg/drift` against the live organization, with a management profile and the Identity Center region; `-fail` exits 1 on drift.
  - `access-roles`: the access-roles map, assuming `-role` (default `OrganizationAccountAccessRole`) in each member account.
  - `aws-ini`: the AWS CLI config of every account with an id, one profile per permission set assigned to it (`<account>@<set>`).
  - `version`.

  The README no longer calls the engine, preflight, drift and CLI planned.

## v0.24.0

- **`pkg/appliance`: the EC2 appliance next to `pkg/bootstrap`.** `New(ctx, name, &Args{...})` registers one component (`truvity:aws-structure:Appliance`, or the type you name) with an Auto Scaling group of 1..N and its launch template, an optional warm pool, an `EC2_INSTANCE_LAUNCHING` lifecycle hook (inline on the group, or a resource; `DefaultResult` `ABANDON` unless you set `UnsafeDefaultContinue`), an instance role and profile, a security group (inline, `aws.vpc` or legacy `aws.ec2` rules), the plan's S3 objects, optional CloudWatch alarms and an instance refresh. The image is a name filter, an SSM parameter or an id; IMDSv2 is always required, the hop limit is configurable. The role policy is built from the user-data: `ssm:GetParameter` on exactly the plan's parameters, `s3:GetObject` on exactly its object keys, `autoscaling:CompleteLifecycleAction` and `SetInstanceHealth` on the group, plus your statements; the builders (`BootstrapStatements`, `Document`, `AssumeRolePolicy`) are exported and byte-stable. `Names.Resolve(name).Lifecycle()` gives the plan its lifecycle before it is rendered. For an existing appliance, `Compat` (component type or `Flat`, logical names, aliases, group tag behaviour), `Names` and `IAM.Policy` plus `bootstrap.Verbatim` make step A an empty preview; composed user-data is step B. Refuses, all at once: no user-data, objects without a bucket, a warm pool without a hook, a bare `*` action, a world-open ingress rule without `World`, and more (see docs/reference.md). `Module` and `Contribution` are the extension points for optional modules, which are a later change. New package, additive. Design: docs/decisions/0004-appliance.md.
- **`pkg/preflight`: the guard to run before an apply.** It refuses, all findings at once:
  - **`irreplaceable`:** a replace (`replace`, `create-replacement`, `delete-replaced`, ...) or a delete of an `Account`, `OrganizationalUnit`, `PermissionSet` or `Organization`.
  - **`break-glass`:** a registry without `identity_center.break_glass`, or with an account that no assignment of it reaches. Also a plan that deletes or replaces a break-glass `AccountAssignment`, matched by `permissionSetArn` and `principalId`.
  - **`scp-on-management`:** a service control policy on the root, the management account or an OU above it, in the registry or as a planned `PolicyAttachment`, without a waiver.
  - **`waiver-expired`:** a waiver past its `expires` day, or one with nothing left to waive.

  `Run(ctx, stack, Opts)` previews an automation-API stack and judges it. `Check(steps, Opts)` takes steps instead, from `StepsFromEvents(ReadEventLog(f))` over a `pulumi preview --event-log` file. `Plan`, `Lockout`, `ProtectedTargets`, `Waived` and `Err` are the parts. New package, additive.
- **`pkg/registry`: `identity_center.break_glass` and `waivers[]`.**
  - `break_glass` takes `principal`, `principal_type` (`group` by default) and `permission_set`; both the principal and the permission set must be declared.
  - A waiver takes `guard` (only `scp-on-management`, `GuardSCPOnManagement`), `target` (an OU or account name, or `root`), `reason` and `exit_condition` (both required) and an optional `expires` date (`YYYY-MM-DD`, `DateLayout`). One waiver per guard and target.

  Both keys are optional for the registry, which stays valid without them. The preflight's lockout guard refuses a registry that has no `break_glass`. Additive.
- **`pkg/drift`: read the organization back and compare it with the registry; the access-roles map.**
  - `Read(ctx, Clients{...})` walks the organization: the root, the OUs, the accounts with their state, and the service control policies on each. It also reads Identity Center: permission sets, groups, users and assignments in every active account.
  - `Compare(registry, live)` reports, sorted:
    - `unmanaged` (made by hand, or a policy attached while dormant; `FullAWSAccess` excepted);
    - `missing`, `moved`, `edited` (an OU name or account email);
    - `unrecorded-id` (it exists, but the registry has no id for it);
    - `not-active` (suspended or closed).
  - `AccessRoles(ctx, accounts, clientFor)` lists the roles Identity Center provisioned in each account (`AWSReservedSSO_<set>_<suffix>`, with and without the path). `RenderAccessRoles` writes them as YAML under a header.
  - Read only: every call is a List or Describe. The clients are inputs: small interfaces the SDK clients satisfy.
  - New package, additive. New dependencies: the AWS SDK's `organizations`, `ssoadmin`, `identitystore` and `iam` clients.

## v0.23.0

- **`pkg/engine/guardduty`: adopt the management account's detectors in every region.** New `NewManagement(ctx, logger, ManagementArgs{...})`: one `NewImported` per region of `Regions`, the existing detector ids (`DetectorIDs`, by region) and the topics (`TopicARNs`, by region, as `pkg/alerting` returns them) as inputs. The names are fixed: provider `guardduty-management-provider-<region>`, children `guardduty-management-<region>-{detector,rule,eventbridge-role,eventbridge-policy,target}`, rule `ManagementRuleName(region)` (`guardduty-findings-<region>`), target id `ManagementTargetID`, description `ManagementRuleDescription`. `ManagementArgs.Validate` refuses, all at once, a missing profile, partition or boundary, an empty or repeated region, a region without a detector id or a topic, and a detector id for a region not in `Regions`. Additive.
- **`pkg/registry`: the ISO 27001 account password policy as a preset.** New `ISO27001PasswordPolicy()`: minimum length 14, maximum age 90 days, the last 24 passwords not reusable, symbols, numbers, upper and lower case required. It returns a fresh value each call, for `iam.Args.PasswordPolicy`, `fleet.IAMArgs.PasswordPolicy` or a registry's `baseline.password_policy`. Additive.
- **`pkg/awsprofile`: AWS access by named profile.** `Manager` (`NewManager(logger)`) caches, per profile, the AWS SDK v2 config (`GetAWSConfig`, `GetAWSConfigWithRegion`), the account id behind the profile (`GetAccountID`, STS `GetCallerIdentity`) and a Pulumi AWS provider: `GetAWSProvider` registers `provider/aws/<profile>` (region from the profile), `GetAWSProviderWithRegion` registers `provider/aws/<profile>/<region>` and shares it with every other `Manager` of the same program run, so a program composed of several builders registers each provider once. The provider names are API. New package, additive.
- **`pkg/backend`: the secrets provider URL of a state bucket's key.** New `SecretsProviderURL(region, profile, opts...)` (`awskms://alias/pulumi-state?awssdk=v2&region=…&profile=…`) and the option `WithContextPurpose(purpose)`, which appends `&context_purpose=<purpose>` for a key that allows Pulumi only with that encryption context. Additive.

## v0.22.0

- **`pkg/bootstrap`: a cloud-init user-data composer from fragments.** A `Fragment` adds items to a `Plan` (`Package`, `File`, `Artifact`, `Binary`, `Unit`, `SSMSecret`, `Step`; `Compose` groups items into a fragment) and `Plan.Render` returns the `#cloud-config`, gzipped when it must be, plus the S3 objects the caller uploads and the SSM parameter names the role needs. The output is deterministic. It refuses two fragments writing the same path or unit, secret material in any content (a secret is an `SSMSecret`: read at boot into a file under `/run`, never in the user-data), an `Artifact` or `Binary` without an https URL and a sha256, and user-data over the hard limit (default 16384 bytes). Past the soft limit (12288) it gzips, then moves `DeliveryAuto` files, largest first, to content-addressed objects that a first-boot step fetches, verifies and installs; with `Options.Lifecycle` a failed download or fetch abandons the lifecycle action. Secrets (`SSMSecret`, and `LoadToken` of a `UnitFragment` under `RunAuto`) load on every boot, because `/run` is empty after a stop and start and warm-pool instances resume that way: the composer writes `/usr/local/lib/bootstrap/secrets.sh`, `bootstrap-secrets.service` (oneshot, after `network-online.target`) and a drop-in that makes each consuming unit require it. With `Options.Lifecycle` the composer also generates `bootstrap-ready.service`, which runs on every boot after the loader and the plan's units, checks they are active and completes the launch lifecycle action with CONTINUE (best effort: tried three times, errors only logged, so a plain reboot with no action is harmless and a missed CONTINUE falls to the hook's `DefaultResult`, which should be `ABANDON`; a warm-pool instance has one at `Warmed:Pending:Wait` and again on resume). A failure tries ABANDON, and only if that is refused (`autoscaling:SetInstanceHealth`) marks the instance unhealthy. `SSMSecret.FirstBootOnly` opts out; a `File` or `Artifact` under `/run` is refused. `UnitFragment{Install, Unit, UnitPath, LoadToken, Start, SSMParameters}.Fragment(name, run)` has the shape of the `instanceconnector` fragment in `truvity/edge`, so a consumer converts with a field copy (neither module imports the other). `Verbatim` carries already-rendered user-data byte for byte. No Pulumi or AWS import. New package, additive.

## v0.21.1

- **Security: Go toolchain 1.27.2 and `golang.org/x/net` v0.60.0.** Clears the `govulncheck` findings in `golang.org/x/net` v0.58.0 and in the standard library of Go 1.27.1 (`net/http`, `net/http/internal/http2`, `crypto/tls`, `mime/multipart`, `os`). `go.mod` now says `toolchain go1.27.2`; `golang.org/x/sync`, `x/sys`, `x/term` and `x/text` moved up with `x/net`. `golangci-lint` moves to 2.14.0 in `devbox.json` so lint can read the Go 1.27.2 standard library. `devbox` has no `go` 1.27.2 yet, so the dev shell keeps `go@1.27.0` and fetches the toolchain from `go.mod`. No API change.

## v0.21.0

- **`pkg/engine/trail`, `pkg/fleet`: leave chosen S3 prefixes out of the trail's data events.** New `trail.Args.DataEventExclusions` (S3 object ARN prefixes, each `<bucket ARN>/` with an optional key prefix) and `fleet.TrailArgs.DataEventExclusions` (a map from account name to such a list). Left empty, nothing changes: the trail keeps its classic event selector and the render is byte-identical. With entries, that account's trail switches to advanced event selectors: "Management events" (`eventCategory` Equals `Management`, the same as the classic management events, read and write) and "S3 data events" (`eventCategory` Equals `Data`, `resources.type` Equals `AWS::S3::Object`, `resources.ARN` NotStartsWith the exclusions). The trail is updated in place. `Args.Validate` refuses an entry that is not an S3 object ARN prefix. Additive.
- **`pkg/engine/guardduty`, `pkg/fleet`: switch chosen detector features off.** New `guardduty.Args.DisabledFeatures` (names such as `S3_DATA_EVENTS`, checked against GuardDuty's list) and `fleet.GuardDutyArgs.DisabledFeatures` (a map from account name to such a list). Left empty, nothing changes: no new resource. With entries, one `aws.guardduty.DetectorFeature` per name (status `DISABLED`, logical name `<component>-feature-<name in lower case, dashes>`) is created next to the detector, with the detector's parent, provider and legacy alias. The detector's deprecated `datasources` block is not used. Additive.

## v0.20.0

- **`pkg/backend`: a state bucket can use a key that already exists.** New `Bucket.ExistingKeyARN` and `Bucket.LegacyKeyAlias`, and `Result.KMSKeyArn`. Left unset, nothing changes: the same resources, the same logical names, the same policy documents. With `ExistingKeyARN` (a single-region key in the bucket's account and region, checked by `Validate`) no key is created: `alias/<KMSAlias>` (`<prefix>/kms-alias`) points at that key, the bucket's default encryption and the `<account>-kms-key-arn` export name it, and the replication role may `kms:Decrypt` with it. The replica bucket keeps its own key. The key policy of the existing key is the caller's. For an account that already has the library's key, the alias is updated in place (same logical name) and the old key is no longer declared, which would make Pulumi delete it; to avoid that set `LegacyKeyAlias`: the old key stays under its logical name `<prefix>/kms-key`, is marked retain-on-delete, gets that second alias (`<prefix>/kms-legacy-alias`), and the replication role may decrypt with both keys. Drop `LegacyKeyAlias` later to let the old key leave the program; because it is retained, Pulumi does not call `ScheduleKeyDeletion` (a permissions boundary may deny it), so schedule the deletion yourself. `Result.KMSKey` is now nil when `ExistingKeyARN` is set without `LegacyKeyAlias`. Additive.

## v0.19.0

- **`pkg/alerting`, `pkg/cost`: an optional SQS subscription on the alert topics.** New `alerting.Delivery{QueueARN, DisableHTTPS}`, a field `Delivery` of `alerting.Args` and `cost.Args`. With `QueueARN` set, every topic these packages own (each region's security topic, which also carries the heartbeat, and the Budgets and Cost Anomaly topics) gets one more `aws.sns.TopicSubscription`, protocol `sqs`, endpoint the queue, raw message delivery off (the receiver verifies the SNS envelope). It is created in the topic's account and region, so the queue may be in another account or region; the queue's policy must admit the topic. New logical names: `alert-ingress-sqs-subscription-<region>` and `cost-{budgets,anomalies}-alert-ingress-sqs`. Left unset, the render is byte-identical and the HTTPS subscriptions are untouched. `DisableHTTPS` (default off) drops the HTTPS subscriptions for the cutover's last step; it needs `QueueARN`, and `Endpoint` is then no longer required. `Args.Validate` refuses a queue ARN that is not an SQS ARN of the partition and `DisableHTTPS` without a queue. Additive.

## v0.18.0

- **`pkg/awsconfig`: the AWS CLI config file of a set of Identity Center accounts.** `Render` writes one `sso-session`, a `[default]` profile that mirrors a named one, and a profile for every (account, role) pair in the order given; `Account.Profiles` expands an account into one profile per role. The caller decides which accounts exist, which roles each carries (an account whose permission sets were never renamed carries the ones it has), the session and the daily driver; every profile signs in through the session the config names. `Render` refuses a missing session field, a profile name twice and a `Default` no section holds. The output is deterministic, so a checked-in copy can be compared with a fresh render. New package, additive.

## v0.17.0

- `pkg/cost`: `Spec.Validate(partition)` reports every shape AWS refuses only at apply: account ids (12 digits) and names, repeated accounts, the default monitor's ARN for the partition, a cost category's account, its node pool names, service codes (not display names) and every literal value against AWS's category-value pattern. `Args.Validate` calls it, so a spec the old check accepted can now be refused. `NodePoolValue(pool)` is the `nodes-<pool>` value.

## v0.16.0

- `pkg/engine/sso`: `GrantsFor` turns one scope's access matrix into the `Grant`s `DeployAssignments` expands. The caller gives a table from its access levels to permission set names, the roles that hold a level on the scope (`Holder`) and an optional filter for groups that must not be assigned; the result is sorted by role, set and group. Additive.

## v0.15.0

- `pkg/boundary`: `Spec.Validate` now checks the delegation graph as well as the required names. A delegate that is not an entry of `Hierarchy`, a leaf shape (`Names.Default`, `Names.Project`, `Names.Audit`) that delegates, and a cycle through the delegates are each reported. A hierarchy that listed a delegate without an entry of its own is now refused: add the entry.

## v0.14.0

- `pkg/fleet`: the per-account loops of an organization's root stack over the
  engines. `Fleet` holds the member accounts, the expected set (a drifted set is
  refused), the regions and the skip list; it builds a cross-account provider
  per account and region through the organization access role and deploys one
  component per account for the baseline (`baseline-<account>`), the IAM
  controls (`iam-<account>`, `iam-root`), CloudTrail (`cloudtrail-<account>`)
  and GuardDuty (`guardduty-<account>-<region>`). `DeployUnits` creates the
  organizational units and their accounts (`orgunit-<ou>`) and exports the
  account ids. Accounts, regions, profile, bucket name formats and the boundary
  name are caller inputs.

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

## v0.12.0

- `pkg/ssosync`: the Google Workspace to Identity Center sync. `Deploy` creates the
  Lambda's role, log group and function (awslabs/ssosync, arm64), the EventBridge
  scheduler role and a schedule that runs it every 15 minutes. The SCIM endpoint
  and token are read from SSM Parameter Store; the artifact, the SSM names, the
  Google credentials, the group query and the partition are caller inputs.
  `Args.Validate` refuses a bad set before anything is registered.

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
