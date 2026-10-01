# Changelog

Entries are written for someone deciding whether to bump: what changed for
them, and for anything breaking, what to do.

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
