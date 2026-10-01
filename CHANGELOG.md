# Changelog

Entries are written for someone deciding whether to bump: what changed for
them, and for anything breaking, what to do.

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
