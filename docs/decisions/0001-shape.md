# 0001 — Registry, engine, preflight, drift; components with aliases

**Status:** Accepted

## Context

An AWS organization's structure (OUs, accounts, SCPs, Identity Center, a
baseline) is today changed by hand. The same problem was solved for a
GitHub organization by github-structure: a registry, an engine that applies
it, a preflight that refuses destructive plans, and drift checks. The
Pulumi component and URN-stability model comes from k8s.

## Decision

1. **Four layers, in this order of dependency.** `pkg/registry` (schema,
   strict loading, validation) has no cloud dependency. `pkg/engine`
   applies a validated registry. `pkg/preflight` judges the engine's
   `pulumi preview` before any apply. `pkg/drift` reads the live structure
   back and compares. Around them: `pkg/awsconfig` renders an Identity
   Center `aws.ini` and an access-roles map, optional `pkg/identitysource`
   fills groups from Google Workspace through ssosync, and the CLI
   `awsorgctl` fronts them.
2. **Components with documented children and no-parent aliases.** Each
   engine piece is a `ComponentResource` whose child names are API. A
   caller adopting it over loose resources keeps URNs through
   `LegacyTopLevel`-style aliases (an alias whose parent is the stack
   root), as k8s does.
3. **v1 scope.** Organization (looked up only), OUs, accounts, SCPs
   (dormant), Identity Center (permission sets, attachments, assignments)
   and a per-account baseline (permissions boundaries, password policy,
   EBS default encryption, Access Analyzer, an auditor role).
4. **The organization is looked up, not managed.** `organization.manage:
   true` is refused. Managing it is a later decision with its own page.
5. **Strict registry.** Unknown keys are errors; validation reports every
   problem at once.

## Consequences

- Only `pkg/registry` exists at first; each later layer lands as its own
  reviewed change.
- A registry that asks for more than v1 does is refused by name rather
  than half-applied.
- The engine's child names are API from its first release.
