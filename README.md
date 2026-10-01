# aws-structure

**An AWS organization's structure as code, with the discipline that makes it survivable.**

One YAML registry says what the organization *is*: its organizational
units, accounts, service control policies, Identity Center (permission
sets, groups, assignments) and the baseline each account carries. Pulumi
components apply it; a preflight refuses the plans that destroy things that
cannot be rebuilt. It is modelled on
[github-structure](https://github.com/truvity/github-structure) (registry,
engine, preflight, drift) and on [k8s](https://github.com/truvity/k8s)
(components with stable URNs).

| What | Where |
| --- | --- |
| Go module `github.com/truvity/aws-structure` | `go get github.com/truvity/aws-structure` |
| `pkg/registry` — the schema, a strict loader and the validator | Go package, no cloud dependency |

Only `pkg/registry` exists today. The engine, the preflight, drift
checking, the `aws.ini` renderer and the CLI are planned and listed under
[Status](#status); each arrives as its own reviewed change and its own
[CHANGELOG](CHANGELOG.md) entry.

## Who it is for

A team that runs an AWS Organization with IAM Identity Center and wants it
reviewed as a file rather than clicked together, with a refusal in front
of the operations that cannot be undone. It assumes you already have an
organization, a Pulumi backend and credentials for the management account.

It does not create or modify the organization itself in v1 (it looks it
up), does not enforce service control policies yet, and chooses none of
your names, ids, regions or policies.

## The model

Three ideas.

**A registry, strictly loaded.** One file, one schema. An unknown key is an
error rather than a silently dropped setting, and validation reports every
problem at once. Refusals include duplicate names, an account without an
OU, an SCP over 5120 bytes or not JSON, and permission-set include cycles
([docs/reference.md](docs/reference.md)).

**Components with stable names.** The engine will be Pulumi
`ComponentResource`s whose child names are documented API. Adopting one
over existing infrastructure keeps URNs through no-parent aliases, proven
by an empty preview ([docs/adoption.md](docs/adoption.md)).

**The engine must not be able to do the worst thing.** Replacing an
account, an OU, a permission set or the organization destroys state that
lives outside the stack, and the follow-up diff reads clean. The preflight
will refuse such plans, and service control policies stay dormant until a
lockout check exists ([docs/safety.md](docs/safety.md)).

## Install and a worked example

```sh
go get github.com/truvity/aws-structure
```

```go
//go:embed registry.yaml
var content embed.FS

reg, err := registry.Load(content, "registry.yaml") // strict, validated
if err != nil {
	return err // every problem, joined
}
for _, a := range reg.Accounts {
	fmt.Println(a.Name, "in", a.OU)
}
```

## Consumers

None recorded at v0. A repository that adopts it adds a line here.

## Neighbours

- [github-structure](https://github.com/truvity/github-structure) — the
  same shape for a GitHub organization; this repository follows its
  registry, preflight and drift layout.
- [k8s](https://github.com/truvity/k8s) — the Pulumi component and
  URN-stability model this repository follows.
- [policy](https://github.com/truvity/policy) — the contracts this
  repository is held to (`docs/contracts/component.md`).
- [ci-workflows](https://github.com/truvity/ci-workflows) — the shared CI
  and release workflows this repository calls.

## Documentation

- [docs/adoption.md](docs/adoption.md) — adopting an existing organization.
- [docs/reference.md](docs/reference.md) — the registry, field by field,
  and every refusal.
- [docs/safety.md](docs/safety.md) — what is refused and why.
- [docs/doctrine.md](docs/doctrine.md) — why it is shaped this way.
- [docs/decisions/](docs/decisions/) — the decisions, one page each.
- [SECURITY.md](SECURITY.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## The rule that makes this repository public

Mechanism only. Account ids, emails, organization and root ids, Identity
Center instance identifiers, group and permission-set names, policy
documents and regions are the caller's, in the caller's private registry
file. Nothing here defaults to one estate's value, and the tests use
documentation placeholders and never reach an AWS account.
[`hack/leak-canary.sh`](hack/leak-canary.sh) enforces the mechanical half
over tracked files and runs in the gate; its only exceptions are the
registry parser's own tests, by path, with the reason in the script.

## Status

v0: the API may still move in a minor release, and every move is a
`Breaking:` bullet in the [CHANGELOG](CHANGELOG.md). Planned, in order:

- `pkg/registry` (present): schema, strict loading, validation.
- `pkg/engine`: components for OUs, accounts, SCPs (dormant), Identity
  Center and the per-account baseline; the organization is looked up only.
- `pkg/preflight`: refuses replacing accounts, OUs, permission sets or the
  organization, and guards against lockout.
- `pkg/drift`: live read-back of the structure and the access-roles map.
- `pkg/awsconfig`: renders an Identity Center `aws.ini` and the
  access-roles map.
- `pkg/identitysource` (optional): Google Workspace to Identity Center
  groups, through ssosync.
- `awsorgctl`: the command line over all of it.

## Development

```sh
devbox shell        # pins every tool
just check          # build, test, lint, leak-canary
just vuln           # reachable Go advisories (its own workflow in CI, not in check)
```

## Releasing

Releases are a `v*` tag, which the shared release workflow turns into the
Go module version and a GitHub Release. Automatic patch releases are not
armed; the first release and every minor and major are hand-cut tags.

## Licence

MIT. See [LICENSE](LICENSE).
