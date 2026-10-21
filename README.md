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
| Go module `github.com/truvity/aws-structure/policy`: a typed IAM policy document, standard library only | `go get github.com/truvity/aws-structure/policy` ([policy/README.md](policy/README.md)) |
| `awsorgctl`, the command line | the release archives, or `go install github.com/truvity/aws-structure/cmd/awsorgctl@latest` |
| `pkg/registry`: the schema, a strict loader and the validator | no cloud dependency |
| `pkg/engine/{org,sso,iam,baseline,trail,guardduty}`: Pulumi components with documented child names | [docs/reference.md](docs/reference.md) |
| `pkg/preflight`: the refusals in front of an apply | [docs/safety.md](docs/safety.md) |
| `pkg/drift`: the live read-back and the access-roles map | read only |
| `pkg/fleet`, `pkg/boundary`, `pkg/alerting`, `pkg/cost`, `pkg/backend`, `pkg/dns`, `pkg/ssosync`, `pkg/awsconfig`, `pkg/awsprofile`, `pkg/bootstrap`, `pkg/appliance` | the estate-wide pieces an organization's root stacks are built from ([docs/reference.md](docs/reference.md)) |

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

**Components with stable names.** The engine is Pulumi
`ComponentResource`s whose child names are documented API. Adopting one
over existing infrastructure keeps URNs through no-parent aliases, proven
by an empty preview ([docs/adoption.md](docs/adoption.md)).

**The engine must not be able to do the worst thing.** Replacing an
account, an OU, a permission set or the organization destroys state that
lives outside the stack, and the follow-up diff reads clean. The preflight
refuses such plans, guards the break-glass way into every account, and keeps
service control policies off the management account's path without a
waiver; accounts, OUs and permission sets are also `protect`ed and retained
([docs/safety.md](docs/safety.md)).

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

## The command line

```sh
awsorgctl validate     -registry registry.yaml
pulumi preview --event-log preview.jsonl            # in your stack
awsorgctl preflight    -registry registry.yaml -events preview.jsonl
awsorgctl drift        -registry registry.yaml -profile <management profile> -sso-region <region>
awsorgctl access-roles -registry registry.yaml -profile <management profile> -accounts <name,name> -out access-roles.yaml
awsorgctl aws-ini      -registry registry.yaml -start-url <portal URL> -sso-region <region> -region <region>
```

Nothing it runs writes to AWS. `preflight` exits 1 on a refusal and
`drift -fail` on drift, so either can gate a pipeline.

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
- [docs/decisions/0003-bootstrap.md](docs/decisions/0003-bootstrap.md) — the cloud-init user-data composer (`pkg/bootstrap`).
- [docs/decisions/0004-appliance.md](docs/decisions/0004-appliance.md) — the EC2 appliance: group, launch template, role, hook, security group (`pkg/appliance`).
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
`Breaking:` bullet in the [CHANGELOG](CHANGELOG.md). Present: the registry,
the engine (the organization is looked up only; SCPs are dormant), the
preflight, drift and the access-roles map, the `aws.ini` renderer, ssosync
(Google Workspace to Identity Center groups) and `awsorgctl`. Next, each its
own decision: activating service control policies behind the preflight's
lockout guard, on a test OU first.

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

`policy/` is its own Go module, versioned by `policy/vX.Y.Z` tags. Such a
tag is not a `v*` tag and starts no workflow: the tag is the release, and
the CHANGELOG section of that name is its notes.

## Licence

MIT. See [LICENSE](LICENSE).
