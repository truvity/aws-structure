# Contributing

Thanks for looking. This repository holds the schema of an AWS
organization's structure and, as they land, the Pulumi components,
preflight and tooling that apply it.

## Before you open a pull request

```sh
devbox shell
just check      # build, test, lint, leak-canary
```

`just check` is exactly what CI runs on a pull request. `just vuln` runs on
a schedule in its own workflow.

## What belongs here

Mechanism. A registry field is something every organization has; the value
is the caller's. If a value would differ in another organization (an
account id, an email, a region, a group name, a policy document), it is an
input and never a default. `hack/leak-canary.sh` catches the mechanical
cases; review catches the rest. Test fixtures use the documentation
placeholders and sit under `pkg/registry`, the one place the canary allows
them.

## Rules of the road

- Strict loading is the contract. A new field is added to the schema, its
  validation and `docs/reference.md` together; a field the loader would
  silently accept is a bug.
- A refusal is a decision. A new refusal, or the relaxing of one (for
  example attaching SCPs), gets a page under `docs/decisions/` and a
  CHANGELOG entry.
- A component's child names, once components exist, are API. Renaming one
  is a `Breaking:` entry and needs an alias.
- Tests never reach an AWS account. A test that needs one does not belong
  here.
- Commits are small and say why. The default branch is `master`; pull
  requests merge by rebase.

## Reporting a vulnerability

Privately, as described in [SECURITY.md](SECURITY.md). Not as an issue.
