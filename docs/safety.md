# Safety

The posture: the engine must not be able to do the worst thing by
accident. This page lists each guard, what it refuses, and whether it
exists yet. A guard that is only planned says so; nothing here claims a
check that is not in the code.

## Present: registry refusals (`pkg/registry`)

Run at load, before anything else sees the registry.

| Refusal | Why |
| --- | --- |
| Unknown key, second document, empty file | A key the loader ignores is a setting that silently did nothing |
| `organization.manage: true` | The organization is lookup-only in v1 (0001) |
| `scp_enforcement: enforced` | SCPs stay dormant until a lockout check exists (0002) |
| Duplicate names, ids or emails | Two entries for one thing means one of them is wrong |
| An account without an OU, or an unknown OU, SCP, group, permission set or account reference | A dangling reference is found now, not at apply |
| An OU parent cycle | The tree would have no root |
| An SCP over 5120 bytes or not a JSON object | AWS rejects it; better to be told at review |
| A permission-set include cycle | The effective policy would have no end |
| An OU without a `reason` | Every OU must say why it exists |

## Present: preflight (`pkg/preflight`)

Run over the plan of `pulumi preview` and the registry before every apply
(`preflight.Run`, or `Check` over a `--event-log` file). Every finding
refuses the whole deploy. See [reference.md](reference.md#pkgpreflight).

| Guard | Refuses | Why |
| --- | --- | --- |
| `irreplaceable` | a replace or a delete of an account, an OU, a permission set or the organization | their state is outside the stack: a replace destroys it and the next diff reads clean; a delete leaves it unmanaged (retained) without anyone deciding so |
| `break-glass` | a registry without `identity_center.break_glass`, an account it does not reach, and a plan that deletes or replaces a break-glass assignment | the last way back into an account must never be removed by a plan |
| `scp-on-management` | a policy on the root, the management account or an OU above it, in the registry or in a plan, without a waiver | a policy there can deny the actions needed to remove it |
| `waiver-expired` | an expired waiver, or one that has nothing left to waive | an exception must not outlive its cause |

`scp_enforcement: enforced` stays refused by the registry: the guard above
is the lockout check 0002 asks for, and activation is its own decision.

## Present defaults (engine)

- Accounts, OUs and permission sets are `protect`ed and retained on delete
  (not closed) by `pkg/engine/org` and `pkg/engine/sso`: `protect` is
  defence in depth behind the preflight, not a substitute for it.
- Policies are dormant. See [0002](decisions/0002-safety.md).

## What no guard covers

Reviewing what a policy document permits. The registry checks that it is
JSON and within AWS's size limits, not that it is wise.
