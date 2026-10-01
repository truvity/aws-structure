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

## Planned: preflight (`pkg/preflight`)

Run over `pulumi preview` before every apply; not present yet.

- **No replace of an irreplaceable type.** Accounts, OUs, permission sets
  and the organization. A replace op (`replace`, `create-replacement`,
  `delete-replaced`) on any of them refuses the whole deploy.
- **Lockout guard.** A plan that would remove the last assignment giving
  anyone administrative access to the management account, or detach the
  only way back into an account, is refused.

## Planned defaults (engine)

- Accounts, OUs and permission sets are `protect`ed and accounts are
  retained on delete (not closed): `protect` is defence in depth behind the
  preflight, not a substitute for it.
- Policies are dormant. See [0002](decisions/0002-safety.md).

## What no guard covers

Reviewing what a policy document permits. The registry checks that it is
JSON and within AWS's size limits, not that it is wise.
