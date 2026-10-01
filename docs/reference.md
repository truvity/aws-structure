# Reference

`pkg/registry`. Every key below is strict: an unknown key anywhere is an
error. Types are in `pkg/registry/types.go`; refusals in
`pkg/registry/validate.go`.

## Loading

- `registry.Parse(data []byte) (*Registry, error)` — parse and validate.
- `registry.Load(fsys fs.FS, name string) (*Registry, error)` — read a file
  (typically from an `embed.FS`), then `Parse`.
- `(*Registry).Validate() error` — every problem, joined.

## The file

| Key | Meaning |
| --- | --- |
| `organization` | `id` (`o-...`), `root_id` (`r-...`), `management_account` (an account name). `manage: true` is refused in v1 |
| `ous[]` | `name`, `parent` (empty is the root), `id` (adopted OU), `scps[]`, `reason` (required) |
| `accounts[]` | `name`, `id` (12 digits, once it exists), `email`, `ou` (required), `scps[]`, `tags`, `baseline_exempt` (a reason) |
| `scp_enforcement` | `dormant` (default); `enforced` is refused in v1 |
| `scps[]` | `name`, `description`, `document` (JSON, at most 5120 bytes) |
| `identity_center` | `instance_arn`, `identity_store_id`, `groups[]`, `permission_sets[]`, `assignments[]` |
| `identity_center.groups[]` | `name`, `source` (`manual` default, or `sync` for an externally filled group) |
| `identity_center.permission_sets[]` | `name`, `description`, `session_duration` (`PT8H`), `managed_policies[]`, `inline_policy` (JSON, at most 10240 bytes), `includes[]` (no cycles) |
| `identity_center.assignments[]` | `principal`, `principal_type` (`group` default, or `user`), `permission_set`, `accounts[]` and/or `ous[]` (at least one) |
| `baseline` | `password_policy`, `ebs_default_encryption` (needs `regions`), `regions[]`, `access_analyzer`, `auditor_role` (`name`, `trusted_account`), `boundaries[]` (`name`, `document`) |

See [safety.md](safety.md) for what each refusal protects against.
