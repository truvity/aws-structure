# Changelog

Entries of the Go module `github.com/truvity/aws-structure/policy`, written
for someone deciding whether to bump. The module is versioned by its own
tags, `policy/vX.Y.Z`; a heading here is the version without the `policy/`
prefix. The repository's CHANGELOG.md holds the releases of the root module.

## v0.1.0

- **`github.com/truvity/aws-structure/policy`: a typed IAM policy document, a new Go module.** Standard library only, versioned by its own `policy/vX.Y.Z` tags. A component that needs a permissions boundary returns a `policy.Document`; the system that creates the boundaries appends its own statements, checks the size and marshals.
  - **Types:** `Document{Version, Statement}`, `Statement{Sid, Effect, Action, NotAction, Resource, NotResource, Condition, Arrays}`, `Effect` (`Allow`, `Deny`) and `Condition{Operator, Key, Values, Array}`. No `Principal`: a boundary has none, and the reader refuses a document that carries one rather than drop it.
  - **Canonical JSON:** `MarshalJSON` writes the minified document in one fixed form. `Version` defaults to `2012-10-17`, the statement fields come in IAM's order, a list of one value is a bare string, and conditions are grouped by operator, then key, in byte order. `Statement.Arrays` and `Condition.Array` keep a one-value list an array, for a document that already exists in an account and must not change by a byte; `UnmarshalJSON` sets them where it reads a one-element array, so a document read and written again is byte-identical (the tests round-trip the goldens of `pkg/boundary`).
  - **`Size()`** is the minified length, the number IAM's 6,144-character limit counts.
  - **`Validate()`** reports every problem at once: Effect, a unique Sid of ASCII letters and digits, one of Action and NotAction and one of Resource and NotResource, no empty string, a complete condition, no condition twice.
  - New module, additive. `pkg/boundary` is moved onto it in a later release.
