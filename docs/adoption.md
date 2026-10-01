# Adoption

## Today: validate a registry

```sh
go get github.com/truvity/aws-structure
```

`pkg/registry` has no cloud dependency. Write the registry in your private
estate, load it with `registry.Load` (or `Parse`) in a test, and let CI hold
it to the schema. Record ids (`id:` on OUs and accounts) as you adopt, so
the engine, when it lands, imports rather than creates.

## Adopting an existing organization (when the engine lands)

Import-first, one step at a time, and never all at once.

1. **Describe what exists.** Fill the registry from the live organization:
   OUs and accounts with their ids, Identity Center groups, permission sets
   and assignments. The organization block is looked up, never managed.
2. **Preview.** The preview must be empty: no create, no delete, no
   replace, no update. Anything else means a name, an id or an input is
   wrong; fix that, never apply "just to see".
3. **Preflight.** The plan goes through `pkg/preflight` before the apply.
4. **Apply, then refresh-preview.** The apply only brings state in line. A
   refresh-preview afterwards must still plan nothing.

Components keep resource URNs through no-parent aliases (`LegacyTopLevel`),
as in [k8s](https://github.com/truvity/k8s); see
[0001](decisions/0001-shape.md).

## Upgrading

Breaking changes are `Breaking:` bullets in the [CHANGELOG](../CHANGELOG.md)
and, for a renamed child, come with the alias that keeps the old URN. Pin an
exact version and read the bullets between the old pin and the new.
