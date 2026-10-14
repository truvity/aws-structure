// Package preflight is the guard that runs before an apply of an
// organization's structure: a read-only judgement over the registry and the
// plan of a `pulumi preview`, refusing the plans that destroy what cannot be
// rebuilt or lock everyone out.
//
// Two guards, each a pure function so it can be tested and run anywhere:
//
//   - Plan judges the steps of a preview (from an automation-API event
//     stream, or from the file `pulumi preview --event-log <file>` writes):
//     a replace or delete of an account, an organizational unit, a permission
//     set or the organization is refused; so is a delete or replace of the
//     break-glass account assignment, and a policy attachment on the
//     organization root, the management account or an OU above it without a
//     waiver.
//   - Lockout judges the registry: the break-glass assignment must be declared
//     and reach every account; no service control policy may sit on the
//     management account or an OU above it without a waiver; an expired
//     waiver is refused, not ignored.
//
// Run wires both to an automation-API stack: it previews, collects the
// steps and returns every finding. Wire it as a hard dependency of the
// deploy command. `protect` and `retainOnDelete` on the same resources are
// defence in depth behind this guard, not a substitute for it.
//
// See docs/safety.md for each guard and why it exists.
package preflight
