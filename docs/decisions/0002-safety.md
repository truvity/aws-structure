# 0002 — Safety: irreplaceable types, a lockout guard, protect and retain, dormant SCPs

**Status:** Accepted

## Context

Several resources here hold state that is not in the Pulumi stack: an
account holds what runs in it, an OU holds the accounts under it, a
permission set holds its assignments, the organization holds everything.
Pulumi plans a replace of any of them without complaint, and the diff after
it reads clean. A service control policy can additionally deny the actions
needed to remove it.

## Decision

1. **Irreplaceable types.** Accounts, OUs, permission sets and the
   organization are never replaced. The preflight refuses a plan with a
   replace-shaped operation on any of them. A human who truly means it can
   act outside the tool; never by accident.
2. **A lockout guard.** The preflight refuses a plan that would remove the
   last administrative path into the management account, or the only way
   back into an account.
3. **Protect and retain by default.** Those types are `protect`ed, and an
   account removed from the registry is retained, not closed. `protect`
   stops deletes, not replaces; it is defence in depth behind point 1.
4. **SCPs are dormant.** They are declared and validated, never attached.
   `scp_enforcement: enforced` is refused until a lockout check exists that
   proves a change cannot cut off the principal that would repair it. That
   check is its own decision, with its own page, when it is built.

## Consequences

- Points 1 and 2 are not present yet; the registry refusals (including
  point 4) are. [safety.md](../safety.md) says which is which.
- Removing an account from the registry leaves a real account behind until
  a person closes it: deliberate, and cheaper than the alternative.
