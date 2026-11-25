# 0005 — Hosted zones: the admin boundary may delete one, and `protect` guards them

**Status:** Accepted

## Context

The admin boundary denied `route53:DeleteHostedZone` with the other
destructive actions. Route 53 offers no condition key on that action and on
the `hostedzone` resource: no tag, and nothing that tells a private zone from
a public one. So the deny could not be narrowed. It refused accidents, and it
also refused every planned replacement of a zone: a zone's name forces a new
zone, so renaming even an empty private zone could not be applied. The only
ways round it were editing the state by hand and deleting the zone outside
the tool.

## Decision

1. **The admin boundary no longer denies `route53:DeleteHostedZone`**, in
   every variant (`OrgAdminOff`, `OrgAdminMember`, `OrgAdminManagement`) and
   under both names (`Names.Admin`, `Names.RoleAdmin`). The rest of its
   destructive list stays.
2. **The audit boundary keeps the deny.** It allows everything else, and an
   auditor has no reason to delete a zone.
3. **Every hosted zone `pkg/dns` makes or imports is `protect`ed.** A delete
   or a replacement of one fails until a person unprotects it
   (`pulumi state unprotect`), which is a deliberate act in the stack it
   belongs to.

## Consequences

- A zone a caller makes outside `pkg/dns` is not covered: the caller protects
  it itself, or decides that it may be replaced.
- Delete a public zone only after its NS delegation at the registrar or in the
  parent zone is gone. A delegation left pointing at a deleted zone's name
  servers can be taken over by anyone who creates a zone of the same name on
  those servers.
- The admin boundary's policy documents change, so attach the new versions.
  An existing zone made by `pkg/dns` becomes protected on its stack's next
  update; nothing is created, changed or deleted.
