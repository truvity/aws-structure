// Package org deploys the organizational structure of an AWS Organization:
// organizational units and the member accounts that sit in them, as one Pulumi
// ComponentResource per unit, truvity:aws-structure:OrganizationalUnit. It also
// renders the service control policy documents, which it never attaches.
//
// What a unit component creates:
//
//   - the organizational unit, under the parent id the caller gives (the
//     organization root, or another unit's id);
//   - one member account per entry the caller lists for the unit, placed in
//     the unit and depending on it.
//
// The boundary is the OU, because an account is created inside exactly one OU
// and takes the OU's id as its parent: the unit and its members are created in
// that order, an OU holds the accounts beneath it, and a stack that manages
// only some OUs must be able to say so. An account is not its own component
// because nothing about it is reviewed apart from the unit it sits in.
//
// The organization itself is never managed. LookupRootID reads it and returns
// the id of its root, the parent of a top-level unit; there is no component
// and no resource for the organization, and none is planned until the legacy
// owner of the organization is gone.
//
// Every unit and every account is protected and retained on delete: an
// account holds what runs in it and an OU holds the accounts beneath it, so
// neither Pulumi nor a removed line of code may delete one silently. Nothing
// else is protected or retained.
//
// SCPs are dormant. SCPs builds the policy documents as typed values and
// checks each is valid JSON within AWS's 5120-byte limit, so that a document
// is correct before it is ever attached. No component creates a policy or an
// attachment, and a unit or account that asks for SCPs is refused rather than
// ignored.
//
// Nothing about an estate lives in this package. Unit names, account names and
// emails, the parent id, the AWS partition, the management account's id, the
// allowed regions and the bucket patterns the policies exempt are caller
// inputs, and the package never writes an ARN or an account id itself. It
// never falls back to a default provider.
//
// What the component refuses, before registering anything and all at once: an
// unnamed unit, a missing parent id or provider, an account without a name or
// an email, a repeated account name, an account placed in another unit, a unit
// or account that carries an id (adoption by import is not built) or SCPs, and
// a naming hook that returns an empty or repeated name. SCPs refuses a
// malformed partition or account id, no regions, a repeated region, a missing
// bucket pattern and a document over the limit.
//
// See docs/reference.md for the children, their names and their aliases.
package org
