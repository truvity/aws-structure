// Package sso deploys IAM Identity Center access as two Pulumi components and
// two lookups:
//
//   - truvity:aws-structure:PermissionSet, one permission set with the
//     policies attached to it;
//   - truvity:aws-structure:AccountAssignments, the assignments that grant
//     principals permission sets on one target account;
//   - LookupGroupIDs and LookupPermissionSetARN, which read what this package
//     does not manage: groups filled by an external source (a directory sync)
//     and permission sets made by hand.
//
// The boundary is the unit that is created, kept and reviewed together. A
// permission set is the object AWS keeps users' sessions behind, so it, its
// managed policy attachments, its inline policy and its permissions boundary
// are one component: they are created in that order, they depend on the set,
// and they go away with it. An assignment is a fact about a target account
// (who may use which set there), and an account is what an assignment is
// reviewed against, so the assignments of one target account are one
// component. Neither component spans the instance: nothing in AWS makes the
// whole of Identity Center one unit, and a stack that manages only some sets
// or only some accounts must be able to say so.
//
// Groups are not a component. Groups that a directory sync fills are only
// looked up (LookupGroupIDs); creating a group the sync does not know of is
// not something this package does.
//
// The Identity Center instance ARN, every principal id, every account id,
// every permission set ARN and the AWS-managed policy ARNs are inputs. The
// package never writes an ARN or an account id itself, and it never falls
// back to a default provider: the caller supplies the provider of the region
// the Identity Center instance lives in.
//
// What the components refuse, before registering anything and all at once: a
// missing instance ARN or provider, an unnamed permission set, a malformed
// session duration, an empty or repeated managed policy ARN, an inline policy
// that is not JSON or is over AWS's limit, an assignment without a principal,
// permission set or either's reference, an unknown principal type, a repeated
// assignment, and a naming hook that returns an empty or repeated name.
//
// A permission set is protected and retained on delete: deleting one revokes
// the access of everyone assigned it, so neither Pulumi nor a removed line of
// code may do it silently. Nothing else is protected or retained.
//
// See docs/reference.md for the children, their names and their aliases.
package sso
