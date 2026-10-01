// Package iam deploys the IAM controls of one AWS account as one Pulumi
// ComponentResource, truvity:aws-structure:AccountIAM.
//
// What it creates:
//
//   - Args.PasswordPolicy: the account password policy
//     (iam.AccountPasswordPolicy), users may change their own password.
//   - Args.Boundaries: one customer-managed policy per boundary
//     (iam.Policy), named and documented by the caller.
//   - Args.AuditorRole: a read-only role a trusted principal assumes: the role
//     (iam.Role) with a trust policy naming the principal and, optionally, an
//     external id; one iam.RolePolicyAttachment per AWS-managed policy; and,
//     when the caller supplies one, a customer-managed policy and its
//     attachment.
//
// Each part is optional; the component creates only what the args name.
//
// The caller supplies the AWS provider of the account: the component never
// falls back to a default provider, because a default would silently create
// the account's controls in whichever account the stack's default provider
// points at. Boundaries may be created under a different provider instance
// than the rest (Args.BoundaryProvider), for stacks that already created them
// that way.
//
// The component holds no policy documents and no ARNs of its own. Boundary
// documents, the trusted principal, the external id, the managed-policy ARNs
// and the role's permissions boundary are all caller inputs, so nothing about
// an estate lives in this package.
//
// What the component refuses, before registering anything and all at once: a
// missing account name or provider, a password policy outside the ranges AWS
// accepts, a boundary without a name or with a document that is not JSON, a
// repeated boundary name, an auditor role without a name, a trusted principal
// or a permissions boundary, an auditor policy without a name or a JSON
// document, and a naming hook that returns an empty or repeated name.
//
// No child is protected: re-creating one of these is harmless to the account
// beyond the moment it is missing.
//
// See docs/reference.md for the children, their names and their aliases.
package iam
