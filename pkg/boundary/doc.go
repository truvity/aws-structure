// Package boundary builds the permissions boundary policy documents of an
// organization: the policies every account carries and every role is bounded
// by, from a small set of shapes.
//
// The shapes (see Names for what each is called by the caller):
//
//   - Admin: everything, except changing SSO and service-linked roles,
//     creating a role or user without one of its delegated boundaries,
//     editing or deleting any boundary, removing a boundary, and a short list
//     of destructive actions and the state buckets.
//   - Deploy: everything, but a created role needs "project" and "cluster"
//     tags and one of its delegated boundaries; boundaries cannot be edited.
//   - Default (and the deprecated Viewer, the same document): everything
//     except IAM writes. For service roles that need no IAM writes.
//   - Audit: the default plus a destructive-action and state-bucket deny.
//   - Project: only resources tagged or named for the principal's own project
//     (SSM, Secrets Manager, KMS, S3); no IAM at all.
//   - ACKIAM: an "IAM role factory": everything, but a role it creates must
//     carry one of its delegated boundaries.
//   - CAPA and EKSAutoNode: infrastructure provisioners; CAPA may pass roles
//     and create service-linked roles, EKS Auto Mode's roles are allow-all.
//
// Who may delegate to whom comes from the caller's hierarchy (Entry); the
// package adds nothing but the one special case that the admin boundary
// delegates to itself and to every boundary of a class by wildcard (the
// "tech" class, named by Spec.ClassPrefix).
//
// The package never writes a boundary name or an ARN partition of its own.
package boundary
