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
// A second generation of shapes, named by the role, controller and project
// fields of Names, replaces them; both may be rendered together while an
// organization moves its roles over:
//
//   - RoleAdmin, RoleDeployer, RoleAuditor: the three human boundaries. The
//     admin and audit documents are the old ones; the admin delegates each
//     boundary by its exact name, never by a wildcard, and the deployer must
//     name its roles "<cluster>-<project>.*" from its own tags.
//   - ACKControllerIAM, -EKS, -S3, -KMS, -DynamoDB: one allowlist per ACK
//     controller, sized to the platform's own resources (Spec.ACK). For a
//     project the controller assumes the project's builder and acts as it.
//   - ProjectACK and EmployeeACK: the boundary of a builder role. One
//     document for every account and project, keyed on the builder's own
//     "project" and "cluster" role tags; it may create only roles named for its
//     project under the one delegated boundary, may not change or remove
//     those two tags, and has no access to data.
//   - ProjectWorkload: the boundary of the roles a builder creates for pods:
//     data actions on the project's own keys, buckets and repositories, and
//     no IAM. The delegation chain ends here.
//
// Grun, named by Names.Grun and optional beside both generations, is the
// boundary of the roles the self-hosted runners stack (cdk-github-runners)
// creates: everything except IAM writes, with two exceptions, passing the
// stack's own roles (Spec.Grun.RolePrefix) to the listed services and creating
// the listed service-linked roles. It cannot create a role or a user.
//
// Extra boundaries, passed in Spec.Extra, are declared by a component as a
// typed policy.Document (github.com/truvity/aws-structure/policy): a name, the
// component's statements, who delegates it and what it delegates. The package
// appends the estate's guards (no edit of a boundary policy, no removal of a
// boundary, and no role creation outside its exact delegates, or none at all for a
// leaf), adds the name to its delegators' lists, and refuses a document over
// IAM's 6,144 characters. Names.Grun and Spec.Grun are deprecated in favour of
// an Extra.
//
// Spec.LegacyProjectNames renders the transition form of ProjectACK,
// ProjectWorkload and RoleDeployer, which also accepts the names projects used
// before the "<cluster>-<project>.<name>" rule.
//
// Spec.OrgAdmin (OrgAdminMode) selects, opt-in, a variant of the admin
// boundary for an organization that uses one admin permission set everywhere:
// OrgAdminManagement for the management account, OrgAdminMember for every
// member account. The zero value changes nothing. See OrgAdminMode.
//
// Who may delegate to whom comes from the caller's hierarchy (Entry); the
// package adds only the special cases that the admin boundaries delegate to
// themselves, and that the old admin boundary (Names.Admin) delegates to
// every boundary of a class by wildcard (the "tech" class, named by
// Spec.ClassPrefix). RoleAdmin has no wildcard.
//
// The package never writes a boundary name, an ARN partition, an account, a
// bucket or a platform role of its own: they are inputs of the Spec.
package boundary
