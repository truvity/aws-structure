// Package trail deploys the audit trail of one AWS account as one Pulumi
// ComponentResource, truvity:aws-structure:AccountTrail.
//
// What it creates, for the account it is given:
//
//   - a KMS key with rotation enabled and an alias; the key policy lets the
//     account's administrators manage it and the CloudTrail service use it for
//     the trails the caller names;
//   - the trail bucket: S3 bucket, bucket policy (CloudTrail may read the ACL
//     and put objects, everything else must use HTTPS), public access block,
//     default encryption with the key, lifecycle (archive to Glacier after 90
//     days, expire after 365), versioning, access logging and cross-region
//     replication;
//   - the access-log bucket: ownership controls, public access block, AES256
//     encryption, an HTTPS-only policy and a 365 day expiry;
//   - the replica bucket, created with the replica provider: versioning,
//     AES256 encryption, public access block, an HTTPS-only policy and a
//     lifecycle (Glacier Instant Retrieval at once, expire after 365 days);
//   - the replication role with its policy and the replication
//     configuration;
//   - one multi-region trail with log file validation, global service events
//     and management events plus the S3 data events the caller selects.
//
// The caller supplies both AWS providers: the component never falls back to a
// default provider, which would silently create the audit trail in whichever
// account the stack's default provider points at.
//
// Nothing about an estate lives in this package. Bucket names, the key alias,
// the replication role's name and permissions boundary, the account root and
// trail ARNs the key policy names, and the S3 data-event resource are caller
// inputs, so the component never writes an ARN or an account id itself.
//
// The component is one per account, not one per organization: it creates a
// trail that logs its own account. An organization trail would be a different
// component.
//
// What the component refuses, before registering anything and all at once: a
// missing account name, provider or replica provider, a missing bucket name,
// key alias, key administrator, trail ARN, data-event resource, replication
// role name or permissions boundary, a key alias without the "alias/" prefix,
// and a naming hook that
// returns an empty or repeated name.
//
// No child is protected and none is retained on delete: that is what the
// resources this component was extracted from carried, and the component adds
// nothing to it.
//
// See docs/reference.md for the children, their names and their aliases.
package trail
