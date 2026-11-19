// Package orgtrail deploys an AWS organisation trail as one Pulumi
// ComponentResource, truvity:aws-structure:OrgTrail.
//
// The layout spans two accounts. The trail lives in the organisation's
// management account (the ManagementProvider); the log bucket and the KMS key
// that encrypts the logs live in a separate logs account (the LogsProvider),
// so the people who administer the management account cannot rewrite the
// evidence by being administrators of that account alone.
//
// In the logs account it creates:
//
//   - a KMS key with rotation enabled and an alias. The key policy names the
//     key administrators (kms:*), lets the CloudTrail service generate data
//     keys for the one trail and no other, lets it describe the key, and lets
//     the readers decrypt. It has NO statement for the account root: the
//     administrators are named principals, and the caller passes the role it
//     deploys with, so the creating principal stays in the policy and KMS's
//     lockout check passes;
//   - the log bucket, created with Object Lock enabled (a setting that can
//     only be made when the bucket is created, never later), with versioning
//     (Object Lock requires it), a default retention rule with the mode and
//     days the caller gives, a public access block, SSE-KMS default encryption
//     with the key (bucket keys on), ownership controls BucketOwnerEnforced
//     and a lifecycle (an optional transition to Glacier, expiry of current
//     versions at the retention period, noncurrent versions expiring after one
//     day and incomplete multipart uploads aborted after seven; the objects
//     stay locked until retention ends, the lifecycle only cleans up after);
//   - the bucket policy: CloudTrail may read the bucket ACL and put objects
//     under AWSLogs/<management account id>/ and AWSLogs/<organisation id>/,
//     in both cases only for the named trail; the readers may read; everything
//     must use TLS; and, under GOVERNANCE, only the named principals may
//     bypass the lock.
//
// In the management account it creates one trail: organisation-wide,
// multi-region, log file validation on, global service events on,
// management events only (read and write, no data events), delivering to the
// bucket and encrypting with the key.
//
// # Retention mode
//
// GOVERNANCE keeps the objects locked until retention ends, but a principal
// that holds s3:BypassGovernanceRetention can still delete them. The bucket
// policy denies that permission to everyone except the principals in
// BypassGovernancePrincipals, which is therefore required: somebody must be
// able to repair a mistake. COMPLIANCE can never be shortened or removed by
// anyone, the account root included, until the retention period of each object
// ends; choosing it is a decision about the cost and the legal position, not
// a default. The bypass list is ignored under COMPLIANCE.
//
// # Region and partition
//
// The component does not look them up. Args.Region and Args.Partition are the
// region and partition of the ManagementProvider; they are written into the
// trail ARN the two policies name, so they must agree with that provider (a
// trail created in another region than the policies name is refused by S3 and
// KMS). Partition empty means "aws".
//
// # What the component does not do
//
//   - The organisation must have trusted access enabled for the service
//     cloudtrail.amazonaws.com. Without it the trail is refused.
//   - The trail must be created from the management account (or from a
//     CloudTrail delegated administrator, which this component does not
//     support): ManagementProvider is that account.
//   - The reader roles must already exist. S3 and KMS refuse a policy that
//     names a principal that does not exist, so a reader created in the same
//     run as this component fails the run. A reader in another account also
//     needs its own identity policy allowing the same actions.
//   - The caller owns the bucket's global name and the key alias.
//
// What the component refuses, before registering anything and all at once: a
// missing account name, provider, account id, organisation id, trail name,
// bucket, region or key administrator; a malformed account id, organisation
// id, region, partition or trail name; a key alias without the "alias/"
// prefix; a retention period that is not positive; a retention mode other than
// GOVERNANCE or COMPLIANCE; a Glacier transition at or after the end of
// retention; an empty or malformed bypass list under GOVERNANCE; and a naming
// hook that returns an empty or repeated name.
//
// No child is protected and none is retained on delete. Object Lock, not
// Pulumi, protects the objects; destroying the stack does not remove locked
// objects and the bucket then cannot be deleted until they expire.
package orgtrail
