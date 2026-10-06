// Package backend deploys the storage a Pulumi state backend lives in: one S3
// bucket per account with its own KMS key, and an optional cross-region
// replica of it.
//
// What NewBucket creates, for the account of the provider it is given:
//
//   - a KMS key with rotation on, and an alias for it;
//   - the S3 bucket, with versioning, SSE-KMS (bucket key on), the four public
//     access blocks and a policy that refuses requests without TLS;
//   - a lifecycle rule that expires noncurrent versions after 30 days.
//
// What NewReplication adds, in the same account and a second region:
//
//   - a provider for that region (same profile, optionally an assumed role);
//   - a KMS key and alias, and a replica bucket with the same baseline;
//   - the role S3 assumes to replicate, with a permissions boundary, and its
//     inline policy;
//   - the replication configuration on the source bucket.
//
// Every logical name is "pulumi-state-<account>/<child>" (replica:
// "pulumi-state-<account>-replica/<child>"), so several buckets can live in one
// stack. Those names are API: a stack that already holds the buckets adopts
// this package with an empty preview. The buckets are not protected here;
// that is the caller's choice (a ResourceOption hook is not offered because
// the existing stacks carry none).
//
// The package never writes an account id, a bucket name or a profile of its
// own: the bucket name, the key alias, the regions, the replica bucket name and
// the name of the permissions boundary all come from the caller.
package backend
