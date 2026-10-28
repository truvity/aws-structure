package backend

import (
	"errors"
	"fmt"
	"sort"
)

// StackScope names ONE stack of a DIY (S3) Pulumi backend and the state key
// that protects it, for StackPolicyStatements.
type StackScope struct {
	// Project and Stack are the Pulumi project and stack name. Required.
	Project string
	Stack   string
	// Bucket is the state bucket's name (see BucketName). Required.
	Bucket string
	// KeyARN is the ARN of the KMS key the bucket encrypts with and the stack's
	// secrets provider uses. Required.
	KeyARN string
	// Region is the bucket's region; it feeds kms:ViaService. Required.
	Region string
	// SecretsContext are the KMS encryption-context pairs the stack's secrets
	// provider URL sends (`context_<key>=<value>`). The secrets statement
	// allows Encrypt and Decrypt only when every pair matches. Required: a
	// key shared by several stacks must tell their secrets apart.
	SecretsContext map[string]string
	// Partition is the AWS partition of the ARNs built here. Empty: "aws".
	Partition string
}

const (
	stackS3GetObject    = "s3:GetObject"
	stackS3PutObject    = "s3:PutObject"
	stackS3DeleteObject = "s3:DeleteObject"
	stackS3ListBucket   = "s3:ListBucket"

	stackKMSDecrypt         = "kms:Decrypt"
	stackKMSEncrypt         = "kms:Encrypt"
	stackKMSGenerateDataKey = "kms:GenerateDataKey"

	stackCondViaService = "kms:ViaService"
	stackCondS3ARN      = "kms:EncryptionContext:aws:s3:arn"
	stackCondContext    = "kms:EncryptionContext:"
)

// Validate refuses a scope with a missing field.
func (s StackScope) Validate() error {
	switch {
	case s.Project == "":
		return errors.New("stack scope: Project is required")
	case s.Stack == "":
		return errors.New("stack scope: Stack is required")
	case s.Bucket == "":
		return errors.New("stack scope: Bucket is required")
	case s.KeyARN == "":
		return errors.New("stack scope: KeyARN is required")
	case s.Region == "":
		return errors.New("stack scope: Region is required")
	case len(s.SecretsContext) == 0:
		return errors.New("stack scope: SecretsContext is required (a shared key must tell stacks apart)")
	}

	return nil
}

// StackObjects are the state objects of the stack in the DIY backend's project
// layout (pulumi pkg/backend/diy), relative to the bucket: the stack file and
// its backup (`<stack>.json`, `.json.bak`, `.json.gz`, `.json.zst`), its tags
// file, its history, its backups and its locks (which the backend keys by the
// stack's fully qualified name, `organization/<project>/<stack>`).
func (s StackScope) StackObjects() []string {
	p, st := s.Project, s.Stack

	return []string{
		".pulumi/stacks/" + p + "/" + st + ".json*",
		".pulumi/stacks/" + p + "/" + st + ".pulumi-tags",
		".pulumi/history/" + p + "/" + st + "/*",
		".pulumi/backups/" + p + "/" + st + "/*",
		s.LockObjects(),
	}
}

// LockObjects is where the backend writes the stack's locks, relative to the
// bucket.
func (s StackScope) LockObjects() string {
	return ".pulumi/locks/organization/" + s.Project + "/" + s.Stack + "/*"
}

// BucketARN is the state bucket's ARN.
func (s StackScope) BucketARN() string { return s.arn() + "s3:::" + s.Bucket }

func (s StackScope) arn() string {
	partition := s.Partition
	if partition == "" {
		partition = "aws"
	}

	return "arn:" + partition + ":"
}

// StackPolicyStatements are the IAM policy statements that confine a role to
// ONE stack of a DIY S3 Pulumi backend: read and write that stack's objects,
// release its locks (the one object a run deletes), read the backend's
// meta.yaml, list the bucket, use the state key through S3 for those objects
// only, and use the key directly for the stack's secrets under SecretsContext
// only. Nothing else: no other stack, no IAM.
//
// The statements are plain maps, in a fixed order, ready to be put under a
// policy document's Statement (with Version 2012-10-17); the caller adds its
// own statements and marshals. Their Sids are ReadAndWriteThisStacksState,
// ReleaseThisStacksLocks, ReadTheBackendsMeta, ListTheStateBucket,
// StateKeyThroughS3ForThisStacksObjects and StateKeyForThisStacksSecrets.
//
// ListBucket is unconditioned, deliberately: S3 answers a read of a MISSING
// object with 404 only to a caller that may list the bucket, and with 403 to
// everyone else. The backend reads objects that may not exist (the stack's
// .pulumi-tags file) and treats anything but NotFound as fatal, so a listing
// narrowed by s3:prefix fails every run of a stack with no tags. A listing
// shows object names (other stacks' among them) and no content.
func StackPolicyStatements(s StackScope) ([]map[string]any, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}

	bucketARN := s.BucketARN()

	objects := s.StackObjects()
	objectARNs := make([]string, 0, len(objects))

	for _, o := range objects {
		objectARNs = append(objectARNs, bucketARN+"/"+o)
	}

	// S3 puts the bucket's ARN in the encryption context with a bucket key
	// (the state buckets have one, see NewBucket), and the object's without:
	// both are named, the objects only this stack's.
	s3Context := append([]string{bucketARN}, objectARNs...)

	secrets := make(map[string]any, len(s.SecretsContext))
	for _, k := range sortedKeys(s.SecretsContext) {
		secrets[stackCondContext+k] = s.SecretsContext[k]
	}

	return []map[string]any{
		{
			"Sid":      "ReadAndWriteThisStacksState",
			"Effect":   "Allow",
			"Action":   []string{stackS3GetObject, stackS3PutObject},
			"Resource": objectARNs,
		},
		{
			// A lock is the one object the backend deletes in a run
			// (Unlock); removing the stack itself is not this role's.
			"Sid":      "ReleaseThisStacksLocks",
			"Effect":   "Allow",
			"Action":   stackS3DeleteObject,
			"Resource": bucketARN + "/" + s.LockObjects(),
		},
		{
			// The backend's version marker, read on every login.
			"Sid":      "ReadTheBackendsMeta",
			"Effect":   "Allow",
			"Action":   stackS3GetObject,
			"Resource": bucketARN + "/.pulumi/meta.yaml",
		},
		{
			"Sid":      "ListTheStateBucket",
			"Effect":   "Allow",
			"Action":   stackS3ListBucket,
			"Resource": bucketARN,
		},
		{
			"Sid":      "StateKeyThroughS3ForThisStacksObjects",
			"Effect":   "Allow",
			"Action":   []string{stackKMSDecrypt, stackKMSGenerateDataKey},
			"Resource": s.KeyARN,
			"Condition": map[string]any{
				"StringEquals": map[string]any{stackCondViaService: fmt.Sprintf("s3.%s.amazonaws.com", s.Region)},
				"StringLike":   map[string]any{stackCondS3ARN: s3Context},
			},
		},
		{
			// The stack's secrets provider (gocloud awskms: Encrypt and
			// Decrypt of the stack's data key, with the URL's context). A
			// stack that sends another context does not decrypt.
			"Sid":       "StateKeyForThisStacksSecrets",
			"Effect":    "Allow",
			"Action":    []string{stackKMSEncrypt, stackKMSDecrypt},
			"Resource":  s.KeyARN,
			"Condition": map[string]any{"StringEquals": secrets},
		},
	}, nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}

	sort.Strings(out)

	return out
}
