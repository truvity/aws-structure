package backend_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/truvity/aws-structure/pkg/backend"
)

func scope() backend.StackScope {
	return backend.StackScope{
		Project:        "proj",
		Stack:          "stk",
		Bucket:         "state-bucket",
		KeyARN:         "arn:test:kms:eu-west-1:123456:key/k",
		Region:         "eu-west-1",
		SecretsContext: map[string]string{"purpose": "p", "org": "stk"},
		Partition:      "test",
	}
}

func TestStackPolicyStatements(t *testing.T) {
	st, err := backend.StackPolicyStatements(scope())
	if err != nil {
		t.Fatal(err)
	}

	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}

	got := string(raw)
	for _, want := range []string{
		`"Sid":"ReadAndWriteThisStacksState"`,
		`arn:test:s3:::state-bucket/.pulumi/stacks/proj/stk.json*`,
		`arn:test:s3:::state-bucket/.pulumi/stacks/proj/stk.pulumi-tags`,
		`arn:test:s3:::state-bucket/.pulumi/history/proj/stk/*`,
		`arn:test:s3:::state-bucket/.pulumi/backups/proj/stk/*`,
		`"Action":"s3:DeleteObject","Effect":"Allow","Resource":"arn:test:s3:::state-bucket/.pulumi/locks/organization/proj/stk/*"`,
		`arn:test:s3:::state-bucket/.pulumi/meta.yaml`,
		`"kms:ViaService":"s3.eu-west-1.amazonaws.com"`,
		`"StringEquals":{"kms:EncryptionContext:org":"stk","kms:EncryptionContext:purpose":"p"}`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in\n%s", want, got)
		}
	}

	if len(st) != 6 {
		t.Fatalf("%d statements, want 6", len(st))
	}
}

func TestStackPolicyDefaultPartitionAndRefusals(t *testing.T) {
	s := scope()
	s.Partition = ""

	if got := s.BucketARN(); got != "arn:"+"aws:s3:::state-bucket" {
		t.Fatalf("default partition: %s", got)
	}

	for name, mut := range map[string]func(*backend.StackScope){
		"project": func(s *backend.StackScope) { s.Project = "" },
		"stack":   func(s *backend.StackScope) { s.Stack = "" },
		"bucket":  func(s *backend.StackScope) { s.Bucket = "" },
		"key":     func(s *backend.StackScope) { s.KeyARN = "" },
		"region":  func(s *backend.StackScope) { s.Region = "" },
		"context": func(s *backend.StackScope) { s.SecretsContext = nil },
	} {
		c := scope()
		mut(&c)

		if _, err := backend.StackPolicyStatements(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A backend that lives under a path of the bucket (`s3://<bucket>/<prefix>`)
// keeps its `.pulumi/` there: every object the statements name is under the
// prefix, the bucket's own root backend is not reachable, and the bucket-level
// parts (the listing, the bucket-key context) still name the bucket.
func TestStackPolicyStatementsUnderAPrefix(t *testing.T) {
	s := scope()
	s.Prefix = "tenants/one"

	st, err := backend.StackPolicyStatements(s)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}

	got := string(raw)
	for _, want := range []string{
		`arn:test:s3:::state-bucket/tenants/one/.pulumi/stacks/proj/stk.json*`,
		`arn:test:s3:::state-bucket/tenants/one/.pulumi/stacks/proj/stk.pulumi-tags`,
		`arn:test:s3:::state-bucket/tenants/one/.pulumi/history/proj/stk/*`,
		`arn:test:s3:::state-bucket/tenants/one/.pulumi/backups/proj/stk/*`,
		`"Action":"s3:DeleteObject","Effect":"Allow","Resource":"arn:test:s3:::state-bucket/tenants/one/.pulumi/locks/organization/proj/stk/*"`,
		`"Action":"s3:GetObject","Effect":"Allow","Resource":"arn:test:s3:::state-bucket/tenants/one/.pulumi/meta.yaml"`,
		`"Action":"s3:ListBucket","Effect":"Allow","Resource":"arn:test:s3:::state-bucket"`,
		`"kms:EncryptionContext:aws:s3:arn":["arn:test:s3:::state-bucket","arn:test:s3:::state-bucket/tenants/one/.pulumi/`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in\n%s", want, got)
		}
	}

	if strings.Contains(got, `state-bucket/.pulumi/`) {
		t.Errorf("a statement names the bucket's root backend:\n%s", got)
	}

	if len(st) != 6 {
		t.Fatalf("%d statements, want 6", len(st))
	}

	// No prefix is the bucket's root, byte for byte what it was.
	root, err := backend.StackPolicyStatements(scope())
	if err != nil {
		t.Fatal(err)
	}

	rootRaw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}

	if want := strings.ReplaceAll(got, "state-bucket/tenants/one/", "state-bucket/"); string(rootRaw) != want {
		t.Errorf("the prefix changed more than the object paths:\n%s\n%s", rootRaw, want)
	}
}

// A prefix goes into object ARNs literally, so one that could widen them is
// refused.
func TestStackPolicyRefusesAPrefixThatIsNotAPlainPath(t *testing.T) {
	for _, prefix := range []string{"/tenants", "tenants/", "tenants//one", "tenants/../other", "./tenants", "tenants/*", "ten?nts"} {
		s := scope()
		s.Prefix = prefix

		if _, err := backend.StackPolicyStatements(s); err == nil {
			t.Errorf("prefix %q: accepted", prefix)
		}
	}
}
