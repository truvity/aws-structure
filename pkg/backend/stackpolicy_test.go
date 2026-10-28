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
		KeyARN:         "arn:test:kms:eu-west-1:000000000001:key/k",
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
