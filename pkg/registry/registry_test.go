package registry_test

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/truvity/aws-structure/pkg/registry"
)

// valid is a small, complete registry. Every identifier is a documentation
// placeholder: 111122223333 and 444455556666 are owned by no one.
const valid = `
organization:
  id: o-abcde12345
  root_id: r-ab12
  management_account: mgmt
ous:
  - name: platform
    reason: platform accounts
  - name: workloads
    parent: platform
    reason: workload accounts
accounts:
  - name: mgmt
    id: "111122223333"
    email: mgmt@example.test
    ou: platform
  - name: app
    id: "444455556666"
    email: app@example.test
    ou: workloads
scps:
  - name: deny-leave
    document: '{"Version":"2012-10-17","Statement":[]}'
identity_center:
  instance_arn: arn:aws:sso:::instance/ssoins-example
  identity_store_id: d-0000000000
  groups:
    - name: admins
  permission_sets:
    - name: base
      session_duration: PT8H
      managed_policies:
        - arn:aws:iam::aws:policy/ReadOnlyAccess
    - name: admin
      includes: [base]
  assignments:
    - principal: admins
      permission_set: admin
      ous: [workloads]
baseline:
  ebs_default_encryption: true
  regions: [eu-west-1]
  access_analyzer: true
  auditor_role:
    name: auditor
    trusted_account: mgmt
  password_policy:
    minimum_length: 14
`

func TestParseValid(t *testing.T) {
	r, err := registry.Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if r.SCPEnforcement != registry.SCPDormant {
		t.Errorf("enforcement defaulted to %q, want dormant", r.SCPEnforcement)
	}
	if got := r.IdentityCenter.Groups[0].Source; got != "manual" {
		t.Errorf("group source defaulted to %q", got)
	}
	if got := r.IdentityCenter.Assignments[0].PrincipalType; got != "group" {
		t.Errorf("principal type defaulted to %q", got)
	}
}

func TestLoadFromFS(t *testing.T) {
	fsys := fstest.MapFS{"registry.yaml": {Data: []byte(valid)}}
	if _, err := registry.Load(fsys, "registry.yaml"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Load(fsys, "missing.yaml"); err == nil {
		t.Fatal("a missing file loaded")
	}
}

func TestParseRefusesStructure(t *testing.T) {
	tests := []struct {
		name, doc, want string
	}{
		{"empty", "", "empty"},
		{"unknown top-level key", valid + "\nsurprise: 1\n", "surprise"},
		{"unknown nested key", strings.Replace(valid, "reason: platform accounts", "reason: x\n    colour: blue", 1), "colour"},
		{"two documents", valid + "\n---\n" + valid, "more than one"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := registry.Parse([]byte(tt.doc))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want an error mentioning %q", err, tt.want)
			}
		})
	}
}
