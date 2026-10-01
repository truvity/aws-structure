package registry_test

import (
	"strings"
	"testing"

	"github.com/truvity/aws-structure/pkg/registry"
)

// mutate parses valid after one textual replacement and returns the error.
func mutate(t *testing.T, old, repl string) error {
	t.Helper()
	if !strings.Contains(valid, old) {
		t.Fatalf("test bug: %q not in the fixture", old)
	}
	_, err := registry.Parse([]byte(strings.Replace(valid, old, repl, 1)))
	return err
}

func TestValidateRefusals(t *testing.T) {
	bigSCP := `'{"Version":"2012-10-17","Pad":"` + strings.Repeat("x", registry.MaxSCPBytes) + `"}'`
	tests := []struct {
		name, old, new, want string
	}{
		{"organization managed", "management_account: mgmt", "management_account: mgmt\n  manage: true", "lookup-only"},
		{"bad organization id", "o-abcde12345", "org-1", "organization id"},
		{"unknown management account", "management_account: mgmt", "management_account: ghost", "not a declared account"},
		{"duplicate ou", "  - name: workloads\n    parent: platform", "  - name: platform\n    parent: platform", "duplicate ou"},
		{"ou without reason", "    reason: workload accounts", "", "no reason"},
		{"ou unknown parent", "parent: platform", "parent: ghost", "not a declared OU"},
		{"ou parent cycle", "  - name: platform\n    reason", "  - name: platform\n    parent: workloads\n    reason", "cycle"},
		{"account without ou", "    ou: workloads", "", "no ou"},
		{"account unknown ou", "ou: workloads", "ou: ghost", "not a declared OU"},
		{"duplicate account", "  - name: app", "  - name: mgmt", "duplicate account"},
		{"duplicate account id", `id: "444455556666"`, `id: "111122223333"`, "share id"},
		{"short account id", `id: "444455556666"`, `id: "4444"`, "not 12 digits"},
		{"bad email", "app@example.test", "not-an-address", "not an address"},
		{"scp enforced", "scps:\n  - name: deny-leave", "scp_enforcement: enforced\nscps:\n  - name: deny-leave", "stay dormant"},
		{"scp enforcement unknown", "scps:\n  - name: deny-leave", "scp_enforcement: maybe\nscps:\n  - name: deny-leave", "not \"dormant\""},
		{"scp invalid json", `'{"Version":"2012-10-17","Statement":[]}'`, `'{nope'`, "not a JSON object"},
		{"scp over 5120 bytes", `'{"Version":"2012-10-17","Statement":[]}'`, bigSCP, "over the 5120-byte limit"},
		{"scp duplicate", "scps:\n  - name: deny-leave", "scps:\n  - name: deny-leave\n    document: '{}'\n  - name: deny-leave", "duplicate scp"},
		{"ou attaches unknown scp", "    reason: platform accounts", "    reason: x\n    scps: [ghost]", "unknown scp"},
		{"unknown include", "includes: [base]", "includes: [ghost]", "unknown permission set"},
		{"bad session duration", "PT8H", "8 hours", "ISO-8601"},
		{"assignment unknown group", "principal: admins", "principal: ghost", "group \"ghost\" is not declared"},
		{"assignment unknown permission set", "permission_set: admin", "permission_set: ghost", "permission set \"ghost\" is not declared"},
		{"assignment without targets", "      ous: [workloads]", "      principal_type: group", "no accounts and no ous"},
		{"assignment unknown ou", "ous: [workloads]", "ous: [ghost]", "ou \"ghost\" is not declared"},
		{"ebs encryption without regions", "regions: [eu-west-1]", "regions: []", "regions are the caller's"},
		{"password too short", "minimum_length: 14", "minimum_length: 3", "outside 8..128"},
		{"auditor trusts unknown account", "trusted_account: mgmt", "trusted_account: ghost", "not a declared account"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mutate(t, tt.old, tt.new)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want an error mentioning %q", err, tt.want)
			}
		})
	}
}

func TestPermissionSetCycle(t *testing.T) {
	// admin includes base; base includes admin.
	doc := strings.Replace(valid, "    - name: base\n      session_duration: PT8H",
		"    - name: base\n      includes: [admin]\n      session_duration: PT8H", 1)
	_, err := registry.Parse([]byte(doc))
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("got %v, want a cycle error", err)
	}
	// Both members of the cycle are named, not just the first found.
	for _, n := range []string{`"base"`, `"admin"`} {
		if !strings.Contains(err.Error(), n) {
			t.Errorf("cycle error does not name %s: %v", n, err)
		}
	}
}

func TestPermissionSetSelfInclude(t *testing.T) {
	doc := strings.Replace(valid, "includes: [base]", "includes: [admin]", 1)
	if _, err := registry.Parse([]byte(doc)); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("got %v, want a cycle error", err)
	}
}

func TestValidateReportsEverythingAtOnce(t *testing.T) {
	doc := strings.NewReplacer(
		"o-abcde12345", "nope",
		"ou: workloads", "ou: ghost",
		"minimum_length: 14", "minimum_length: 3",
	).Replace(valid)
	_, err := registry.Parse([]byte(doc))
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"organization id", "not a declared OU", "outside 8..128"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
}

func TestDiamondIncludeIsNotACycle(t *testing.T) {
	doc := strings.Replace(valid, "    - name: admin\n      includes: [base]",
		"    - name: left\n      includes: [base]\n    - name: right\n      includes: [base]\n    - name: admin\n      includes: [left, right]", 1)
	if _, err := registry.Parse([]byte(doc)); err != nil {
		t.Fatalf("a diamond is not a cycle: %v", err)
	}
}
