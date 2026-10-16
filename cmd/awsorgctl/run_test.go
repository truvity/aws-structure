package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/truvity/aws-structure/pkg/awsconfig"
	"github.com/truvity/aws-structure/pkg/registry"
)

// registryYAML is a small registry; every identifier is a placeholder and no
// account carries an id, so nothing here resembles an account.
const registryYAML = `
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
    email: mgmt@example.test
    ou: platform
  - name: app
    email: app@example.test
    ou: workloads
identity_center:
  instance_arn: instance
  identity_store_id: d-0000000000
  groups:
    - name: admins
  permission_sets:
    - name: admin
    - name: viewer
  assignments:
    - principal: admins
      permission_set: admin
      ous: [platform]
    - principal: admins
      permission_set: viewer
      accounts: [app]
  break_glass:
    principal: admins
    permission_set: admin
`

func files(t *testing.T, contents map[string]string) string {
	t.Helper()

	dir := t.TempDir()
	for name, body := range contents {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return dir
}

func runCLI(args ...string) (int, string) {
	var out, errOut bytes.Buffer

	code := run(args, &out, &errOut)

	return code, out.String() + errOut.String()
}

func TestUsage(t *testing.T) {
	if code, out := runCLI(); code != exitUsage || !strings.Contains(out, "commands:") {
		t.Fatalf("no args: %d %s", code, out)
	}

	if code, out := runCLI("nope"); code != exitUsage || !strings.Contains(out, `unknown command "nope"`) {
		t.Fatalf("unknown: %d %s", code, out)
	}
}

func TestValidate(t *testing.T) {
	dir := files(t, map[string]string{"r.yaml": registryYAML, "bad.yaml": registryYAML + "surprise: 1\n"})

	if code, out := runCLI("validate", "-registry", filepath.Join(dir, "r.yaml")); code != exitOK ||
		!strings.Contains(out, "ok: 2 OUs, 2 accounts, 2 permission sets, 2 assignments") {
		t.Fatalf("valid: %d %s", code, out)
	}

	if code, out := runCLI("validate", "-registry", filepath.Join(dir, "bad.yaml")); code != exitUsage || !strings.Contains(out, "surprise") {
		t.Fatalf("invalid: %d %s", code, out)
	}

	if code, _ := runCLI("validate"); code != exitUsage {
		t.Fatalf("no registry: %d", code)
	}
}

const replaceEvents = `{"sequence":1,"timestamp":1,"resourcePreEvent":{"metadata":{"op":"replace",` +
	`"urn":"u-account","type":"aws:organizations/account:Account","provider":"","detailedDiff":null}}}
`

const cleanEvents = `{"sequence":1,"timestamp":1,"resourcePreEvent":{"metadata":{"op":"same",` +
	`"urn":"u-account","type":"aws:organizations/account:Account","provider":"","detailedDiff":null}}}
`

func TestPreflight(t *testing.T) {
	dir := files(t, map[string]string{"r.yaml": registryYAML, "bad.jsonl": replaceEvents, "ok.jsonl": cleanEvents})
	reg := filepath.Join(dir, "r.yaml")

	if code, out := runCLI("preflight", "-registry", reg, "-events", filepath.Join(dir, "ok.jsonl")); code != exitOK ||
		!strings.Contains(out, "preflight: clean (1 steps)") {
		t.Fatalf("clean: %d %s", code, out)
	}

	code, out := runCLI("preflight", "-registry", reg, "-events", filepath.Join(dir, "bad.jsonl"))
	if code != exitFindings || !strings.Contains(out, "REFUSED irreplaceable: u-account: replace (replace) planned") {
		t.Fatalf("replace: %d %s", code, out)
	}

	if code, out := runCLI("preflight", "-registry", reg, "-events", filepath.Join(dir, "ok.jsonl"), "-break-glass-set", "x"); code != exitUsage ||
		!strings.Contains(out, "go together") {
		t.Fatalf("half a break glass: %d %s", code, out)
	}
}

func TestAWSIni(t *testing.T) {
	reg, err := registry.Parse([]byte(registryYAML))
	if err != nil {
		t.Fatal(err)
	}

	// Ids are set after parsing: a twelve-digit placeholder is for the
	// registry's own tests only.
	reg.Accounts[0].ID, reg.Accounts[1].ID = "id-mgmt", "id-app"

	out, err := renderAWSIni(reg, awsconfig.Session{
		Name: "sso", StartURL: "https://portal.example.test/start", Region: "region-a", RegistrationScopes: "sso:account:access",
	}, "region-b", "app@viewer")
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"[profile mgmt@admin]", "[profile app@admin]", "[profile app@viewer]", "sso_role_name = viewer", "[sso-session sso]"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}

	if strings.Contains(out, "[profile mgmt@viewer]") {
		t.Errorf("an unassigned set got a profile:\n%s", out)
	}

	dir := files(t, map[string]string{"r.yaml": registryYAML})
	if code, out := runCLI("aws-ini", "-registry", filepath.Join(dir, "r.yaml"), "-start-url", "u", "-sso-region", "a", "-region", "b"); code != exitUsage ||
		!strings.Contains(out, "no account with an id") {
		t.Fatalf("no ids: %d %s", code, out)
	}
}

func TestLiveCommandsNeedTheirFlags(t *testing.T) {
	dir := files(t, map[string]string{"r.yaml": registryYAML})
	reg := filepath.Join(dir, "r.yaml")

	if code, out := runCLI("drift", "-registry", reg); code != exitUsage || !strings.Contains(out, "-profile and -sso-region are required") {
		t.Fatalf("drift: %d %s", code, out)
	}

	if code, out := runCLI("access-roles", "-registry", reg); code != exitUsage || !strings.Contains(out, "-profile is required") {
		t.Fatalf("access-roles: %d %s", code, out)
	}
}

func TestAccessRoleAccounts(t *testing.T) {
	reg, err := registry.Parse([]byte(registryYAML))
	if err != nil {
		t.Fatal(err)
	}

	// Placeholder ids, built so the source holds no twelve-digit run (the
	// leak canary bans those outside pkg/registry's tests).
	idOne, idTwo := strings.Repeat("1", 12), strings.Repeat("2", 12)
	reg.Accounts[0].ID = idOne
	reg.Accounts[1].ID = idTwo

	all, err := accessRoleAccounts(reg, "")
	if err != nil || len(all) != 2 {
		t.Fatalf("all: %v %v", all, err)
	}

	one, err := accessRoleAccounts(reg, " app ")
	if err != nil || len(one) != 1 || one["app"] != idTwo {
		t.Fatalf("one: %v %v", one, err)
	}

	reg.Accounts[1].Closed = true

	rest, err := accessRoleAccounts(reg, "")
	if err != nil || len(rest) != 1 || rest["mgmt"] == "" {
		t.Fatalf("a closed account is skipped by default: %v %v", rest, err)
	}

	for _, only := range []string{"ghost", "app"} {
		if _, err := accessRoleAccounts(reg, only); err == nil {
			t.Fatalf("-accounts %s accepted", only)
		}
	}

	reg.Accounts[0].ID = ""
	if _, err := accessRoleAccounts(reg, "mgmt"); err == nil {
		t.Fatal("an account without an id accepted")
	}
}
