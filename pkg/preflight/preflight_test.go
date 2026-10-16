package preflight_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/truvity/aws-structure/pkg/preflight"
	"github.com/truvity/aws-structure/pkg/registry"
)

var now = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

// reg is a small registry: root -> platform (mgmt) -> workloads (app, data).
// The ids are placeholders, never real shapes.
func reg() *registry.Registry {
	return &registry.Registry{
		Organization: registry.Organization{ID: "o-example", RootID: "r-root", ManagementAccount: "mgmt"},
		OUs: []registry.OU{
			{Name: "platform", ID: "ou-platform", Reason: "x"},
			{Name: "workloads", Parent: "platform", ID: "ou-workloads", Reason: "x"},
		},
		Accounts: []registry.Account{
			{Name: "mgmt", ID: "acct-mgmt", OU: "platform"},
			{Name: "app", ID: "acct-app", OU: "workloads"},
			{Name: "data", ID: "acct-data", OU: "workloads"},
		},
		IdentityCenter: registry.IdentityCenter{
			Assignments: []registry.Assignment{
				{Principal: "admins", PrincipalType: "group", PermissionSet: "admin", OUs: []string{"workloads"}},
				{Principal: "admins", PrincipalType: "group", PermissionSet: "admin", Accounts: []string{"mgmt"}},
				{Principal: "viewers", PrincipalType: "group", PermissionSet: "viewer", OUs: []string{"platform"}},
			},
			BreakGlass: &registry.BreakGlass{Principal: "admins", PrincipalType: "group", PermissionSet: "admin"},
		},
	}
}

func guards(fs []preflight.Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.Guard + "=" + f.Subject + ";")
	}

	return b.String()
}

func TestLockoutCleanRegistry(t *testing.T) {
	if fs := preflight.Lockout(reg(), now); len(fs) != 0 {
		t.Fatalf("clean registry refused: %v", fs)
	}
}

func TestLockoutBreakGlass(t *testing.T) {
	r := reg()
	r.IdentityCenter.BreakGlass = nil

	if got := guards(preflight.Lockout(r, now)); got != "break-glass=identity_center.break_glass;" {
		t.Fatalf("missing break glass: %s", got)
	}

	r = reg()
	r.IdentityCenter.Assignments = r.IdentityCenter.Assignments[:1] // mgmt no longer reached
	r.IdentityCenter.Assignments = append(r.IdentityCenter.Assignments,
		registry.Assignment{Principal: "admins", PrincipalType: "group", PermissionSet: "viewer", Accounts: []string{"mgmt"}})

	if got := guards(preflight.Lockout(r, now)); got != "break-glass=mgmt;" {
		t.Fatalf("unreached account: %s", got)
	}
}

func TestLockoutIgnoresClosedAccounts(t *testing.T) {
	r := reg()
	r.Accounts = append(r.Accounts, registry.Account{Name: "old", ID: "acct-old", OU: "workloads", Closed: true})
	r.IdentityCenter.Assignments = r.IdentityCenter.Assignments[1:2] // only mgmt; app, data and old unreached

	if got := guards(preflight.Lockout(r, now)); got != "break-glass=app;break-glass=data;" {
		t.Fatalf("a closed account needs no way in, the others do: %s", got)
	}
}

func TestLockoutSCPOnManagementChain(t *testing.T) {
	r := reg()
	r.OUs[0].SCPs = []string{"deny-leave"}           // platform: above mgmt
	r.Accounts[1].SCPs = []string{"deny-everything"} // app: not on the chain

	if got := guards(preflight.Lockout(r, now)); got != "scp-on-management=platform;" {
		t.Fatalf("policy above management: %s", got)
	}

	r.Waivers = []registry.Waiver{{Guard: registry.GuardSCPOnManagement, Target: "platform", Reason: "r", ExitCondition: "e", Expires: "2026-10-15"}}
	if fs := preflight.Lockout(r, now); len(fs) != 0 {
		t.Fatalf("waived (expires today) still refused: %v", fs)
	}

	r.Waivers[0].Expires = "2026-10-14"
	if got := guards(preflight.Lockout(r, now)); got != "scp-on-management=platform;waiver-expired=platform;" {
		t.Fatalf("expired waiver: %s", got)
	}
}

func TestLockoutStaleWaiver(t *testing.T) {
	r := reg()
	r.Waivers = []registry.Waiver{
		{Guard: registry.GuardSCPOnManagement, Target: "platform", Reason: "r", ExitCondition: "e"},
		{Guard: registry.GuardSCPOnManagement, Target: "root", Reason: "r", ExitCondition: "e"},
	}

	if got := guards(preflight.Lockout(r, now)); got != "waiver-expired=platform;" {
		t.Fatalf("stale waiver (root waivers are for plans): %s", got)
	}
}

func TestProtectedTargets(t *testing.T) {
	got := preflight.ProtectedTargets(reg())
	want := map[string]string{"r-root": "root", "acct-mgmt": "mgmt", "ou-platform": "platform"}

	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	for id, name := range want {
		if got[id] != name {
			t.Errorf("%s: %q, want %q", id, got[id], name)
		}
	}
}

func TestPlanIrreplaceable(t *testing.T) {
	steps := []preflight.Step{
		{Op: "replace", URN: "u-account", Type: preflight.TypeAccount},
		{Op: "create-replacement", URN: "u-ou", Type: preflight.TypeOrganizationalUnit},
		{Op: "delete-replaced", URN: "u-ou", Type: preflight.TypeOrganizationalUnit},
		{Op: "delete", URN: "u-ps", Type: preflight.TypePermissionSet},
		{Op: "update", URN: "u-account-2", Type: preflight.TypeAccount},
		{Op: "same", URN: "u-org", Type: preflight.TypeOrganization},
		{Op: "create", URN: "u-ps-2", Type: preflight.TypePermissionSet},
		{Op: "replace", URN: "u-other", Type: "aws:s3/bucket:Bucket"},
	}

	got := guards(preflight.Plan(steps, preflight.PlanOpts{}))
	if got != "irreplaceable=u-account;irreplaceable=u-ou;irreplaceable=u-ps;" {
		t.Fatalf("got %s", got)
	}
}

func TestPlanBreakGlassAssignment(t *testing.T) {
	bg := &preflight.BreakGlassAssignment{PermissionSetARN: "ps-admin", PrincipalID: "g-admins"}
	steps := []preflight.Step{
		{Op: "delete", URN: "u-bg", Type: preflight.TypeAccountAssignment, Old: map[string]any{"permissionSetArn": "ps-admin", "principalId": "g-admins"}},
		{Op: "replace", URN: "u-bg-2", Type: preflight.TypeAccountAssignment, Old: map[string]any{"permissionSetArn": "ps-admin", "principalId": "g-admins"}},
		{Op: "delete", URN: "u-viewer", Type: preflight.TypeAccountAssignment, Old: map[string]any{"permissionSetArn": "ps-viewer", "principalId": "g-admins"}},
		{Op: "create", URN: "u-new", Type: preflight.TypeAccountAssignment, New: map[string]any{"permissionSetArn": "ps-admin", "principalId": "g-admins"}},
	}

	if got := guards(preflight.Plan(steps, preflight.PlanOpts{BreakGlass: bg})); got != "break-glass=u-bg;break-glass=u-bg-2;" {
		t.Fatalf("got %s", got)
	}

	if got := preflight.Plan(steps, preflight.PlanOpts{}); len(got) != 0 {
		t.Fatalf("no break glass given, yet refused: %v", got)
	}
}

func TestPlanPolicyAttachment(t *testing.T) {
	r := reg()
	steps := []preflight.Step{
		{Op: "create", URN: "u-root", Type: preflight.TypePolicyAttachment, New: map[string]any{"targetId": "r-root"}},
		{Op: "create", URN: "u-mgmt", Type: preflight.TypePolicyAttachment, New: map[string]any{"targetId": "acct-mgmt"}},
		{Op: "create", URN: "u-app", Type: preflight.TypePolicyAttachment, New: map[string]any{"targetId": "acct-app"}},
		{Op: "delete", URN: "u-gone", Type: preflight.TypePolicyAttachment, Old: map[string]any{"targetId": "r-root"}},
	}

	o := preflight.PlanOpts{ProtectedTargets: preflight.ProtectedTargets(r), Waived: preflight.Waived(r, now)}
	if got := guards(preflight.Plan(steps, o)); got != "scp-on-management=u-root;scp-on-management=u-mgmt;" {
		t.Fatalf("got %s", got)
	}

	r.Waivers = []registry.Waiver{{Guard: registry.GuardSCPOnManagement, Target: "root", Reason: "r", ExitCondition: "e"}}
	o.Waived = preflight.Waived(r, now)

	if got := guards(preflight.Plan(steps, o)); got != "scp-on-management=u-mgmt;" {
		t.Fatalf("root waived: %s", got)
	}
}

func TestCheckAndErr(t *testing.T) {
	r := reg()
	r.IdentityCenter.BreakGlass = nil

	fs := preflight.Check([]preflight.Step{{Op: "replace", URN: "u-account", Type: preflight.TypeAccount}}, preflight.Opts{Registry: r, Now: now})

	err := preflight.Err(fs)
	if err == nil {
		t.Fatal("no error")
	}

	msg := err.Error()
	if !strings.Contains(msg, "preflight: break-glass: identity_center.break_glass") ||
		!strings.Contains(msg, "preflight: irreplaceable: u-account: replace (replace) planned") {
		t.Fatalf("message: %s", msg)
	}

	if strings.Index(msg, "break-glass") > strings.Index(msg, "irreplaceable") {
		t.Fatalf("findings not sorted by guard: %s", msg)
	}

	if preflight.Err(nil) != nil {
		t.Fatal("no findings, yet an error")
	}
}

func TestEventLog(t *testing.T) {
	f, err := os.Open("testdata/preview.events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	evs, err := preflight.ReadEventLog(f)
	if err != nil {
		t.Fatal(err)
	}

	steps := preflight.StepsFromEvents(evs)
	if len(steps) != 2 {
		t.Fatalf("steps: %+v", steps)
	}

	if s := steps[0]; s.Op != "replace" || s.Type != preflight.TypeAccount || s.Old["name"] != "a" || s.New["name"] != "b" {
		t.Fatalf("step 0: %+v", s)
	}

	if _, err := preflight.ReadEventLog(strings.NewReader("{nope\n")); err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("bad line: %v", err)
	}
}

func TestLockoutBreakGlassThroughBuilder(t *testing.T) {
	r := reg()
	r.IdentityCenter.Assignments = nil // no registry assignment declares break-glass
	r.Accounts = append(r.Accounts,
		registry.Account{Name: "top", ID: "acct-top", OU: registry.OURoot},
		registry.Account{Name: "old", ID: "acct-old", OU: "workloads", Closed: true},
		registry.Account{Name: "soon", OU: "workloads"})

	if got := guards(preflight.Lockout(r, now)); got == "" {
		t.Fatal("without the builder the registry must be refused")
	}

	// sso.DeployBreakGlass reaches every open account with an id, root OU
	// included, so the guard passes.
	if fs := preflight.LockoutWith(r, now, &preflight.BreakGlassBuilder{}); len(fs) != 0 {
		t.Fatalf("builder-declared break-glass refused: %v", fs)
	}

	if fs := preflight.Check(nil, preflight.Opts{Registry: r, Now: now, BreakGlassBuilder: &preflight.BreakGlassBuilder{}}); len(fs) != 0 {
		t.Fatalf("Check ignores the builder: %v", fs)
	}

	// An account the caller skips must be reached by the registry itself.
	skip := &preflight.BreakGlassBuilder{Skip: func(a string) bool { return a == "app" }}
	if got := guards(preflight.LockoutWith(r, now, skip)); got != "break-glass=app;" {
		t.Fatalf("skipped account not judged: %s", got)
	}

	r.IdentityCenter.Assignments = []registry.Assignment{
		{Principal: "admins", PrincipalType: "group", PermissionSet: "admin", Accounts: []string{"app"}},
	}

	if fs := preflight.LockoutWith(r, now, skip); len(fs) != 0 {
		t.Fatalf("skipped account covered by the registry still refused: %v", fs)
	}
}

// Changing a boundary policy or a permission set's inline policy is an update
// in place; neither is guarded, so the management-account admin boundary
// (pkg/boundary.OrgAdminManagement) and the organization-admin inline policy
// (pkg/engine/sso.OrgAdminInlinePolicy) need no waiver. Replacing the
// permission set itself is still refused.
func TestPlanBoundaryAndInlinePolicyUpdatesNeedNoWaiver(t *testing.T) {
	steps := []preflight.Step{
		{Op: "update", URN: "u-boundary", Type: "aws:iam/policy:Policy"},
		{Op: "replace", URN: "u-boundary-2", Type: "aws:iam/policy:Policy"},
		{Op: "update", URN: "u-inline", Type: "aws:ssoadmin/permissionSetInlinePolicy:PermissionSetInlinePolicy"},
		{Op: "create", URN: "u-attach", Type: "aws:ssoadmin/permissionsBoundaryAttachment:PermissionsBoundaryAttachment"},
	}

	if fs := preflight.Plan(steps, preflight.PlanOpts{}); len(fs) != 0 {
		t.Fatalf("refused: %v", fs)
	}

	if got := guards(preflight.Plan([]preflight.Step{{Op: "replace", URN: "u-ps", Type: preflight.TypePermissionSet}}, preflight.PlanOpts{})); got != "irreplaceable=u-ps;" {
		t.Fatalf("permission set replace: %s", got)
	}
}
