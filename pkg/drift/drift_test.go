package drift_test

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	idstypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"

	"github.com/truvity/aws-structure/pkg/drift"
	"github.com/truvity/aws-structure/pkg/registry"
)

// fakeOrg is an organization: root r-1 holding OUs platform (ou-p, holding
// workloads ou-w) and sandbox (ou-x, made by hand).
type fakeOrg struct{}

func (fakeOrg) ListRoots(context.Context, *organizations.ListRootsInput, ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
	return &organizations.ListRootsOutput{Roots: []orgtypes.Root{{Id: aws.String("r-1")}}}, nil
}

func (fakeOrg) ListOrganizationalUnitsForParent(_ context.Context, in *organizations.ListOrganizationalUnitsForParentInput,
	_ ...func(*organizations.Options),
) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
	ous := map[string][]orgtypes.OrganizationalUnit{
		"r-1":  {{Id: aws.String("ou-p"), Name: aws.String("platform")}, {Id: aws.String("ou-x"), Name: aws.String("sandbox")}},
		"ou-p": {{Id: aws.String("ou-w"), Name: aws.String("workloads")}},
	}

	return &organizations.ListOrganizationalUnitsForParentOutput{OrganizationalUnits: ous[aws.ToString(in.ParentId)]}, nil
}

func acct(id, name, email string) orgtypes.Account {
	return orgtypes.Account{Id: aws.String(id), Name: aws.String(name), Email: aws.String(email), State: orgtypes.AccountStateActive}
}

func (fakeOrg) ListAccountsForParent(_ context.Context, in *organizations.ListAccountsForParentInput,
	_ ...func(*organizations.Options),
) (*organizations.ListAccountsForParentOutput, error) {
	accts := map[string][]orgtypes.Account{
		"ou-p": {acct("acct-mgmt", "Management", "mgmt@example.test"), acct("acct-app", "App", "app@example.test")},
		"ou-w": {acct("acct-new", "New", "new@example.test")},
		"ou-x": {acct("acct-rogue", "Rogue", "rogue@example.test")},
	}

	return &organizations.ListAccountsForParentOutput{Accounts: accts[aws.ToString(in.ParentId)]}, nil
}

func (fakeOrg) ListPoliciesForTarget(_ context.Context, in *organizations.ListPoliciesForTargetInput,
	_ ...func(*organizations.Options),
) (*organizations.ListPoliciesForTargetOutput, error) {
	out := []orgtypes.PolicySummary{{Name: aws.String("FullAWSAccess")}}
	if aws.ToString(in.TargetId) == "r-1" {
		out = append(out, orgtypes.PolicySummary{Name: aws.String("deny-leave")})
	}

	return &organizations.ListPoliciesForTargetOutput{Policies: out}, nil
}

type fakeSSO struct{}

var setNames = map[string]string{"ps-a": "admin", "ps-v": "viewer", "ps-c": "console-made"}

func (fakeSSO) ListPermissionSets(context.Context, *ssoadmin.ListPermissionSetsInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListPermissionSetsOutput, error) {
	return &ssoadmin.ListPermissionSetsOutput{PermissionSets: []string{"ps-a", "ps-v", "ps-c"}}, nil
}

func (fakeSSO) DescribePermissionSet(_ context.Context, in *ssoadmin.DescribePermissionSetInput,
	_ ...func(*ssoadmin.Options),
) (*ssoadmin.DescribePermissionSetOutput, error) {
	return &ssoadmin.DescribePermissionSetOutput{PermissionSet: &ssotypes.PermissionSet{Name: aws.String(setNames[aws.ToString(in.PermissionSetArn)])}}, nil
}

func (fakeSSO) ListAccountAssignments(_ context.Context, in *ssoadmin.ListAccountAssignmentsInput,
	_ ...func(*ssoadmin.Options),
) (*ssoadmin.ListAccountAssignmentsOutput, error) {
	a := func(principalType ssotypes.PrincipalType, id string) ssotypes.AccountAssignment {
		return ssotypes.AccountAssignment{
			AccountId: in.AccountId, PermissionSetArn: in.PermissionSetArn, PrincipalType: principalType, PrincipalId: aws.String(id),
		}
	}

	key := aws.ToString(in.AccountId) + "/" + aws.ToString(in.PermissionSetArn)
	out := map[string][]ssotypes.AccountAssignment{
		"acct-mgmt/ps-a": {a(ssotypes.PrincipalTypeGroup, "g-1")},
		"acct-app/ps-a":  {a(ssotypes.PrincipalTypeGroup, "g-1")},
		"acct-app/ps-v":  {a(ssotypes.PrincipalTypeUser, "u-1")},
	}

	return &ssoadmin.ListAccountAssignmentsOutput{AccountAssignments: out[key]}, nil
}

type fakeStore struct{}

func (fakeStore) ListGroups(context.Context, *identitystore.ListGroupsInput, ...func(*identitystore.Options)) (*identitystore.ListGroupsOutput, error) {
	return &identitystore.ListGroupsOutput{Groups: []idstypes.Group{{GroupId: aws.String("g-1"), DisplayName: aws.String("admins")}}}, nil
}

func (fakeStore) ListUsers(context.Context, *identitystore.ListUsersInput, ...func(*identitystore.Options)) (*identitystore.ListUsersOutput, error) {
	return &identitystore.ListUsersOutput{Users: []idstypes.User{{UserId: aws.String("u-1"), UserName: aws.String("alice")}}}, nil
}

func reg() *registry.Registry {
	return &registry.Registry{
		Organization:   registry.Organization{RootID: "r-1", ManagementAccount: "mgmt"},
		SCPEnforcement: registry.SCPDormant,
		OUs: []registry.OU{
			{Name: "workloads", Parent: "platform"}, // listed before its parent on purpose
			{Name: "platform", ID: "ou-p"},
			{Name: "gone", ID: "ou-gone"},
		},
		Accounts: []registry.Account{
			{Name: "mgmt", ID: "acct-mgmt", Email: "mgmt@example.test", OU: "platform"},
			{Name: "app", ID: "acct-app", Email: "app@example.test", OU: "workloads"},
			{Name: "new", Email: "NEW@example.test", OU: "workloads"},
			{Name: "later", Email: "later@example.test", OU: "workloads"},
		},
		IdentityCenter: registry.IdentityCenter{
			PermissionSets: []registry.PermissionSet{{Name: "admin"}, {Name: "viewer"}, {Name: "auditor"}},
			Assignments: []registry.Assignment{
				{Principal: "admins", PrincipalType: "group", PermissionSet: "admin", OUs: []string{"platform"}},
			},
		},
	}
}

func read(t *testing.T) *drift.Live {
	t.Helper()

	live, err := drift.Read(context.Background(), drift.Clients{
		Organizations: fakeOrg{}, SSOAdmin: fakeSSO{}, IdentityStore: fakeStore{},
		InstanceARN: "instance", IdentityStoreID: "store",
	})
	if err != nil {
		t.Fatal(err)
	}

	return live
}

func TestReadWalksTheTree(t *testing.T) {
	live := read(t)

	if live.RootID != "r-1" || len(live.OUs) != 3 || len(live.Accounts) != 4 || len(live.Assignments) != 3 {
		t.Fatalf("live: %+v", live)
	}

	if got := live.Policies["r-1"]; strings.Join(got, ",") != "FullAWSAccess,deny-leave" {
		t.Fatalf("root policies: %v", got)
	}
}

func TestReadRefusesMissingClients(t *testing.T) {
	if _, err := drift.Read(context.Background(), drift.Clients{}); err == nil {
		t.Fatal("empty clients accepted")
	}
}

func TestCompare(t *testing.T) {
	got := drift.Compare(reg(), read(t))

	var lines []string
	for _, f := range got {
		lines = append(lines, f.String())
	}

	want := []string{
		"missing account later: not created yet",
		"moved account app: parent ou-p, declared workloads (ou-w)",
		"unmanaged account Rogue: acct-rogue",
		"unrecorded-id account new: exists as acct-new",
		"missing assignment new|admin|GROUP|admins: declared, not granted",
		"unmanaged assignment app|viewer|USER|alice: granted in AWS, not declared",
		"missing ou gone: id ou-gone not found",
		"unmanaged ou sandbox: ou-x",
		"unrecorded-id ou workloads: exists as ou-w",
		"missing permission-set auditor",
		"unmanaged permission-set console-made: ps-c",
		"unmanaged scp-attachment root (r-1): policy \"deny-leave\" attached while the registry is dormant",
	}

	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\n\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}

type fakeIAM struct{ roles []iamtypes.Role }

func (f fakeIAM) ListRoles(_ context.Context, in *iam.ListRolesInput, _ ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	if aws.ToString(in.PathPrefix) != "/aws-reserved/sso.amazonaws.com/" {
		return &iam.ListRolesOutput{}, nil
	}

	return &iam.ListRolesOutput{Roles: f.roles}, nil
}

func role(account, name string) iamtypes.Role {
	return iamtypes.Role{
		RoleName: aws.String(name),
		Arn:      aws.String("arn:example:iam::" + account + ":role/aws-reserved/sso.amazonaws.com/region-a/" + name),
	}
}

func TestAccessRoles(t *testing.T) {
	clients := map[string]drift.IAMAPI{
		"acct-a": fakeIAM{roles: []iamtypes.Role{
			role("acct-a", "AWSReservedSSO_role_admin_abc123"),
			role("acct-a", "AWSReservedSSO_viewer_def456"),
			role("acct-a", "not-an-sso-role"),
		}},
	}

	set, err := drift.AccessRoles(context.Background(), map[string]string{"a": "acct-a"},
		func(_ context.Context, id string) (drift.IAMAPI, error) { return clients[id], nil })
	if err != nil {
		t.Fatal(err)
	}

	admin := set.Accounts["a"].Roles["role_admin"]
	if admin.RoleName != "AWSReservedSSO_role_admin_abc123" ||
		admin.RoleARNPathless != "arn:example:iam::acct-a:role/AWSReservedSSO_role_admin_abc123" ||
		!strings.Contains(admin.RoleARN, "/aws-reserved/sso.amazonaws.com/region-a/") {
		t.Fatalf("admin role: %+v", admin)
	}

	if len(set.Accounts["a"].Roles) != 2 {
		t.Fatalf("roles: %+v", set.Accounts["a"].Roles)
	}

	out, err := drift.RenderAccessRoles(set, "GENERATED by a test.\nDo not edit.")
	if err != nil {
		t.Fatal(err)
	}

	text := string(out)
	if !strings.HasPrefix(text, "# GENERATED by a test.\n# Do not edit.\naccounts:\n") ||
		!strings.Contains(text, "role_arn_pathless: arn:example:iam::acct-a:role/AWSReservedSSO_viewer_def456") {
		t.Fatalf("render:\n%s", text)
	}
}

func TestCompareAccountAtTheRoot(t *testing.T) {
	r := &registry.Registry{
		Organization:   registry.Organization{RootID: "r-1", ManagementAccount: "mgmt"},
		SCPEnforcement: registry.SCPDormant,
		Accounts:       []registry.Account{{Name: "mgmt", ID: "acct-mgmt", Email: "mgmt@example.test", OU: registry.OURoot}},
	}
	live := &drift.Live{
		RootID:   "r-1",
		Accounts: []drift.LiveAccount{{ID: "acct-mgmt", Name: "mgmt", Email: "mgmt@example.test", ParentID: "r-1", State: "ACTIVE"}},
	}

	if got := drift.Compare(r, live); len(got) != 0 {
		t.Fatalf("an account at the root drifts: %v", got)
	}

	live.Accounts[0].ParentID = "ou-x"

	got := drift.Compare(r, live)
	if len(got) != 1 || got[0].Kind != drift.KindMoved {
		t.Fatalf("an account moved off the root: %v", got)
	}
}

func TestCompareClosedAccount(t *testing.T) {
	r := &registry.Registry{
		Organization:   registry.Organization{RootID: "r-1", ManagementAccount: "mgmt"},
		SCPEnforcement: registry.SCPDormant,
		Accounts: []registry.Account{
			{Name: "mgmt", ID: "acct-mgmt", Email: "mgmt@example.test", OU: registry.OURoot},
			{Name: "old", ID: "acct-old", Email: "old@example.test", OU: registry.OURoot, Closed: "closed"},
		},
		IdentityCenter: registry.IdentityCenter{
			PermissionSets: []registry.PermissionSet{{Name: "admin"}},
			Assignments:    []registry.Assignment{{Principal: "admins", PrincipalType: "group", PermissionSet: "admin", Accounts: []string{"mgmt", "old"}}},
		},
	}
	live := &drift.Live{
		RootID: "r-1",
		Accounts: []drift.LiveAccount{
			{ID: "acct-mgmt", Name: "mgmt", Email: "mgmt@example.test", ParentID: "r-1", State: "ACTIVE"},
			{ID: "acct-old", Name: "old", Email: "old@example.test", ParentID: "r-1", State: "SUSPENDED"},
		},
		PermissionSets: map[string]string{"arn-admin": "admin"},
		Groups:         map[string]string{"g-1": "admins"},
		Assignments:    []drift.LiveAssignment{{AccountID: "acct-mgmt", PermissionSetARN: "arn-admin", PrincipalType: "GROUP", PrincipalID: "g-1"}},
	}

	if got := drift.Compare(r, live); len(got) != 0 {
		t.Fatalf("a closed account that is closed drifts: %v", got)
	}

	live.Accounts[1].State = "ACTIVE"

	got := drift.Compare(r, live)
	if len(got) != 1 || got[0].Kind != drift.KindEdited {
		t.Fatalf("a closed account that came back is not reported: %v", got)
	}

	r.Accounts[1].Closed = ""
	live.Accounts[1].State = "SUSPENDED"

	got = drift.Compare(r, live)
	if len(got) < 1 || got[0].Kind != drift.KindNotActive {
		t.Fatalf("an account that is not active and not declared closed: %v", got)
	}
}
