package ssmaudit_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/truvity/aws-structure/pkg/ssmaudit"
)

// One account behind two read-only profiles and one admin profile, which is
// the shape that made the first run of this audit report the estate as twice
// as dirty as it is.
const twoRolesOneAccount = `
[profile a-west@ro]
sso_account_id = acct-a
sso_role_name  = ro
region         = west-1

[profile a@ro]
sso_account_id = acct-a
sso_role_name  = ro
region         = central-1

[profile a@admin]
sso_account_id = acct-a
sso_role_name  = admin
region         = central-1
`

func writeINI(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "aws.ini")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestOneAccountIsVisitedOncePerRegion(t *testing.T) {
	accounts, err := ssmaudit.ReadAccounts(writeINI(t, twoRolesOneAccount), "ro", "west-1")
	if err != nil {
		t.Fatal(err)
	}

	// Two regions, not three visits: the two read-only profiles are one
	// account, and the admin profile is not a read-only role.
	if len(accounts) != 2 {
		t.Fatalf("got %d visits, want 2: %+v", len(accounts), accounts)
	}

	regions := map[string]bool{}

	for _, a := range accounts {
		regions[a.Region] = true

		if a.ID != "acct-a" {
			t.Errorf("id = %q", a.ID)
		}

		got := map[string]bool{}
		for _, p := range a.Profiles {
			got[p] = true
		}

		// Every profile of the account must be tried in every region: which
		// role the operator holds is discovered, not declared.
		if len(got) != 2 || !got["a-west@ro"] || !got["a@ro"] {
			t.Errorf("profiles = %v", a.Profiles)
		}
	}

	if !regions["central-1"] || !regions["west-1"] {
		t.Errorf("regions = %v", regions)
	}
}

func TestNoExtraRegionMeansOneVisitPerProfileRegion(t *testing.T) {
	accounts, err := ssmaudit.ReadAccounts(writeINI(t, twoRolesOneAccount), "ro", "")
	if err != nil {
		t.Fatal(err)
	}

	if len(accounts) != 2 {
		t.Fatalf("got %d, want 2 (the two profiles name two regions)", len(accounts))
	}
}

func TestRoleIsRequired(t *testing.T) {
	if _, err := ssmaudit.ReadAccounts(writeINI(t, twoRolesOneAccount), "", ""); err == nil {
		t.Fatal("an empty role would match every profile")
	}
}

func TestNoViewerProfilesIsAnError(t *testing.T) {
	_, err := ssmaudit.Audit(context.Background(), ssmaudit.Config{
		ConfigFile: writeINI(t, twoRolesOneAccount),
		Role:       "nobody",
		Declared:   func(string) bool { return true },
		List:       func(context.Context, string, string) ([]string, error) { return nil, nil },
	})
	if err == nil || !strings.Contains(err.Error(), "no nobody profiles") {
		t.Fatalf("err = %v", err)
	}
}

func TestAuditJudgesNamesAndFallsBackAcrossProfiles(t *testing.T) {
	declared := func(name string) bool { return strings.HasPrefix(name, "/known/") }

	var tried []string

	list := func(_ context.Context, profile, region string) ([]string, error) {
		tried = append(tried, profile+"/"+region)

		// The operator holds a@ro only: the other profile is a closed door.
		if profile != "a@ro" {
			return nil, errors.New("not signed in")
		}

		if region == "west-1" {
			return nil, errors.New("access denied")
		}

		return []string{"/known/x", "/stray/y"}, nil
	}

	res, err := ssmaudit.Audit(context.Background(), ssmaudit.Config{
		ConfigFile:  writeINI(t, twoRolesOneAccount),
		Role:        "ro",
		ExtraRegion: "west-1",
		Declared:    declared,
		List:        list,
	})
	if err != nil {
		t.Fatal(err)
	}

	if res.Declared != 1 {
		t.Errorf("declared = %d", res.Declared)
	}

	if len(res.Undeclared) != 1 || res.Undeclared[0].Name != "/stray/y" ||
		res.Undeclared[0].Account != "acct-a central-1 via a@ro" {
		t.Errorf("undeclared = %+v", res.Undeclared)
	}

	// An unreachable region is reported, not fatal: the audit still reached
	// the one it could see.
	if len(res.Skipped) != 1 || res.Skipped[0].Account.Region != "west-1" {
		t.Errorf("skipped = %+v", res.Skipped)
	}
}

func TestAuditNeedsItsInputs(t *testing.T) {
	if _, err := ssmaudit.Audit(context.Background(), ssmaudit.Config{ConfigFile: "x", Role: "ro"}); err == nil {
		t.Fatal("Declared and List are required")
	}
}

func TestWrite(t *testing.T) {
	res := &ssmaudit.Result{
		Declared:   3,
		Undeclared: []ssmaudit.Finding{{Account: "b", Name: "/n2"}, {Account: "a", Name: "/n1"}},
		Skipped: []ssmaudit.Skipped{{
			Account: ssmaudit.Account{ID: "acct-c", Region: "r", Profiles: []string{"p1", "p2"}},
			Err:     errors.New("denied"),
		}},
	}

	var out bytes.Buffer
	if err := res.Write(&out, "declare it"); err != nil {
		t.Fatal(err)
	}

	got := out.String()
	for _, want := range []string{
		"declared parameters: 3",
		"- acct-c r (tried p1, p2): denied",
		"UNDECLARED (2)",
		"\n  a (1)\n    /n1\n",
		"\n  b (1)\n    /n2\n",
		"declare it",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}

	if strings.Index(got, "  a (1)") > strings.Index(got, "  b (1)") {
		t.Error("accounts must be sorted")
	}

	out.Reset()
	if err := (&ssmaudit.Result{Declared: 1}).Write(&out, "declare it"); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(out.String(), "no undeclared parameters") || strings.Contains(out.String(), "declare it") {
		t.Errorf("clean output = %s", out.String())
	}
}

// fakeSSM serves two pages of names.
type fakeSSM struct{ calls int }

func (f *fakeSSM) DescribeParameters(_ context.Context, in *ssm.DescribeParametersInput,
	_ ...func(*ssm.Options)) (*ssm.DescribeParametersOutput, error) {
	f.calls++

	str := func(s string) *string { return &s }

	if in.NextToken == nil {
		return &ssm.DescribeParametersOutput{
			Parameters: []types.ParameterMetadata{{Name: str("/b")}, {Name: nil}},
			NextToken:  str("page2"),
		}, nil
	}

	return &ssm.DescribeParametersOutput{Parameters: []types.ParameterMetadata{{Name: str("/a")}}}, nil
}

func TestListParametersPagesAndSorts(t *testing.T) {
	f := &fakeSSM{}

	names, err := ssmaudit.ListParameters(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}

	if f.calls != 2 || len(names) != 2 || names[0] != "/a" || names[1] != "/b" {
		t.Fatalf("calls=%d names=%v", f.calls, names)
	}
}
