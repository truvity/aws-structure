package sso_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/truvity/aws-structure/pkg/boundary"
	"github.com/truvity/aws-structure/pkg/engine/sso"
)

func TestOrgAdminStatement(t *testing.T) {
	b, err := json.Marshal(sso.OrgAdminStatement())
	if err != nil {
		t.Fatal(err)
	}

	want := `{"Action":["organizations:*","account:*","sso:*","sso-directory:*","identitystore:*"],"Effect":"Allow","Resource":"*","Sid":"OrganizationAdmin"}`
	if string(b) != want {
		t.Errorf("statement = %s", b)
	}

	// The returned slice is the caller's own.
	a := sso.OrgAdminActions()
	a[0] = "x"

	if sso.OrgAdminActions()[0] != "organizations:*" {
		t.Error("OrgAdminActions shares its backing array")
	}
}

func TestOrgAdminInlinePolicyFromNothing(t *testing.T) {
	got, err := sso.OrgAdminInlinePolicy("")
	if err != nil {
		t.Fatal(err)
	}

	want := `{"Statement":[{"Action":["organizations:*","account:*","sso:*","sso-directory:*","identitystore:*"],"Effect":"Allow","Resource":"*","Sid":"OrganizationAdmin"}],"Version":"2012-10-17"}`
	if got != want {
		t.Errorf("got %s", got)
	}
}

func TestOrgAdminInlinePolicyKeepsBase(t *testing.T) {
	base := `{"Version":"2012-10-17","Statement":[{"Sid":"X","Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`

	got, err := sso.OrgAdminInlinePolicy(base)
	if err != nil {
		t.Fatal(err)
	}

	var d struct{ Statement []map[string]any }
	if err := json.Unmarshal([]byte(got), &d); err != nil {
		t.Fatal(err)
	}

	if len(d.Statement) != 2 || d.Statement[0]["Sid"] != "X" || d.Statement[1]["Sid"] != "OrganizationAdmin" {
		t.Errorf("statements = %v", d.Statement)
	}

	// Idempotent: applying it to its own output changes nothing.
	again, err := sso.OrgAdminInlinePolicy(got)
	if err != nil || again != got {
		t.Errorf("not idempotent: %v\n%s\n%s", err, got, again)
	}

	// A single-object Statement is accepted.
	one := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`
	if got, err := sso.OrgAdminInlinePolicy(one); err != nil || strings.Count(got, `"Effect"`) != 2 {
		t.Errorf("single statement: %v %s", err, got)
	}
}

func TestOrgAdminInlinePolicyRefusals(t *testing.T) {
	for name, base := range map[string]string{
		"not json":      "{",
		"not an object": `[1]`,
		"bad statement": `{"Statement":"x"}`,
		"too big":       `{"Statement":[{"Sid":"Pad","Effect":"Allow","Action":"s3:*","Resource":"` + strings.Repeat("a", 10300) + `"}]}`,
	} {
		if _, err := sso.OrgAdminInlinePolicy(base); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The identity side and the boundary side name the same actions.
func TestOrgAdminActionsMatchTheManagementBoundary(t *testing.T) {
	s := boundary.Spec{
		Partition: "part", Prefix: "b@", ClassPrefix: "b@t-",
		Names: boundary.Names{
			Admin: "b@admin", Deploy: "b@deploy", Default: "b@default", Viewer: "b@viewer", Project: "b@project",
			Audit: "b@audit", ACKIAM: "b@t-iam", CAPA: "b@t-capa", EKSAutoNode: "b@t-node",
		},
		Hierarchy: []boundary.Entry{{Name: "b@admin", Delegates: []string{"b@t-iam"}}, {Name: "b@deploy"}, {Name: "b@t-iam"}},
		OrgAdmin:  boundary.OrgAdminManagement,
	}

	ps, err := boundary.Policies(s)
	if err != nil {
		t.Fatal(err)
	}

	var d struct {
		Statement []struct {
			Sid    string
			Action any
		}
	}
	if err := json.Unmarshal([]byte(ps[0].Document), &d); err != nil {
		t.Fatal(err)
	}

	for _, st := range d.Statement {
		if st.Sid != "AllowOrganizationAdmin" {
			continue
		}

		var got []string
		for _, a := range st.Action.([]any) {
			got = append(got, a.(string))
		}

		if !slices.Equal(got, sso.OrgAdminActions()) {
			t.Errorf("boundary allows %v, inline policy grants %v", got, sso.OrgAdminActions())
		}

		return
	}

	t.Error("no AllowOrganizationAdmin statement")
}
