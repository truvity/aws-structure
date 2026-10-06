package boundary_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/truvity/aws-structure/pkg/boundary"
)

func spec() boundary.Spec {
	return boundary.Spec{
		Partition:   "part",
		Prefix:      "bound@",
		ClassPrefix: "bound@tech-",
		Names: boundary.Names{
			Admin: "bound@admin", Deploy: "bound@deploy", Default: "bound@default", Viewer: "bound@viewer",
			Project: "bound@project", Audit: "bound@audit",
			ACKIAM: "bound@tech-iam", CAPA: "bound@tech-capa", EKSAutoNode: "bound@tech-node",
		},
		Hierarchy: []boundary.Entry{
			{Name: "bound@admin", Delegates: []string{"bound@deploy", "bound@project", "bound@tech-iam", "bound@tech-capa"}},
			{Name: "bound@deploy", Delegates: []string{"bound@project", "bound@default"}, EnforcesTags: []string{"project"}},
			{Name: "bound@tech-iam", Delegates: []string{"bound@default", "bound@project"}},
			{Name: "bound@project"},
		},
	}
}

func TestDelegation(t *testing.T) {
	s := spec()

	admin := s.DelegateARNs("bound@admin")
	want := []string{
		"arn:part:iam::*:policy/bound@admin",
		"arn:part:iam::*:policy/bound@deploy",
		"arn:part:iam::*:policy/bound@project",
		"arn:part:iam::*:policy/bound@tech-*",
	}

	if strings.Join(admin, ",") != strings.Join(want, ",") {
		t.Errorf("admin delegates = %v, want %v (itself, its delegates, the class as one wildcard)", admin, want)
	}

	if got := s.DelegateARNs("bound@deploy"); strings.Join(got, ",") != "arn:part:iam::*:policy/bound@project,arn:part:iam::*:policy/bound@default" {
		t.Errorf("deploy delegates = %v", got)
	}

	if s.DelegateARNs("bound@project") != nil || s.DelegateARNs("unknown") != nil {
		t.Error("a leaf and an unknown name delegate to nothing")
	}

	if got := s.EnforcedTags("bound@deploy"); len(got) != 1 || got[0] != "project" {
		t.Errorf("enforced tags = %v", got)
	}
}

func TestPoliciesAreValidJSONInOrder(t *testing.T) {
	ps, err := boundary.Policies(spec())
	if err != nil {
		t.Fatal(err)
	}

	order := []string{
		"bound@admin", "bound@viewer", "bound@default", "bound@tech-iam", "bound@tech-capa",
		"bound@tech-node", "bound@deploy", "bound@project", "bound@audit",
	}

	if len(ps) != len(order) {
		t.Fatalf("%d policies, want %d", len(ps), len(order))
	}

	docs := map[string]string{}

	for i, p := range ps {
		if p.Name != order[i] {
			t.Errorf("policy %d is %s, want %s", i, p.Name, order[i])
		}

		if !json.Valid([]byte(p.Document)) {
			t.Errorf("%s is not valid JSON", p.Name)
		}

		docs[p.Name] = p.Document
	}

	if docs["bound@viewer"] != docs["bound@default"] {
		t.Error("the deprecated viewer is the default's document")
	}

	if !strings.Contains(docs["bound@admin"], `"Resource":["arn:part:iam::*:policy/bound@*"]`) {
		t.Error("admin must deny editing every boundary by prefix")
	}

	if !strings.Contains(docs["bound@project"], "arn:part:ssm:*:*:parameter/${aws:PrincipalTag/project}/*") {
		t.Error("project is scoped by the principal's own project tag")
	}

	for name, doc := range docs {
		if strings.Contains(doc, "arn:"+"aws") {
			t.Errorf("%s names a partition the caller did not give", name)
		}
	}
}

func TestSpecRefusals(t *testing.T) {
	s := spec()
	s.Partition = ""
	s.ClassPrefix = "other@tech-"
	s.Hierarchy = s.Hierarchy[1:]

	_, err := boundary.Policies(s)
	if err == nil {
		t.Fatal("invalid spec accepted")
	}

	for _, frag := range []string{"Partition is empty", "does not extend Prefix", `no entry for "bound@admin"`} {
		if !strings.Contains(err.Error(), frag) {
			t.Errorf("error %q lacks %q", err, frag)
		}
	}
}
