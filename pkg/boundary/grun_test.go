package boundary_test

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/truvity/aws-structure/pkg/boundary"
)

// grunSpec is currentSpec with the Grun boundary beside it.
func grunSpec() boundary.Spec {
	s := currentSpec()
	s.Names.Grun = "bound@tech-grun"
	s.Hierarchy[0].Delegates = append(s.Hierarchy[0].Delegates, "bound@tech-grun")
	s.Hierarchy = append(s.Hierarchy, boundary.Entry{Name: "bound@tech-grun"})
	s.Grun = boundary.GrunScope{
		RolePrefix:         "grun-",
		PassedToServices:   []string{"ecs-tasks.amazonaws.com"},
		ServiceLinkedRoles: []string{"ecs.amazonaws.com"},
	}

	return s
}

func TestGrunGolden(t *testing.T) {
	goldenIndented(t, "grun.json", docs(t, grunSpec())["bound@tech-grun"])
}

func TestGrunStatements(t *testing.T) {
	got := parse(t, docs(t, grunSpec())["bound@tech-grun"])

	want := []string{
		"AllowAll", "DenyIAMWriteExceptGrun", "DenyCreateExceptServiceLinkedRole", "DenyPassRoleOutsideGrunRoles",
		"DenyPassRoleToOtherServices", "DenyBoundaryPolicyEdit", "NoBoundaryDelete",
	}
	if !slices.Equal(sids(got), want) {
		t.Errorf("statements = %v, want %v", sids(got), want)
	}

	// Nothing that creates a role or user, or changes a boundary, is allowed
	// beside the two exceptions: the unconditional deny covers the rest of IAM.
	writes := actions(got.Statement[1].Action)
	for _, a := range []string{"iam:Put*", "iam:Update*", "iam:Attach*", "iam:Delete*", "iam:Tag*", "iam:Set*"} {
		if !slices.Contains(writes, a) {
			t.Errorf("DenyIAMWriteExceptGrun lacks %s", a)
		}
	}

	for _, a := range []string{"iam:Create*", "iam:Pass*"} {
		if slices.Contains(writes, a) {
			t.Errorf("DenyIAMWriteExceptGrun carries %s, which is denied under a condition instead", a)
		}
	}
}

// Without service-linked roles the whole of iam:Create* is denied outright.
func TestGrunWithoutServiceLinkedRoles(t *testing.T) {
	s := grunSpec()
	s.Grun.ServiceLinkedRoles = nil

	got := parse(t, docs(t, s)["bound@tech-grun"])

	if slices.Contains(sids(got), "DenyCreateExceptServiceLinkedRole") {
		t.Error("a conditional create deny was rendered with no service-linked role allowed")
	}

	if !slices.Contains(actions(got.Statement[1].Action), "iam:Create*") {
		t.Error("iam:Create* is not denied outright")
	}
}

func TestGrunIsALeafAndOptional(t *testing.T) {
	s := grunSpec()
	s.Hierarchy[len(s.Hierarchy)-1].Delegates = []string{"bound@default"}

	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), `leaf boundary "bound@tech-grun" must not have delegates`) {
		t.Errorf("a Grun that delegates was accepted: %v", err)
	}

	g := grunSpec()
	if got := g.DelegateARNs("bound@tech-grun"); got != nil {
		t.Errorf("Grun delegates %v", got)
	}

	// The role admin reaches it by its exact name.
	if !slices.Contains(g.DelegateARNs("bound@role-admin"), "arn:part:iam::*:policy/bound@tech-grun") {
		t.Error("role-admin does not delegate Grun")
	}

	// Naming it adds one document; the role admin, which lists it as a
	// delegate, is the only one that changes.
	without, with := docs(t, currentSpec()), docs(t, grunSpec())
	if len(with) != len(without)+1 {
		t.Errorf("%d documents, want %d", len(with), len(without)+1)
	}

	for name, d := range without {
		if name != "bound@role-admin" && with[name] != d {
			t.Errorf("%s changed when Grun was named", name)
		}
	}
}

func TestGrunRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*boundary.Spec)
		want   string
	}{
		"no prefix":   {func(s *boundary.Spec) { s.Grun.RolePrefix = "" }, "Grun.RolePrefix is empty"},
		"no services": {func(s *boundary.Spec) { s.Grun.PassedToServices = nil }, "Grun.PassedToServices is empty"},
		"empty service": {func(s *boundary.Spec) {
			s.Grun.ServiceLinkedRoles = []string{""}
		}, "Grun.ServiceLinkedRoles has an empty entry"},
		"no hierarchy entry": {func(s *boundary.Spec) {
			s.Hierarchy = s.Hierarchy[:len(s.Hierarchy)-1]
		}, `Hierarchy has no entry for "bound@tech-grun"`},
		"duplicate name": {func(s *boundary.Spec) { s.Names.Grun = "bound@tech-ack-s3" }, "are both named"},
	} {
		s := grunSpec()
		tc.mutate(&s)

		if err := s.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want containing %q", name, err, tc.want)
		}
	}

	// The scope is not checked when no Grun is named.
	s := currentSpec()
	s.Grun = boundary.GrunScope{}

	if err := s.Validate(); err != nil {
		t.Errorf("an unused empty scope was refused: %v", err)
	}
}

func TestGrunFitsTheManagedPolicyLimit(t *testing.T) {
	var b bytes.Buffer
	if err := json.Compact(&b, []byte(docs(t, grunSpec())["bound@tech-grun"])); err != nil {
		t.Fatal(err)
	}

	if b.Len() > maxPolicyChars {
		t.Errorf("%d characters, over IAM's %d", b.Len(), maxPolicyChars)
	}
}
