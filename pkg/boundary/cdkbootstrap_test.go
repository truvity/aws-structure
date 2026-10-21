package boundary_test

import (
	"strings"
	"testing"

	"github.com/truvity/aws-structure/pkg/boundary"
	"github.com/truvity/aws-structure/pkg/cdkbootstrap"
)

func bootstrapOf(deploy string) cdkbootstrap.Bootstrap {
	return cdkbootstrap.Bootstrap{
		Qualifier:      "app",
		DeployBoundary: deploy,
		Accounts:       []string{"alpha"},
		Regions:        []string{"eu-central-1"},
	}
}

func TestCDKBootstrapsAreChecked(t *testing.T) {
	top := topExtra()
	leaf := leafExtra(t)

	valid := func() boundary.Spec {
		s := extraSpec()
		s.Extra = []boundary.Extra{leaf, top}
		s.CDKBootstraps = []cdkbootstrap.Bootstrap{bootstrapOf(extraTop)}

		return s
	}

	if err := (func() error { s := valid(); return s.Validate() })(); err != nil {
		t.Fatalf("a valid Spec is refused: %v", err)
	}

	// The bootstraps change no document.
	with, without := valid(), valid()
	without.CDKBootstraps = nil

	if a, b := docs(t, with), docs(t, without); len(a) != len(b) {
		t.Fatalf("%d documents with bootstraps, %d without", len(a), len(b))
	} else {
		for k, v := range a {
			if b[k] != v {
				t.Errorf("document %s differs with a bootstrap", k)
			}
		}
	}

	for name, tc := range map[string]struct {
		edit func(*boundary.Spec)
		want string
	}{
		"unknown boundary": {func(s *boundary.Spec) { s.CDKBootstraps[0].DeployBoundary = "bound@tech-nowhere" }, "is not a boundary of the Spec"},
		"a built-in boundary is a boundary of the Spec": {func(s *boundary.Spec) {
			s.CDKBootstraps[0].DeployBoundary = extraAdmin
			s.CDKBootstraps[0].Qualifier = "ok"
		}, ""},
		"bad qualifier": {func(s *boundary.Spec) { s.CDKBootstraps[0].Qualifier = "Bad-Q" }, "qualifier"},
		"duplicate": {func(s *boundary.Spec) {
			s.CDKBootstraps = append(s.CDKBootstraps, bootstrapOf(extraLeaf))
		}, "both bootstrap qualifier"},
		"extra not in the account": {func(s *boundary.Spec) {
			s.Extra[1].Accounts = []string{"beta"}
			s.Extra[1].Delegates = nil
			s.Extra[0].Accounts = []string{"beta"}
			s.Extra[0].DelegatedBy = []string{extraAdmin}
		}, `is not rendered in account "alpha"`},
	} {
		t.Run(name, func(t *testing.T) {
			s := valid()
			tc.edit(&s)

			err := s.Validate()
			if tc.want == "" {
				if err != nil {
					t.Errorf("Validate = %v", err)
				}

				return
			}

			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Validate = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}
