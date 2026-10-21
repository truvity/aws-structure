package boundary

import (
	"fmt"
	"slices"

	"github.com/truvity/aws-structure/pkg/cdkbootstrap"
)

// validateCDKBootstraps checks the CDK bootstraps of the Spec: each on its
// own and as a set (pkg/cdkbootstrap), and that the boundary each one names
// as its DeployBoundary is a boundary of this Spec, rendered in every account
// the bootstrap is deployed to.
func (s *Spec) validateCDKBootstraps() []error {
	if len(s.CDKBootstraps) == 0 {
		return nil
	}

	var errs []error

	if err := cdkbootstrap.Validate(s.CDKBootstraps); err != nil {
		errs = append(errs, fmt.Errorf("spec: CDKBootstraps: %w", err))
	}

	known := s.builtinNames()

	for _, e := range s.Hierarchy {
		known[e.Name] = true
	}

	extras := map[string]*Extra{}

	for i := range s.Extra {
		known[s.Extra[i].Name] = true
		extras[s.Extra[i].Name] = &s.Extra[i]
	}

	for i := range s.CDKBootstraps {
		b := &s.CDKBootstraps[i]

		if b.DeployBoundary == "" {
			continue // reported by the bootstrap's own validation
		}

		if !known[b.DeployBoundary] {
			errs = append(errs, fmt.Errorf("spec: CDKBootstraps[%d] (%s): DeployBoundary %q is not a boundary of the Spec", i, b.Qualifier, b.DeployBoundary))

			continue
		}

		e, ok := extras[b.DeployBoundary]
		if !ok || len(e.Accounts) == 0 {
			continue
		}

		for _, a := range b.Accounts {
			if !slices.Contains(e.Accounts, a) {
				errs = append(errs, fmt.Errorf("spec: CDKBootstraps[%d] (%s): DeployBoundary %q is not rendered in account %q (Extra.Accounts %v)",
					i, b.Qualifier, b.DeployBoundary, a, e.Accounts))
			}
		}
	}

	return errs
}
