package boundary

import (
	"errors"
	"fmt"
	"slices"

	"github.com/truvity/aws-structure/policy"
)

// GrunScope configures the Grun boundary: the roles the self-hosted GitHub
// runners stack (cdk-github-runners) may pass at run time. Every value is a
// caller input.
//
// Deprecated: the stack declares its own boundaries
// (github.com/truvity/grun/boundary, Runtime and Deploy) and the caller passes
// them as Extra values. Names.Grun renders the same document as an Extra built
// from boundary.Runtime. GrunScope is kept for one release.
type GrunScope struct {
	// RolePrefix is what the names of the stack's roles start with, such as
	// "grun-": the only roles Grun may pass. The stack's roles are created by
	// the deploying human role, never by the stack's own runtime. Required.
	RolePrefix string
	// PassedToServices are the services a role may be passed to
	// (iam:PassedToService), such as "ecs-tasks.amazonaws.com". Required.
	PassedToServices []string
	// ServiceLinkedRoles are the services whose service-linked role Grun may
	// create (iam:AWSServiceName), such as "ecs.amazonaws.com". Optional: empty
	// allows none.
	ServiceLinkedRoles []string
}

func (s *Spec) validateGrun() []error {
	var errs []error

	if s.Names.Grun == "" {
		return nil
	}

	if s.Grun.RolePrefix == "" {
		errs = append(errs, errors.New("spec: Grun.RolePrefix is empty"))
	}

	if len(s.Grun.PassedToServices) == 0 {
		errs = append(errs, errors.New("spec: Grun.PassedToServices is empty"))
	}

	for name, v := range map[string][]string{
		"Grun.PassedToServices": s.Grun.PassedToServices, "Grun.ServiceLinkedRoles": s.Grun.ServiceLinkedRoles,
	} {
		for _, x := range v {
			if x == "" {
				errs = append(errs, fmt.Errorf("spec: %s has an empty entry", name))
			}
		}
	}

	return errs
}

// grun is the boundary of the roles cdk-github-runners creates (its Step
// Functions state machines and Lambda functions): everything except IAM
// writes, with two exceptions. It may pass the stack's own roles
// (Grun.RolePrefix) to Grun.PassedToServices, which is how a state machine
// starts an ECS task, and create the service-linked roles of
// Grun.ServiceLinkedRoles. It cannot create a role or a user, so it
// delegates nothing.
//
// Each exception is carved out of the deny by the key that scopes it, not
// listed beside it: an explicit Deny always wins over an Allow, and the
// absent key of a negated condition operator matches, so an action that does
// not carry the key (every other "iam:Create*") stays denied.
func (s *Spec) grun() (string, error) {
	const (
		actionPassRole   = "iam:PassRole"
		condPassedTo     = "iam:PassedToService"
		condServiceNamed = "iam:AWSServiceName"
	)

	// iamWriteDenied without the two actions that are denied below under a condition.
	writes := slices.DeleteFunc(slices.Clone(iamWriteDenied), func(a string) bool {
		return a == "iam:Pass*" || (a == "iam:Create*" && len(s.Grun.ServiceLinkedRoles) > 0)
	})

	stmts := []policy.Statement{
		allowAll(),
		{Sid: "DenyIAMWriteExceptGrun", Effect: deny, Action: writes, Resource: star()},
	}

	if len(s.Grun.ServiceLinkedRoles) > 0 {
		// iam:Create* except iam:CreateServiceLinkedRole for the allowed services.
		stmts = append(stmts, policy.Statement{
			Sid: "DenyCreateExceptServiceLinkedRole", Effect: deny, Action: []string{"iam:Create*"}, Resource: star(),
			Condition: []policy.Condition{cond("StringNotEquals", condServiceNamed, s.Grun.ServiceLinkedRoles...)},
		})
	}

	stmts = append(stmts,
		policy.Statement{
			Sid: "DenyPassRoleOutsideGrunRoles", Effect: deny, Action: []string{actionPassRole},
			NotResource: []string{s.roleARN(s.Grun.RolePrefix + "*")},
		},
		policy.Statement{
			Sid: "DenyPassRoleToOtherServices", Effect: deny, Action: []string{actionPassRole}, Resource: star(),
			Condition: []policy.Condition{cond("StringNotEquals", condPassedTo, s.Grun.PassedToServices...)},
		},
		s.denyBoundaryEdit(),
		noBoundaryDelete(),
	)

	return marshal(s.Names.Grun, stmts)
}
