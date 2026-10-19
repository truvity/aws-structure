package boundary

import "fmt"

// roleDeployer is the deployer boundary under the role name. It is the
// legacy deploy boundary (everything, but a created role needs "project" and
// "cluster" tags and one of its delegated boundaries) plus, in the final form,
// a name rule: a role is named "<cluster>-<project>.<name>" from its own
// request tags. LegacyProjectNames renders the transition form without the
// name rule.
func (s *Spec) roleDeployer() (string, error) {
	stmts := []statement{
		allowAll(),
		{
			Sid: "DenyCreateRoleWithoutProjectTag", Effect: deny, Action: actionCreateRole, Resource: "*",
			Condition: map[string]any{"Null": map[string]any{"aws:RequestTag/project": "true"}},
		},
		{
			Sid: "DenyCreateRoleWithoutClusterTag", Effect: deny, Action: actionCreateRole, Resource: "*",
			Condition: map[string]any{"Null": map[string]any{"aws:RequestTag/cluster": "true"}},
		},
	}

	if !s.LegacyProjectNames {
		stmts = append(stmts, statement{
			Sid: "DenyCreateRoleOutsideProjectName", Effect: deny, Action: actionCreateRole,
			NotResource: fmt.Sprintf("arn:%s:iam::*:role/${aws:RequestTag/cluster}-${aws:RequestTag/project}.*", s.Partition),
		})
	}

	stmts = append(stmts,
		denyWithoutBoundary("DenyCreateOrChangeWithoutAllowedBoundary", s.DelegateARNs(s.Names.RoleDeployer)),
		s.denyBoundaryEdit(),
		noBoundaryDelete(),
	)

	return marshal(s.Names.RoleDeployer, document{Version: policyVersion, Statement: stmts})
}
