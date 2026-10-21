package boundary

import (
	"fmt"

	"github.com/truvity/aws-structure/policy"
)

// roleDeployer is the deployer boundary under the role name. It is the
// legacy deploy boundary (everything, but a created role needs "project" and
// "cluster" tags and one of its delegated boundaries) plus, in the final form,
// a name rule: a role is named "<cluster>-<project>.<name>" from its own
// request tags. LegacyProjectNames renders the transition form without the
// name rule.
func (s *Spec) roleDeployer() (string, error) {
	stmts := []policy.Statement{
		allowAll(),
		{
			Sid: "DenyCreateRoleWithoutProjectTag", Effect: deny, Action: []string{actionCreateRole}, Resource: star(),
			Condition: []policy.Condition{cond("Null", "aws:RequestTag/project", "true")},
		},
		{
			Sid: "DenyCreateRoleWithoutClusterTag", Effect: deny, Action: []string{actionCreateRole}, Resource: star(),
			Condition: []policy.Condition{cond("Null", "aws:RequestTag/cluster", "true")},
		},
	}

	if !s.LegacyProjectNames {
		stmts = append(stmts, policy.Statement{
			Sid: "DenyCreateRoleOutsideProjectName", Effect: deny, Action: []string{actionCreateRole},
			NotResource: []string{fmt.Sprintf("arn:%s:iam::*:role/${aws:RequestTag/cluster}-${aws:RequestTag/project}.*", s.Partition)},
		})
	}

	stmts = append(stmts,
		denyWithoutBoundary("DenyCreateOrChangeWithoutAllowedBoundary", s.DelegateARNs(s.Names.RoleDeployer)),
		s.denyBoundaryEdit(),
		noBoundaryDelete(),
	)

	return marshal(s.Names.RoleDeployer, stmts)
}
