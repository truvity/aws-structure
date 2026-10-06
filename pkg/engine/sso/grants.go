package sso

import "sort"

// Holder is one role as it sits on one scope: the access level the scope's
// matrix gives it and the directory groups that carry the role.
type Holder struct {
	// Role is the role's name. It only feeds Grant.Role.
	Role string
	// Level is the access level the role holds on the scope. The caller's
	// own vocabulary: this package only looks it up in the table it is given.
	Level string
	// Groups are the directory groups of the role's population.
	Groups []string
}

// GrantsFor turns one scope's access matrix into the grants DeployAssignments
// expands. setOf maps an access level to the NAME of the permission set that
// level is granted (SetSpec.Name); a holder whose level is not in setOf gets
// nothing. Every group of a holder gets one grant. skip, when set, drops the
// groups that must not be assigned (placeholders, groups outside the
// synced directory).
//
// Only the top-level set is named here: a level that implies lower ones
// (admin also grants viewer) says so in SetSpec.Include, which
// DeployAssignments expands. The grants come back sorted by role, set and
// group, so the result never depends on map order; the assignment's identity
// (scope, set, group) is what DeployAssignments deduplicates on.
func GrantsFor(scope string, setOf map[string]string, holders []Holder, skip func(group string) bool) []Grant {
	var grants []Grant

	for _, h := range holders {
		set, ok := setOf[h.Level]
		if !ok {
			continue
		}

		for _, g := range h.Groups {
			if skip != nil && skip(g) {
				continue
			}

			grants = append(grants, Grant{Scope: scope, Set: set, Group: g, Role: h.Role})
		}
	}

	sort.Slice(grants, func(i, j int) bool {
		a, b := grants[i], grants[j]
		if a.Role != b.Role {
			return a.Role < b.Role
		}

		if a.Set != b.Set {
			return a.Set < b.Set
		}

		return a.Group < b.Group
	})

	return grants
}
