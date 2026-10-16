package preflight

import (
	"fmt"
	"slices"
	"time"

	"github.com/truvity/aws-structure/pkg/registry"
)

// Lockout judges a validated registry against the lockout guards and returns
// every refusal. now decides which waivers have expired.
//
//   - The registry must declare identity_center.break_glass, and an
//     assignment of that principal and permission set must reach every
//     account, directly or through an OU at any depth.
//   - The management account and every OU above it must carry no service
//     control policy without a waiver of GuardSCPOnManagement for it. (In v1
//     policies are dormant; the guard holds the line before they are not.)
//   - A waiver past its expiry date is refused, and so is a waiver for an
//     OU or account that carries no policy: an exception must not outlive its
//     cause.
func Lockout(reg *registry.Registry, now time.Time) []Finding {
	var out []Finding

	out = append(out, breakGlassReach(reg)...)

	waived := Waived(reg, now)
	chain := managementChain(reg)

	for _, name := range chain {
		if scps := attached(reg, name); len(scps) > 0 && !waived(name) {
			out = append(out, Finding{
				Guard: GuardSCPOnManagement, Subject: name,
				Message: fmt.Sprintf("carries %v above or on the management account without a %s waiver",
					scps, registry.GuardSCPOnManagement),
			})
		}
	}

	today := day(now)

	for _, w := range reg.Waivers {
		if w.Expires != "" && w.Expires < today {
			out = append(out, Finding{
				Guard: GuardWaiverExpired, Subject: w.Target,
				Message: fmt.Sprintf("the %s waiver expired on %s (exit condition: %s); renew it with a reason or remove its cause",
					w.Guard, w.Expires, w.ExitCondition),
			})

			continue
		}

		if w.Guard == registry.GuardSCPOnManagement && w.Target != registry.WaiverTargetRoot &&
			(!slices.Contains(chain, w.Target) || len(attached(reg, w.Target)) == 0) {
			out = append(out, Finding{
				Guard: GuardWaiverExpired, Subject: w.Target,
				Message: "the waiver has nothing left to waive (no policy on it, or it is not above the management account); remove it",
			})
		}
	}

	return out
}

func breakGlassReach(reg *registry.Registry) []Finding {
	bg := reg.IdentityCenter.BreakGlass
	if bg == nil {
		return []Finding{{
			Guard: GuardBreakGlass, Subject: "identity_center.break_glass",
			Message: "not declared: the lockout guard needs the principal and permission set that must reach every account",
		}}
	}

	parent := map[string]string{}
	for _, o := range reg.OUs {
		parent[o.Name] = o.Parent
	}

	reached, reachedOUs := map[string]bool{}, map[string]bool{}

	for _, a := range reg.IdentityCenter.Assignments {
		if a.Principal != bg.Principal || a.PrincipalType != bg.PrincipalType || a.PermissionSet != bg.PermissionSet {
			continue
		}

		for _, n := range a.Accounts {
			reached[n] = true
		}

		for _, n := range a.OUs {
			reachedOUs[n] = true
		}
	}

	var out []Finding

	for _, acct := range reg.Accounts {
		if reached[acct.Name] || acct.Closed {
			continue
		}

		ok := false

		for ou, seen := acct.OU, map[string]bool{}; ou != "" && !seen[ou]; ou = parent[ou] {
			seen[ou] = true

			if reachedOUs[ou] {
				ok = true

				break
			}
		}

		if !ok {
			out = append(out, Finding{
				Guard: GuardBreakGlass, Subject: acct.Name,
				Message: fmt.Sprintf("no assignment of %s %q with permission set %q reaches this account",
					bg.PrincipalType, bg.Principal, bg.PermissionSet),
			})
		}
	}

	return out
}

// managementChain is the management account's name followed by its OU and
// every OU above it.
func managementChain(reg *registry.Registry) []string {
	mgmt := reg.Organization.ManagementAccount

	idx := slices.IndexFunc(reg.Accounts, func(a registry.Account) bool { return a.Name == mgmt })
	if idx < 0 {
		return nil
	}

	parent := map[string]string{}
	for _, o := range reg.OUs {
		parent[o.Name] = o.Parent
	}

	chain := []string{mgmt}

	for ou, seen := reg.Accounts[idx].OU, map[string]bool{}; ou != "" && !seen[ou]; ou = parent[ou] {
		seen[ou] = true
		chain = append(chain, ou)
	}

	return chain
}

// attached returns the policies declared on the OU or account named name.
func attached(reg *registry.Registry, name string) []string {
	for _, a := range reg.Accounts {
		if a.Name == name {
			return a.SCPs
		}
	}

	for _, o := range reg.OUs {
		if o.Name == name {
			return o.SCPs
		}
	}

	return nil
}

// Waived returns whether a target (by name) has a waiver of
// GuardSCPOnManagement that has not expired at now.
func Waived(reg *registry.Registry, now time.Time) func(target string) bool {
	today := day(now)

	return func(target string) bool {
		return slices.ContainsFunc(reg.Waivers, func(w registry.Waiver) bool {
			return w.Guard == registry.GuardSCPOnManagement && w.Target == target && (w.Expires == "" || w.Expires >= today)
		})
	}
}

// ProtectedTargets maps the ids a policy attachment must not land on without a
// waiver to their names: the organization root (named "root"), the
// management account and every OU above it, for those whose id the registry
// records.
func ProtectedTargets(reg *registry.Registry) map[string]string {
	out := map[string]string{}
	if reg.Organization.RootID != "" {
		out[reg.Organization.RootID] = registry.WaiverTargetRoot
	}

	for _, name := range managementChain(reg) {
		for _, a := range reg.Accounts {
			if a.Name == name && a.ID != "" {
				out[a.ID] = name
			}
		}

		for _, o := range reg.OUs {
			if o.Name == name && o.ID != "" {
				out[o.ID] = name
			}
		}
	}

	return out
}

func day(t time.Time) string { return t.UTC().Format(registry.DateLayout) }
