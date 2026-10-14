package preflight

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Resource types whose real state lives outside the stack: a replace destroys
// something Pulumi cannot put back, and a delete stops managing it while the
// next diff reads clean.
const (
	TypeAccount            = "aws:organizations/account:Account"
	TypeOrganizationalUnit = "aws:organizations/organizationalUnit:OrganizationalUnit"
	TypePermissionSet      = "aws:ssoadmin/permissionSet:PermissionSet"
	TypeOrganization       = "aws:organizations/organization:Organization"
	TypeAccountAssignment  = "aws:ssoadmin/accountAssignment:AccountAssignment"
	TypePolicyAttachment   = "aws:organizations/policyAttachment:PolicyAttachment"
)

// Guard names, as Finding.Guard reports them.
const (
	GuardIrreplaceable   = "irreplaceable"
	GuardBreakGlass      = "break-glass"
	GuardSCPOnManagement = "scp-on-management"
	GuardWaiverExpired   = "waiver-expired"
)

// irreplaceable says, per type, why a replace or delete is refused.
var irreplaceable = map[string]string{
	TypeAccount: "a replace closes the account and opens an empty one; a delete leaves it unmanaged " +
		"(remove it from state deliberately if that is the intent)",
	TypeOrganizationalUnit: "a replace moves every account out and deletes the unit; a delete leaves it unmanaged",
	TypePermissionSet: "a replace deletes the set and every assignment and provisioned role that use it; " +
		"a delete leaves it unmanaged",
	TypeOrganization: "the organization is lookup-only: nothing may replace or delete it",
}

// replaceOps are the engine ops that destroy and recreate. A preview reports a
// replacement as `replace` and splits it into create-replacement and
// delete-replaced when the steps are shown separately, so all are caught.
var replaceOps = map[string]bool{
	"replace":                true,
	"create-replacement":     true,
	"delete-replaced":        true,
	"import-replacement":     true,
	"discard-replaced":       true,
	"remove-pending-replace": true,
}

// deleteOps destroy without recreating.
var deleteOps = map[string]bool{
	"delete":  true,
	"discard": true,
}

// attachOps put a policy on a target.
var attachOps = map[string]bool{
	"create":             true,
	"update":             true,
	"replace":            true,
	"create-replacement": true,
	"import":             true,
}

// Finding is one refusal.
type Finding struct {
	// Guard is the guard that refused.
	Guard string
	// Subject is what it refused: a URN, an account, a target.
	Subject string
	// Message says why.
	Message string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s: %s: %s", f.Guard, f.Subject, f.Message)
}

// Err joins findings into one error, or returns nil when there are none.
func Err(findings []Finding) error {
	if len(findings) == 0 {
		return nil
	}

	sorted := append([]Finding(nil), findings...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Guard != sorted[j].Guard {
			return sorted[i].Guard < sorted[j].Guard
		}

		return sorted[i].Subject < sorted[j].Subject
	})

	errs := make([]error, len(sorted))
	for i, f := range sorted {
		errs[i] = errors.New("preflight: " + f.String())
	}

	return errors.Join(errs...)
}

// Step is one planned operation on one resource.
type Step struct {
	// Op is the engine op: create, update, same, delete, replace,
	// create-replacement, delete-replaced, ...
	Op string
	// URN and Type identify the resource.
	URN  string
	Type string
	// Old and New are the inputs before and after; either may be nil.
	Old map[string]any
	New map[string]any
}

// BreakGlassAssignment identifies the break-glass account assignments in a
// plan by their inputs. Both fields are required for the guard to run: an
// assignment matches when its permissionSetArn and principalId both equal
// them.
type BreakGlassAssignment struct {
	PermissionSetARN string
	PrincipalID      string
}

// PlanOpts configures Plan.
type PlanOpts struct {
	// BreakGlass identifies the break-glass assignments; nil skips that
	// guard (Lockout still requires the registry to declare one).
	BreakGlass *BreakGlassAssignment
	// ProtectedTargets are the ids a policy attachment must not land on
	// without a waiver, mapped to their name for messages and waivers: the
	// organization root ("r-..."), the management account and every OU above
	// it. ProtectedTargets(registry) builds it from a registry.
	ProtectedTargets map[string]string
	// Waived reports whether the target (by name) has a valid waiver of
	// GuardSCPOnManagement. Nil means none has.
	Waived func(target string) bool
}

// Plan judges the steps of a preview and returns every refusal.
func Plan(steps []Step, o PlanOpts) []Finding {
	var out []Finding

	seen := map[string]bool{}
	add := func(f Finding) {
		key := f.Guard + "\x00" + f.Subject
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}

	for _, s := range steps {
		if reason, ok := irreplaceable[s.Type]; ok && (replaceOps[s.Op] || deleteOps[s.Op]) {
			add(Finding{Guard: GuardIrreplaceable, Subject: s.URN, Message: fmt.Sprintf("%s planned: %s", opKind(s.Op), reason)})
		}

		if s.Type == TypeAccountAssignment && o.BreakGlass != nil && (replaceOps[s.Op] || deleteOps[s.Op]) &&
			o.BreakGlass.matches(s.Old) {
			add(Finding{
				Guard: GuardBreakGlass, Subject: s.URN,
				Message: opKind(s.Op) + " of a break-glass assignment planned: it is the way back into the account",
			})
		}

		if s.Type == TypePolicyAttachment && attachOps[s.Op] {
			target := str(s.New, "targetId")
			if name, ok := o.ProtectedTargets[target]; ok && (o.Waived == nil || !o.Waived(name)) {
				add(Finding{
					Guard: GuardSCPOnManagement, Subject: s.URN,
					Message: fmt.Sprintf("a policy attachment on %s (%s) without a %s waiver can lock the management account out",
						name, target, GuardSCPOnManagement),
				})
			}
		}
	}

	return out
}

func (b *BreakGlassAssignment) matches(inputs map[string]any) bool {
	if b.PermissionSetARN == "" || b.PrincipalID == "" {
		return false
	}

	return str(inputs, "permissionSetArn") == b.PermissionSetARN && str(inputs, "principalId") == b.PrincipalID
}

func opKind(op string) string {
	if replaceOps[op] {
		return "replace (" + op + ")"
	}

	return strings.ToLower(op)
}

func str(m map[string]any, key string) string {
	if m == nil {
		return ""
	}

	s, _ := m[key].(string)

	return s
}
