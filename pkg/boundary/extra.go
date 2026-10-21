package boundary

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/truvity/aws-structure/pkg/registry"
	"github.com/truvity/aws-structure/policy"
)

// Extra is a boundary a component declares and the caller passes in: the
// component knows what its principals need, this package knows what the estate
// requires of every boundary. The Document is the component's part only; Policies
// appends the estate's guards to a copy of it:
//
//   - DenyBoundaryPolicyEdit and NoBoundaryDelete, as on every other boundary;
//   - for a boundary with Delegates, DenyCreateOrChangeWithoutAllowedBoundary,
//     which refuses creating a role or user, and putting a boundary on one,
//     under any boundary but the exact names in Delegates;
//   - for a leaf (no Delegates), the same deny without an exception, unless the
//     Document already denies iam:CreateRole, iam:CreateUser,
//     iam:PutRolePermissionsBoundary and iam:PutUserPermissionsBoundary for
//     every resource by an explicit Deny (a Deny with a condition counts: the
//     component carved out its own exception, as the runners' Runtime does for
//     the service-linked role). A leaf can never mint a role that is not
//     bounded.
//
// A Document that uses the Sid of one of these statements is refused, and so is
// one that does not validate (policy.Document.Validate) or whose final form is
// over IAM's 6,144 characters.
type Extra struct {
	// Name is the policy name: it starts with Spec.ClassPrefix, holds no
	// wildcard, is at most 128 characters, and is not the name of any other
	// boundary of the Spec.
	Name string
	// Document is the component's statements.
	Document policy.Document
	// DelegatedBy are the boundaries that may attach this one, each of them in
	// Spec.ExtraDelegators. Each gets the exact Name added to its delegates.
	DelegatedBy []string
	// Delegates are the boundaries a role under this one may create roles
	// under, by exact name. Each is a boundary of the Spec (a built-in's hierarchy
	// entry or another Extra). Empty makes this boundary a leaf.
	Delegates []string
	// Accounts limits the boundary to the named accounts (see Spec.Account).
	// Empty means every account.
	Accounts []string
}

const (
	// sidDelegation is the Sid of the delegation guard on an Extra.
	sidDelegation = "DenyCreateOrChangeWithoutAllowedBoundary"

	// maxPolicyName is IAM's limit on the length of a policy name.
	maxPolicyName = 128

	// MaxDocumentSize is IAM's limit on a managed policy document, in
	// characters of the minified document. Policies refuses a boundary over it.
	MaxDocumentSize = 6144
)

// reservedSids are the Sids of the statements Policies appends to an Extra.
var reservedSids = []string{sidDenyBoundaryEdit, sidNoBoundaryDelete, sidDelegation}

// creationActions are what a leaf boundary must keep from minting a role.
var creationActions = []string{actionCreateRole, actionCreateUser, actionPutRoleBoundary, actionPutUserBoundary}

// extras returns the Extra values rendered for s.Account.
func (s *Spec) extras() []Extra {
	if s.Account == "" {
		return s.Extra
	}

	var out []Extra

	for i := range s.Extra {
		if len(s.Extra[i].Accounts) == 0 || slices.Contains(s.Extra[i].Accounts, s.Account) {
			out = append(out, s.Extra[i])
		}
	}

	return out
}

// extraDelegators returns Spec.ExtraDelegators, or the default.
func (s *Spec) extraDelegators() []string {
	if len(s.ExtraDelegators) > 0 {
		return s.ExtraDelegators
	}

	if s.Names.RoleAdmin == "" {
		return nil
	}

	return []string{s.Names.RoleAdmin}
}

// hierarchy returns the delegation graph the documents are built from: the
// Spec's Hierarchy, one entry for each Extra, and each delegator's list
// extended by the Extra values it delegates. The Spec is not changed.
func (s *Spec) hierarchy() []Entry {
	out := make([]Entry, 0, len(s.Hierarchy)+len(s.Extra))

	for _, e := range s.Hierarchy {
		e.Delegates = slices.Clone(e.Delegates)
		out = append(out, e)
	}

	extras := s.extras()

	for i := range extras {
		out = append(out, Entry{Name: extras[i].Name, Delegates: slices.Clone(extras[i].Delegates)})
	}

	for i := range extras {
		for _, by := range extras[i].DelegatedBy {
			for j := range out {
				if out[j].Name == by && !slices.Contains(out[j].Delegates, extras[i].Name) {
					out[j].Delegates = append(out[j].Delegates, extras[i].Name)
				}
			}
		}
	}

	return out
}

// builtinNames returns every boundary name the Names fields give.
func (s *Spec) builtinNames() map[string]bool {
	out := map[string]bool{s.Names.Default: true, s.Names.EKSAutoNode: true, s.Names.Grun: true}

	for _, n := range append(s.legacyNames(), s.currentNames()...) {
		out[n[1]] = true
	}

	delete(out, "")

	return out
}

// validateExtras checks the Extra values and the delegator allow list. The
// graph itself (undefined delegates, patterns, cycles) is checked by
// validateHierarchy over the hierarchy that includes them.
func (s *Spec) validateExtras() []error {
	if len(s.Extra) == 0 {
		return nil
	}

	var errs []error

	if s.ClassPrefix == "" {
		errs = append(errs, errors.New("spec: ClassPrefix is empty, and Extra boundary names must start with it"))
	} else if !strings.HasPrefix(s.ClassPrefix, s.Prefix) {
		errs = append(errs, fmt.Errorf("spec: ClassPrefix %q does not extend Prefix %q", s.ClassPrefix, s.Prefix))
	}

	delegators := s.extraDelegators()
	if len(delegators) == 0 {
		errs = append(errs, errors.New("spec: Extra boundaries need a delegator: set ExtraDelegators or Names.RoleAdmin"))
	}

	for _, d := range delegators {
		if d == "" || strings.ContainsAny(d, "*?") {
			errs = append(errs, fmt.Errorf("spec: ExtraDelegators entry %q is not an exact boundary name", d))
		}
	}

	builtin := s.builtinNames()
	listed := map[string]bool{}

	for _, e := range s.Hierarchy {
		listed[e.Name] = true
	}

	seen := map[string]bool{}

	// The boundaries a delegator may be: the Hierarchy's and the Extra values.
	known := maps.Clone(listed)
	for i := range s.Extra {
		known[s.Extra[i].Name] = true
	}

	for i := range s.Extra {
		errs = append(errs, s.validateExtra(&s.Extra[i], builtin, listed, seen, known, delegators)...)
	}

	return errs
}

func (s *Spec) validateExtra(e *Extra, builtin, listed, seen, known map[string]bool, delegators []string) []error {
	var errs []error

	label := fmt.Sprintf("spec: Extra %q", e.Name)

	switch {
	case e.Name == "":
		return append(errs, errors.New("spec: an Extra has no Name"))
	case strings.ContainsAny(e.Name, "*?"):
		errs = append(errs, fmt.Errorf("%s: the name holds a wildcard: boundaries are named exactly", label))
	case len(e.Name) > maxPolicyName:
		errs = append(errs, fmt.Errorf("%s: the name is %d characters, IAM allows %d", label, len(e.Name), maxPolicyName))
	case !validPolicyName(e.Name):
		errs = append(errs, fmt.Errorf("%s: the name has a character IAM does not allow in a policy name", label))
	}

	if s.ClassPrefix != "" && (!strings.HasPrefix(e.Name, s.ClassPrefix) || len(e.Name) <= len(s.ClassPrefix)) {
		errs = append(errs, fmt.Errorf("%s: the name must start with the class prefix %q and add to it", label, s.ClassPrefix))
	}

	switch {
	case builtin[e.Name]:
		errs = append(errs, fmt.Errorf("%s: the name is a built-in boundary", label))
	case listed[e.Name]:
		errs = append(errs, fmt.Errorf("%s: the name is also an entry of Hierarchy: declare its edges on the Extra", label))
	case seen[e.Name]:
		errs = append(errs, fmt.Errorf("%s: declared twice", label))
	}

	seen[e.Name] = true

	for _, by := range e.DelegatedBy {
		switch {
		case !slices.Contains(delegators, by):
			errs = append(errs, fmt.Errorf("%s: delegated by %q, which is not in ExtraDelegators %v", label, by, delegators))
		case !known[by]:
			errs = append(errs, fmt.Errorf("%s: delegated by %q, which is not a boundary of the Spec (no Hierarchy entry)", label, by))
		}
	}

	for _, a := range e.Accounts {
		if a == "" {
			errs = append(errs, fmt.Errorf("%s: Accounts has an empty entry", label))
		}
	}

	if err := e.Document.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("%s: document: %w", label, err))
	}

	for i := range e.Document.Statement {
		if slices.Contains(reservedSids, e.Document.Statement[i].Sid) {
			errs = append(errs, fmt.Errorf("%s: the document uses the Sid %q, which is reserved for the estate's guard", label, e.Document.Statement[i].Sid))
		}
	}

	return errs
}

// validPolicyName reports whether name is made of what IAM allows in a policy
// name: letters, digits and + = , . @ _ -.
func validPolicyName(name string) bool {
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("+=,.@_-", r):
		default:
			return false
		}
	}

	return name != ""
}

// extra returns the final document of e: its statements, then the guards.
// The Extra is not changed.
func (s *Spec) extra(e *Extra) (string, error) {
	stmts := slices.Clone(e.Document.Statement)

	if len(e.Delegates) > 0 {
		stmts = append(stmts, denyWithoutBoundary(sidDelegation, s.DelegateARNs(e.Name)))
	} else if !deniesCreation(e.Document) {
		stmts = append(stmts, denyCreation(sidDelegation))
	}

	stmts = append(stmts, s.denyBoundaryEdit(), noBoundaryDelete())

	return marshal(e.Name, stmts)
}

// denyCreation is the guard of a leaf: no role or user may be created, and no
// boundary put on one.
func denyCreation(sid string) policy.Statement {
	return policy.Statement{
		Sid: sid, Effect: deny, Action: slices.Clone(creationActions), Resource: star(),
	}
}

// deniesCreation reports whether d already denies every action a leaf must not
// take, by an explicit Deny for every resource. A condition on the Deny is the
// component's own carve-out and is accepted. The check is by the action names
// and patterns of the statements; it does not evaluate IAM.
func deniesCreation(d policy.Document) bool {
	for _, action := range creationActions {
		if !denies(d, action) {
			return false
		}
	}

	return true
}

func denies(d policy.Document, action string) bool {
	for i := range d.Statement {
		s := &d.Statement[i]

		if s.Effect != deny || len(s.NotAction) > 0 || len(s.NotResource) > 0 || !slices.Contains(s.Resource, "*") {
			continue
		}

		for _, p := range s.Action {
			if globMatch(p, action) {
				return true
			}
		}
	}

	return false
}

// globMatch matches an IAM action pattern (* any run, ? one character; IAM
// compares actions without regard to case) against an action.
func globMatch(pattern, s string) bool {
	p, t := strings.ToLower(pattern), strings.ToLower(s)

	var pi, ti, star, mark int

	star = -1

	for ti < len(t) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == t[ti]):
			pi++
			ti++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, ti
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			ti = mark
		default:
			return false
		}
	}

	for pi < len(p) && p[pi] == '*' {
		pi++
	}

	return pi == len(p)
}

// extraPolicies renders the Extra values, in the order given.
func (s *Spec) extraPolicies() ([]registry.Boundary, []error) {
	var (
		out  []registry.Boundary
		errs []error
	)

	extras := s.extras()

	for i := range extras {
		doc, err := s.extra(&extras[i])
		if err != nil {
			errs = append(errs, err)

			continue
		}

		out = append(out, registry.Boundary{Name: extras[i].Name, Document: doc})
	}

	return out, errs
}

// checkSizes refuses a document over IAM's limit.
func checkSizes(bs []registry.Boundary) []error {
	var errs []error

	for _, b := range bs {
		if len(b.Document) > MaxDocumentSize {
			errs = append(errs, fmt.Errorf("boundary %s: the document is %d characters minified, over IAM's limit of %d",
				b.Name, len(b.Document), MaxDocumentSize))
		}
	}

	return errs
}
