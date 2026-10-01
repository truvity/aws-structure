package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
)

const (
	// SCPDormant is the only enforcement mode v1 accepts.
	SCPDormant = "dormant"
	// SCPEnforced attaches policies. Refused until a lockout check exists
	// (docs/decisions/0002-safety.md).
	SCPEnforced = "enforced"

	// MaxSCPBytes is AWS's cap on a service control policy document.
	MaxSCPBytes = 5120
	// MaxInlinePolicyBytes is AWS's cap on a permission set's inline policy.
	MaxInlinePolicyBytes = 10240
)

var (
	accountID  = regexp.MustCompile(`^[0-9]{12}$`)
	orgID      = regexp.MustCompile(`^o-[a-z0-9]{10,32}$`)
	rootID     = regexp.MustCompile(`^r-[a-z0-9]{4,32}$`)
	ouID       = regexp.MustCompile(`^ou-[a-z0-9]{4,32}-[a-z0-9]{8,32}$`)
	duration   = regexp.MustCompile(`^PT([0-9]+H)?([0-9]+M)?$`)
	emailShape = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
)

// Validate reports every problem in the registry, joined, or nil. It never
// mutates the registry.
func (r *Registry) Validate() error {
	v := &validator{}
	v.organization(r)
	v.ous(r)
	v.accounts(r)
	v.scps(r)
	v.identityCenter(r)
	v.baseline(r)
	return errors.Join(v.errs...)
}

type validator struct{ errs []error }

func (v *validator) errf(format string, args ...any) {
	v.errs = append(v.errs, fmt.Errorf("registry: "+format, args...))
}

// unique reports a duplicate or empty name in a list and returns the set.
func (v *validator) unique(kind string, names []string) map[string]bool {
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		switch {
		case n == "":
			v.errf("%s with an empty name", kind)
		case seen[n]:
			v.errf("duplicate %s name %q", kind, n)
		}
		seen[n] = true
	}
	return seen
}

func (v *validator) organization(r *Registry) {
	o := r.Organization
	if o.Manage {
		v.errf("organization.manage is true: the organization is lookup-only in v1 (docs/decisions/0001-shape.md)")
	}
	if !orgID.MatchString(o.ID) {
		v.errf("organization.id %q is not an organization id (o-...)", o.ID)
	}
	if !rootID.MatchString(o.RootID) {
		v.errf("organization.root_id %q is not a root id (r-...)", o.RootID)
	}
	if o.ManagementAccount == "" {
		v.errf("organization.management_account is required")
	} else if !slices.ContainsFunc(r.Accounts, func(a Account) bool { return a.Name == o.ManagementAccount }) {
		v.errf("organization.management_account %q is not a declared account", o.ManagementAccount)
	}
}

func (v *validator) ous(r *Registry) {
	names := make([]string, len(r.OUs))
	for i, o := range r.OUs {
		names[i] = o.Name
	}
	set := v.unique("ou", names)
	parent := map[string]string{}
	for _, o := range r.OUs {
		if o.Reason == "" {
			v.errf("ou %q has no reason", o.Name)
		}
		if o.ID != "" && !ouID.MatchString(o.ID) {
			v.errf("ou %q: id %q is not an OU id", o.Name, o.ID)
		}
		if o.Parent != "" && !set[o.Parent] {
			v.errf("ou %q: parent %q is not a declared OU", o.Name, o.Parent)
		}
		if o.Parent == o.Name && o.Name != "" {
			v.errf("ou %q is its own parent", o.Name)
		}
		parent[o.Name] = o.Parent
	}
	for _, o := range r.OUs {
		seen := map[string]bool{}
		for cur := o.Name; cur != ""; cur = parent[cur] {
			if seen[cur] {
				v.errf("ou %q is in a parent cycle", o.Name)
				break
			}
			seen[cur] = true
		}
	}
	v.scpRefs(r, "ou", func(yield func(string, []string)) {
		for _, o := range r.OUs {
			yield(o.Name, o.SCPs)
		}
	})
}

func (v *validator) accounts(r *Registry) {
	names := make([]string, len(r.Accounts))
	for i, a := range r.Accounts {
		names[i] = a.Name
	}
	v.unique("account", names)

	ous := map[string]bool{}
	for _, o := range r.OUs {
		ous[o.Name] = true
	}
	ids, emails := map[string]string{}, map[string]string{}
	for _, a := range r.Accounts {
		switch {
		case a.OU == "":
			v.errf("account %q has no ou: every account sits in an OU", a.Name)
		case !ous[a.OU]:
			v.errf("account %q: ou %q is not a declared OU", a.Name, a.OU)
		}
		if a.ID != "" {
			if !accountID.MatchString(a.ID) {
				v.errf("account %q: id %q is not 12 digits", a.Name, a.ID)
			} else if prev, dup := ids[a.ID]; dup {
				v.errf("accounts %q and %q share id %q", prev, a.Name, a.ID)
			}
			ids[a.ID] = a.Name
		}
		if !emailShape.MatchString(a.Email) {
			v.errf("account %q: email %q is not an address", a.Name, a.Email)
		} else if prev, dup := emails[a.Email]; dup {
			v.errf("accounts %q and %q share email %q", prev, a.Name, a.Email)
		}
		emails[a.Email] = a.Name
	}
	v.scpRefs(r, "account", func(yield func(string, []string)) {
		for _, a := range r.Accounts {
			yield(a.Name, a.SCPs)
		}
	})
}

func (v *validator) scpRefs(r *Registry, kind string, each func(func(string, []string))) {
	known := map[string]bool{}
	for _, s := range r.SCPs {
		known[s.Name] = true
	}
	each(func(owner string, refs []string) {
		for _, ref := range refs {
			if !known[ref] {
				v.errf("%s %q attaches unknown scp %q", kind, owner, ref)
			}
		}
	})
}

func (v *validator) scps(r *Registry) {
	switch r.SCPEnforcement {
	case SCPDormant:
	case SCPEnforced:
		v.errf("scp_enforcement %q is refused in v1: SCPs stay dormant until a lockout check exists (docs/decisions/0002-safety.md)", SCPEnforced)
	default:
		v.errf("scp_enforcement %q is not %q", r.SCPEnforcement, SCPDormant)
	}
	names := make([]string, len(r.SCPs))
	for i, s := range r.SCPs {
		names[i] = s.Name
	}
	v.unique("scp", names)
	for _, s := range r.SCPs {
		v.policyDocument("scp "+fmt.Sprintf("%q", s.Name), s.Document, MaxSCPBytes)
	}
}

// policyDocument checks a policy is valid JSON within an AWS size cap.
func (v *validator) policyDocument(what, doc string, limit int) {
	if len(doc) > limit {
		v.errf("%s is %d bytes, over the %d-byte limit", what, len(doc), limit)
	}
	var probe map[string]any
	if err := json.Unmarshal([]byte(doc), &probe); err != nil {
		v.errf("%s is not a JSON object: %v", what, err)
	}
}

func (v *validator) identityCenter(r *Registry) {
	ic := r.IdentityCenter

	groupNames := make([]string, len(ic.Groups))
	for i, g := range ic.Groups {
		groupNames[i] = g.Name
		if g.Source != "manual" && g.Source != "sync" {
			v.errf("group %q: source %q is not manual or sync", g.Name, g.Source)
		}
	}
	groups := v.unique("group", groupNames)

	psNames := make([]string, len(ic.PermissionSets))
	for i, p := range ic.PermissionSets {
		psNames[i] = p.Name
	}
	sets := v.unique("permission set", psNames)

	include := map[string][]string{}
	for _, p := range ic.PermissionSets {
		if p.SessionDuration != "" && !duration.MatchString(p.SessionDuration) {
			v.errf("permission set %q: session_duration %q is not an ISO-8601 PT..H..M duration", p.Name, p.SessionDuration)
		}
		if p.InlinePolicy != "" {
			v.policyDocument(fmt.Sprintf("permission set %q inline_policy", p.Name), p.InlinePolicy, MaxInlinePolicyBytes)
		}
		for _, inc := range p.Includes {
			if !sets[inc] {
				v.errf("permission set %q includes unknown permission set %q", p.Name, inc)
			}
		}
		include[p.Name] = p.Includes
	}
	v.includeCycles(include)

	accounts, ous := map[string]bool{}, map[string]bool{}
	for _, a := range r.Accounts {
		accounts[a.Name] = true
	}
	for _, o := range r.OUs {
		ous[o.Name] = true
	}
	for i, a := range ic.Assignments {
		at := fmt.Sprintf("assignment %d (%q)", i, a.Principal)
		switch a.PrincipalType {
		case "group":
			if !groups[a.Principal] {
				v.errf("%s: group %q is not declared", at, a.Principal)
			}
		case "user":
			if a.Principal == "" {
				v.errf("%s: empty principal", at)
			}
		default:
			v.errf("%s: principal_type %q is not group or user", at, a.PrincipalType)
		}
		if !sets[a.PermissionSet] {
			v.errf("%s: permission set %q is not declared", at, a.PermissionSet)
		}
		if len(a.Accounts)+len(a.OUs) == 0 {
			v.errf("%s: no accounts and no ous", at)
		}
		for _, n := range a.Accounts {
			if !accounts[n] {
				v.errf("%s: account %q is not declared", at, n)
			}
		}
		for _, n := range a.OUs {
			if !ous[n] {
				v.errf("%s: ou %q is not declared", at, n)
			}
		}
	}
}

// includeCycles reports every permission set that can reach itself.
func (v *validator) includeCycles(include map[string][]string) {
	names := make([]string, 0, len(include))
	for n := range include {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, start := range names {
		seen := map[string]bool{}
		stack := slices.Clone(include[start])
		for len(stack) > 0 {
			cur := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if cur == start {
				v.errf("permission set %q includes itself through a cycle", start)
				break
			}
			if seen[cur] {
				continue
			}
			seen[cur] = true
			stack = append(stack, include[cur]...)
		}
	}
}

func (v *validator) baseline(r *Registry) {
	b := r.Baseline
	if p := b.PasswordPolicy; p != nil {
		if p.MinimumLength < 8 || p.MinimumLength > 128 {
			v.errf("baseline.password_policy.minimum_length %d is outside 8..128", p.MinimumLength)
		}
		if p.MaxAgeDays < 0 || p.MaxAgeDays > 1095 {
			v.errf("baseline.password_policy.max_age_days %d is outside 0..1095", p.MaxAgeDays)
		}
		if p.ReusePrevention < 0 || p.ReusePrevention > 24 {
			v.errf("baseline.password_policy.reuse_prevention %d is outside 0..24", p.ReusePrevention)
		}
	}
	if b.EBSDefaultEncryption && len(b.Regions) == 0 {
		v.errf("baseline.ebs_default_encryption needs baseline.regions: the regions are the caller's, never defaulted")
	}
	if a := b.AuditorRole; a != nil {
		if a.Name == "" {
			v.errf("baseline.auditor_role.name is required")
		}
		if !slices.ContainsFunc(r.Accounts, func(x Account) bool { return x.Name == a.TrustedAccount }) {
			v.errf("baseline.auditor_role.trusted_account %q is not a declared account", a.TrustedAccount)
		}
	}
	names := make([]string, len(b.Boundaries))
	for i, bd := range b.Boundaries {
		names[i] = bd.Name
	}
	v.unique("boundary", names)
	for _, bd := range b.Boundaries {
		v.policyDocument(fmt.Sprintf("boundary %q", bd.Name), bd.Document, MaxInlinePolicyBytes)
	}
}
