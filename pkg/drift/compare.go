package drift

import (
	"fmt"
	"sort"
	"strings"

	"github.com/truvity/aws-structure/pkg/registry"
)

// Finding kinds.
const (
	KindUnmanaged    = "unmanaged"     // exists in AWS, not in the registry
	KindMissing      = "missing"       // in the registry (with an id), not in AWS
	KindMoved        = "moved"         // under a different parent than declared
	KindEdited       = "edited"        // a declared attribute differs
	KindUnrecordedID = "unrecorded-id" // exists, but the registry has no id for it yet
	KindNotActive    = "not-active"    // a declared account that is suspended or closed
)

// awsDefaultPolicy is the policy AWS attaches to every target of an
// organization with service control policies enabled.
const awsDefaultPolicy = "FullAWSAccess"

// Finding is one difference between the registry and AWS.
type Finding struct {
	Kind string
	// What is the kind of thing: account, ou, scp-attachment,
	// permission-set, assignment.
	What string
	// Subject names it.
	Subject string
	// Detail says what differs.
	Detail string
}

func (f Finding) String() string {
	s := fmt.Sprintf("%s %s %s", f.Kind, f.What, f.Subject)
	if f.Detail != "" {
		s += ": " + f.Detail
	}

	return s
}

// Compare returns every difference between the registry and what Read found,
// sorted.
func Compare(reg *registry.Registry, live *Live) []Finding {
	c := &comparer{reg: reg, live: live, ouID: map[string]string{}, acctID: map[string]string{}, closed: map[string]bool{}}
	for _, a := range reg.Accounts {
		c.closed[a.Name] = a.Closed
	}

	c.ous()
	c.accounts()
	c.policies()
	c.permissionSets()
	c.assignments()

	sort.Slice(c.out, func(i, j int) bool {
		a, b := c.out[i], c.out[j]
		if a.What != b.What {
			return a.What < b.What
		}

		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}

		return a.Subject < b.Subject
	})

	return c.out
}

type comparer struct {
	reg  *registry.Registry
	live *Live
	out  []Finding
	// ouID and acctID map registry names to the live ids they matched.
	ouID, acctID map[string]string
	// closed holds the names of the accounts the registry declares closed.
	closed map[string]bool
}

func (c *comparer) add(kind, what, subject, detail string) {
	c.out = append(c.out, Finding{Kind: kind, What: what, Subject: subject, Detail: detail})
}

// parentID is the live id of a registry parent name ("" is the root).
func (c *comparer) parentID(name string) string {
	if name == "" || name == registry.OURoot {
		return c.live.RootID
	}

	return c.ouID[name]
}

func (c *comparer) ous() {
	byID := map[string]LiveOU{}
	for _, o := range c.live.OUs {
		byID[o.ID] = o
	}

	matched := map[string]bool{}

	// Parents first, so a child's parent id is known when it is matched.
	for _, o := range orderOUs(c.reg.OUs) {
		if o.ID != "" {
			l, ok := byID[o.ID]
			if !ok {
				c.add(KindMissing, "ou", o.Name, "id "+o.ID+" not found")

				continue
			}

			matched[l.ID] = true
			c.ouID[o.Name] = l.ID

			if l.Name != o.Name {
				c.add(KindEdited, "ou", o.Name, fmt.Sprintf("named %q in AWS", l.Name))
			}

			if want := c.parentID(o.Parent); want != "" && l.ParentID != want {
				c.add(KindMoved, "ou", o.Name, fmt.Sprintf("parent %s, declared %s", l.ParentID, want))
			}

			continue
		}

		parent := c.parentID(o.Parent)
		found := false

		for _, l := range c.live.OUs {
			if l.Name == o.Name && l.ParentID == parent && parent != "" {
				matched[l.ID] = true
				c.ouID[o.Name] = l.ID
				found = true

				c.add(KindUnrecordedID, "ou", o.Name, "exists as "+l.ID)

				break
			}
		}

		if !found {
			c.add(KindMissing, "ou", o.Name, "not created yet")
		}
	}

	for _, l := range c.live.OUs {
		if !matched[l.ID] {
			c.add(KindUnmanaged, "ou", l.Name, l.ID)
		}
	}
}

// orderOUs returns the OUs parents first.
func orderOUs(ous []registry.OU) []registry.OU {
	depth := map[string]int{}
	parent := map[string]string{}

	for _, o := range ous {
		parent[o.Name] = o.Parent
	}

	for _, o := range ous {
		d, seen := 0, map[string]bool{}
		for p := o.Parent; p != "" && !seen[p]; p = parent[p] {
			seen[p] = true
			d++
		}

		depth[o.Name] = d
	}

	out := append([]registry.OU(nil), ous...)
	sort.SliceStable(out, func(i, j int) bool { return depth[out[i].Name] < depth[out[j].Name] })

	return out
}

func (c *comparer) accounts() {
	byID, byEmail := map[string]LiveAccount{}, map[string]LiveAccount{}
	for _, a := range c.live.Accounts {
		byID[a.ID] = a
		byEmail[strings.ToLower(a.Email)] = a
	}

	matched := map[string]bool{}

	for _, a := range c.reg.Accounts {
		var (
			l  LiveAccount
			ok bool
		)

		if a.ID != "" {
			if l, ok = byID[a.ID]; !ok {
				c.add(KindMissing, "account", a.Name, "id "+a.ID+" not found")

				continue
			}
		} else {
			if l, ok = byEmail[strings.ToLower(a.Email)]; !ok {
				c.add(KindMissing, "account", a.Name, "not created yet")

				continue
			}

			c.add(KindUnrecordedID, "account", a.Name, "exists as "+l.ID)
		}

		matched[l.ID] = true
		c.acctID[a.Name] = l.ID

		if !strings.EqualFold(l.Email, a.Email) {
			c.add(KindEdited, "account", a.Name, fmt.Sprintf("email %q in AWS, declared %q", l.Email, a.Email))
		}

		if want := c.parentID(a.OU); want != "" && l.ParentID != want {
			c.add(KindMoved, "account", a.Name, fmt.Sprintf("parent %s, declared %s (%s)", l.ParentID, a.OU, want))
		}

		active := l.State == "" || l.State == "ACTIVE"

		switch {
		case a.Closed && active:
			c.add(KindEdited, "account", a.Name, "declared closed, active in AWS")
		case !a.Closed && !active:
			c.add(KindNotActive, "account", a.Name, l.State)
		}
	}

	for _, l := range c.live.Accounts {
		if !matched[l.ID] {
			c.add(KindUnmanaged, "account", l.Name, l.ID)
		}
	}
}

// policies reports every attached service control policy the registry does
// not attach. v1 registries are dormant, so that is every policy but the one
// AWS attaches by default.
func (c *comparer) policies() {
	names := map[string]string{c.live.RootID: "root"}
	for _, o := range c.live.OUs {
		names[o.ID] = "ou " + o.Name
	}

	for _, a := range c.live.Accounts {
		names[a.ID] = "account " + a.Name
	}

	targets := make([]string, 0, len(c.live.Policies))
	for t := range c.live.Policies {
		targets = append(targets, t)
	}

	sort.Strings(targets)

	for _, t := range targets {
		for _, p := range c.live.Policies[t] {
			if p == awsDefaultPolicy || c.reg.SCPEnforcement != registry.SCPDormant {
				continue
			}

			c.add(KindUnmanaged, "scp-attachment", names[t]+" ("+t+")", fmt.Sprintf("policy %q attached while the registry is dormant", p))
		}
	}
}

func (c *comparer) permissionSets() {
	live := map[string]bool{}
	for _, name := range c.live.PermissionSets {
		live[name] = true
	}

	declared := map[string]bool{}

	for _, p := range c.reg.IdentityCenter.PermissionSets {
		declared[p.Name] = true

		if !live[p.Name] {
			c.add(KindMissing, "permission-set", p.Name, "")
		}
	}

	for arn, name := range c.live.PermissionSets {
		if !declared[name] {
			c.add(KindUnmanaged, "permission-set", name, arn)
		}
	}
}

// assignmentKey names an assignment by names: account|set|TYPE|principal.
func assignmentKey(account, set, principalType, principal string) string {
	return strings.Join([]string{account, set, strings.ToUpper(principalType), principal}, "|")
}

func (c *comparer) assignments() {
	accountsUnder := c.accountsUnder()
	nameOfID := map[string]string{}

	for name, id := range c.acctID {
		nameOfID[id] = name
	}

	want := map[string]bool{}

	for _, a := range c.reg.IdentityCenter.Assignments {
		targets := append([]string(nil), a.Accounts...)
		for _, ou := range a.OUs {
			targets = append(targets, accountsUnder[ou]...)
		}

		for _, acct := range targets {
			if c.closed[acct] {
				continue // a closed account grants nothing
			}

			if _, ok := c.acctID[acct]; ok {
				want[assignmentKey(acct, a.PermissionSet, a.PrincipalType, a.Principal)] = true
			}
		}
	}

	have := map[string]bool{}

	for _, l := range c.live.Assignments {
		acct, ok := nameOfID[l.AccountID]
		if !ok {
			continue // an unmanaged account is reported as such
		}

		principal := c.live.Groups[l.PrincipalID]
		if strings.EqualFold(l.PrincipalType, "USER") {
			principal = c.live.Users[l.PrincipalID]
		}

		if principal == "" {
			principal = "id:" + l.PrincipalID
		}

		set := c.live.PermissionSets[l.PermissionSetARN]
		if set == "" {
			set = l.PermissionSetARN // a set Read could not name
		}

		have[assignmentKey(acct, set, l.PrincipalType, principal)] = true
	}

	for k := range have {
		if !want[k] {
			c.add(KindUnmanaged, "assignment", k, "granted in AWS, not declared")
		}
	}

	for k := range want {
		if !have[k] {
			c.add(KindMissing, "assignment", k, "declared, not granted")
		}
	}
}

// accountsUnder maps each OU name to the account names in it, at any depth.
func (c *comparer) accountsUnder() map[string][]string {
	parent := map[string]string{}
	for _, o := range c.reg.OUs {
		parent[o.Name] = o.Parent
	}

	out := map[string][]string{}

	for _, a := range c.reg.Accounts {
		seen := map[string]bool{}
		for ou := a.OU; ou != "" && !seen[ou]; ou = parent[ou] {
			seen[ou] = true
			out[ou] = append(out[ou], a.Name)
		}
	}

	return out
}
