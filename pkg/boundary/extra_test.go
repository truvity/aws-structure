package boundary_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/truvity/aws-structure/pkg/boundary"
	"github.com/truvity/aws-structure/policy"
)

const (
	extraAdmin = "bound@role-admin"
	extraLeaf  = "bound@tech-grun"
	extraTop   = "bound@tech-deployer"
)

// extraSpec is currentSpec with the class prefix Extra boundaries need.
func extraSpec() boundary.Spec {
	s := currentSpec()
	s.ClassPrefix = "bound@tech-"

	return s
}

// runtimeDocument returns the statements of testdata/grun.json that the runners
// stack's component owns (everything before the two estate guards) and the
// compact form of the whole.
func runtimeDocument(t *testing.T) (policy.Document, string) {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", "grun.json"))
	if err != nil {
		t.Fatal(err)
	}

	var d policy.Document
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}

	n := len(d.Statement)
	if d.Statement[n-2].Sid != "DenyBoundaryPolicyEdit" || d.Statement[n-1].Sid != "NoBoundaryDelete" {
		t.Fatalf("grun.json does not end with the estate guards: %v", d.Statement[n-2:])
	}

	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		t.Fatal(err)
	}

	d.Statement = d.Statement[:n-2]

	return d, compact.String()
}

func leafExtra(t *testing.T) boundary.Extra {
	t.Helper()

	d, _ := runtimeDocument(t)

	return boundary.Extra{Name: extraLeaf, Document: d, DelegatedBy: []string{extraAdmin}}
}

// topExtra is a boundary that delegates the leaf: it may create roles under it
// and under nothing else.
func topExtra() boundary.Extra {
	return boundary.Extra{
		Name: extraTop,
		Document: policy.Document{Statement: []policy.Statement{
			{Sid: "AllowAll", Effect: policy.Allow, Action: []string{"*"}, Resource: []string{"*"}},
			{
				Sid: "DenyUserCreate", Effect: policy.Deny, Action: []string{"iam:CreateUser"}, Resource: []string{"*"},
			},
		}},
		DelegatedBy: []string{extraAdmin},
		Delegates:   []string{extraLeaf},
	}
}

func mustPolicies(t *testing.T, s boundary.Spec) map[string]string {
	t.Helper()

	return docs(t, s)
}

// The boundary the old Names.Grun path renders is what an Extra made of the
// component's statements renders, byte for byte, and so is every other
// document of the Spec.
func TestExtraEqualsTheGrunPath(t *testing.T) {
	_, want := runtimeDocument(t)

	s := extraSpec()
	s.Extra = []boundary.Extra{leafExtra(t)}

	got := mustPolicies(t, s)

	if got[extraLeaf] != want {
		t.Errorf("the Extra differs from testdata/grun.json:\n got: %s\nwant: %s", got[extraLeaf], want)
	}

	old := mustPolicies(t, grunSpec())
	if len(old) != len(got) {
		t.Fatalf("%d documents through Extra, %d through Names.Grun", len(got), len(old))
	}

	for name, doc := range old {
		if got[name] != doc {
			t.Errorf("%s differs between the Extra and the Names.Grun paths", name)
		}
	}
}

func TestExtraIsAppendedLastAndTheSpecIsNotChanged(t *testing.T) {
	s := extraSpec()
	s.Extra = []boundary.Extra{topExtra(), leafExtra(t)}
	n := len(s.Extra[0].Document.Statement)

	ps, err := boundary.Policies(s)
	if err != nil {
		t.Fatal(err)
	}

	if last := ps[len(ps)-2:]; last[0].Name != extraTop || last[1].Name != extraLeaf {
		t.Errorf("the last two boundaries are %s and %s, want the Extra values in order", last[0].Name, last[1].Name)
	}

	if len(s.Extra[0].Document.Statement) != n || len(s.Hierarchy[0].Delegates) != 12 {
		t.Error("Policies changed the Spec")
	}

	again, err := boundary.Policies(s)
	if err != nil || len(again) != len(ps) {
		t.Fatalf("second run: %v", err)
	}

	for i := range ps {
		if ps[i] != again[i] {
			t.Errorf("%s renders differently on a second run", ps[i].Name)
		}
	}
}

func TestNonLeafExtraDeniesAnyBoundaryButItsDelegates(t *testing.T) {
	s := extraSpec()
	s.Extra = []boundary.Extra{topExtra(), leafExtra(t)}

	got := parse(t, docs(t, s)[extraTop])

	want := []string{"AllowAll", "DenyUserCreate", "DenyCreateOrChangeWithoutAllowedBoundary", "DenyBoundaryPolicyEdit", "NoBoundaryDelete"}
	if !slices.Equal(sids(got), want) {
		t.Fatalf("statements = %v, want %v", sids(got), want)
	}

	raw := docs(t, s)[extraTop]
	for _, frag := range []string{
		`"Condition":{"StringNotLike":{"iam:PermissionsBoundary":["arn:part:iam::*:policy/bound@tech-grun"]}}`,
		`"Resource":["arn:part:iam::*:policy/bound@*"]`,
	} {
		if !strings.Contains(raw, frag) {
			t.Errorf("the document lacks %s:\n%s", frag, raw)
		}
	}

	// The delegation reaches exactly the delegates.
	if d := s.DelegateARNs(extraTop); !slices.Equal(d, []string{"arn:part:iam::*:policy/bound@tech-grun"}) {
		t.Errorf("DelegateARNs = %v", d)
	}
}

func TestExtraDelegatorsGrowByTheExactName(t *testing.T) {
	s := extraSpec()
	s.Extra = []boundary.Extra{topExtra(), leafExtra(t)}

	for _, name := range []string{extraTop, extraLeaf} {
		if !slices.Contains(s.DelegateARNs(extraAdmin), "arn:part:iam::*:policy/"+name) {
			t.Errorf("role-admin does not delegate %s", name)
		}
	}

	if slices.Contains(s.DelegateARNs("bound@role-deployer"), "arn:part:iam::*:policy/"+extraLeaf) {
		t.Error("the deployer delegates an Extra it was not named by")
	}

	before := docs(t, extraSpec())
	after := docs(t, s)

	for name, d := range before {
		if name != extraAdmin && after[name] != d {
			t.Errorf("%s changed when Extra boundaries were added", name)
		}
	}

	if after[extraAdmin] == before[extraAdmin] {
		t.Error("role-admin did not change")
	}

	var grew int

	for _, e := range s.Extra {
		grew += len(`,"arn:part:iam::*:policy/` + e.Name + `"`)
	}

	if d := len(after[extraAdmin]) - len(before[extraAdmin]); d != grew {
		t.Errorf("role-admin grew by %d characters, want %d", d, grew)
	}
}

func TestExtraDelegatorAllowList(t *testing.T) {
	deployer := leafExtra(t)
	deployer.DelegatedBy = []string{"bound@role-deployer"}

	s := extraSpec()
	s.Extra = []boundary.Extra{deployer}

	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), `delegated by "bound@role-deployer", which is not in ExtraDelegators`) {
		t.Errorf("a delegator outside the allow list was accepted: %v", err)
	}

	s.ExtraDelegators = []string{"bound@role-deployer"}
	if err := s.Validate(); err != nil {
		t.Errorf("an allow-listed delegator was refused: %v", err)
	}

	if !slices.Contains(s.DelegateARNs("bound@role-deployer"), "arn:part:iam::*:policy/"+extraLeaf) {
		t.Error("the allow-listed delegator does not delegate the Extra")
	}

	ghost := leafExtra(t)
	ghost.DelegatedBy = []string{"bound@ghost"}
	s.Extra, s.ExtraDelegators = []boundary.Extra{ghost}, []string{"bound@ghost"}

	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "not a boundary of the Spec") {
		t.Errorf("a delegator that is no boundary was accepted: %v", err)
	}
}

func TestExtraRefusals(t *testing.T) {
	long := leafExtra(t)
	long.Name = "bound@tech-" + strings.Repeat("a", 120)

	for name, tc := range map[string]struct {
		mutate func(*boundary.Spec)
		want   string
	}{
		"no class prefix": {func(s *boundary.Spec) { s.Extra[0].Name = "bound@other" }, "must start with the class prefix"},
		"only the prefix": {func(s *boundary.Spec) { s.Extra[0].Name = "bound@tech-" }, "must start with the class prefix"},
		"wildcard":        {func(s *boundary.Spec) { s.Extra[0].Name = "bound@tech-x*" }, "holds a wildcard"},
		"too long":        {func(s *boundary.Spec) { s.Extra[0] = long }, "IAM allows 128"},
		"bad character":   {func(s *boundary.Spec) { s.Extra[0].Name = "bound@tech-a b" }, "a character IAM does not allow"},
		"built-in name":   {func(s *boundary.Spec) { s.Extra[0].Name = "bound@tech-ack-s3" }, "is a built-in boundary"},
		"grun name": {func(s *boundary.Spec) {
			s.Names.Grun = extraLeaf
			s.Grun.RolePrefix = "g-"
			s.Grun.PassedToServices = []string{"x"}
		}, "built-in"},
		"listed in the hierarchy": {func(s *boundary.Spec) {
			s.Hierarchy = append(s.Hierarchy, boundary.Entry{Name: extraLeaf})
		}, "also an entry of Hierarchy"},
		"duplicate":           {func(s *boundary.Spec) { s.Extra = append(s.Extra, s.Extra[0]) }, "declared twice"},
		"no class prefix set": {func(s *boundary.Spec) { s.ClassPrefix = "" }, "ClassPrefix is empty"},
		"reserved sid edit": {func(s *boundary.Spec) {
			s.Extra[0].Document.Statement = append(s.Extra[0].Document.Statement,
				policy.Statement{Sid: "DenyBoundaryPolicyEdit", Effect: policy.Deny, Action: []string{"iam:X"}, Resource: []string{"*"}})
		}, `reserved for the estate's guard`},
		"reserved sid delete": {func(s *boundary.Spec) {
			s.Extra[0].Document.Statement = append(s.Extra[0].Document.Statement,
				policy.Statement{Sid: "NoBoundaryDelete", Effect: policy.Deny, Action: []string{"iam:X"}, Resource: []string{"*"}})
		}, `reserved for the estate's guard`},
		"reserved sid delegation": {func(s *boundary.Spec) {
			s.Extra[0].Document.Statement = append(s.Extra[0].Document.Statement,
				policy.Statement{Sid: "DenyCreateOrChangeWithoutAllowedBoundary", Effect: policy.Deny, Action: []string{"iam:X"}, Resource: []string{"*"}})
		}, `reserved for the estate's guard`},
		"invalid document":     {func(s *boundary.Spec) { s.Extra[0].Document.Statement[0].Action = nil }, "neither Action nor NotAction"},
		"empty accounts entry": {func(s *boundary.Spec) { s.Extra[0].Accounts = []string{""} }, "Accounts has an empty entry"},
		"undefined delegate":   {func(s *boundary.Spec) { s.Extra[0].Delegates = []string{"bound@ghost"} }, `delegates to undefined boundary "bound@ghost"`},
		"pattern delegate": {func(s *boundary.Spec) { s.Extra[0].Delegates = []string{"bound@tech-*"} },
			`delegates to the pattern "bound@tech-*"`},
		"self cycle": {func(s *boundary.Spec) { s.Extra[0].Delegates = []string{extraLeaf} }, "bound@tech-grun -> bound@tech-grun"},
		"cycle through the admin": {func(s *boundary.Spec) { s.Extra[0].Delegates = []string{extraAdmin} },
			"cycle: bound@role-admin -> bound@tech-grun -> bound@role-admin"},
		"cycle between extras": {func(s *boundary.Spec) {
			other := topExtra()
			other.Delegates = []string{extraLeaf}
			s.Extra[0].Delegates = []string{extraTop}
			s.Extra = append(s.Extra, other)
		}, "cycle: "},
		"no delegator": {func(s *boundary.Spec) { s.Names.RoleAdmin = "" }, "delegator"},
	} {
		s := extraSpec()
		s.Extra = []boundary.Extra{leafExtra(t)}
		tc.mutate(&s)

		err := s.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want containing %q", name, err, tc.want)
		}

		if _, perr := boundary.Policies(s); perr == nil {
			t.Errorf("%s: Policies accepted it", name)
		}
	}
}

func TestExtraSizeRefusals(t *testing.T) {
	t.Run("the document with its guards", func(t *testing.T) {
		big := leafExtra(t)
		big.Document.Statement = append(big.Document.Statement, policy.Statement{
			Sid: "AllowBig", Effect: policy.Allow, Action: []string{"s3:Get*"}, Resource: []string{"a"},
		})

		// Pad the document to 6,100 characters: under the limit alone, over it
		// once the guards are appended.
		base, _ := big.Document.Size()
		big.Document.Statement[len(big.Document.Statement)-1].Resource = []string{strings.Repeat("a", 6100-base+1)}

		if n, _ := big.Document.Size(); n > boundary.MaxDocumentSize {
			t.Fatalf("the fixture is already over the limit before the guards: %d", n)
		}

		s := extraSpec()
		s.Extra = []boundary.Extra{big}

		_, err := boundary.Policies(s)
		if err == nil || !strings.Contains(err.Error(), "boundary bound@tech-grun: the document is") || !strings.Contains(err.Error(), "over IAM's limit of 6144") {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("the delegator that grows past the limit", func(t *testing.T) {
		s := extraSpec()

		base := docs(t, s)[extraAdmin]
		if len(base) > boundary.MaxDocumentSize {
			t.Fatal("role-admin is over the limit before any Extra")
		}

		// Each leaf adds its exact name to role-admin: with long names, a few dozen
		// of them carry it past the limit while every Extra is small.
		for i := range 60 {
			e := leafExtra(t)
			e.Name = "bound@tech-" + strings.Repeat("n", 90) + string(rune('a'+i/26)) + string(rune('a'+i%26))
			s.Extra = append(s.Extra, e)
		}

		_, err := boundary.Policies(s)
		if err == nil || !strings.Contains(err.Error(), "boundary bound@role-admin: the document is") {
			t.Errorf("err = %v, want the parent named", err)
		}
	})
}

// A leaf whose document does not deny creating roles gets the unconditional
// deny; one that already denies them by an explicit Deny, even a conditional
// one, does not.
func TestLeafGuard(t *testing.T) {
	plain := boundary.Extra{
		Name: "bound@tech-plain", DelegatedBy: []string{extraAdmin},
		Document: policy.Document{Statement: []policy.Statement{
			{Sid: "AllowAll", Effect: policy.Allow, Action: []string{"*"}, Resource: []string{"*"}},
		}},
	}

	denies := func(action ...string) policy.Statement {
		return policy.Statement{Sid: "DenyMint", Effect: policy.Deny, Action: action, Resource: []string{"*"}}
	}

	withDeny := func(st policy.Statement) boundary.Extra {
		e := plain
		e.Name = "bound@tech-denied"
		e.Document = policy.Document{Statement: []policy.Statement{plain.Document.Statement[0], st}}

		return e
	}

	conditional := denies("iam:Create*", "iam:Put*")
	conditional.Condition = []policy.Condition{{Operator: "StringNotEquals", Key: "iam:AWSServiceName", Values: []string{"x.amazonaws.com"}}}

	notAction := policy.Statement{Sid: "DenyMint", Effect: policy.Deny, NotAction: []string{"s3:*"}, Resource: []string{"*"}}
	scoped := denies("iam:*")
	scoped.Resource = []string{"arn:part:iam::*:role/x*"}

	for name, tc := range map[string]struct {
		e     boundary.Extra
		guard bool
	}{
		"no deny":                 {plain, true},
		"iam star":                {withDeny(denies("iam:*")), false},
		"all star":                {withDeny(denies("*")), false},
		"create and put patterns": {withDeny(denies("iam:Create*", "iam:Put*")), false},
		"exact names": {withDeny(denies("iam:CreateRole", "iam:CreateUser", "iam:PutRolePermissionsBoundary",
			"iam:PutUserPermissionsBoundary")), false},
		"case insensitive":           {withDeny(denies("IAM:create*", "iam:PUT*")), false},
		"conditional create and put": {withDeny(conditional), false},
		"only the create":            {withDeny(denies("iam:Create*")), true},
		"only roles":                 {withDeny(denies("iam:CreateRole", "iam:PutRolePermissionsBoundary")), true},
		"a deny on some roles only":  {withDeny(scoped), true},
		"a deny with NotAction":      {withDeny(notAction), true},
		"an allow does not count": {withDeny(policy.Statement{
			Sid: "DenyMint", Effect: policy.Allow, Action: []string{"iam:*"}, Resource: []string{"*"},
		}), true},
		"question mark pattern":         {withDeny(denies("iam:C?eate*", "iam:Put*")), false},
		"a pattern that does not fit":   {withDeny(denies("iam:Crate*", "iam:Put*")), true},
		"a shorter pattern than action": {withDeny(denies("iam:CreateRol", "iam:Put*")), true},
	} {
		s := extraSpec()
		s.Extra = []boundary.Extra{tc.e}

		got := parse(t, docs(t, s)[tc.e.Name])
		ids := sids(got)

		want := []string{"DenyBoundaryPolicyEdit", "NoBoundaryDelete"}
		if tc.guard {
			want = []string{"DenyCreateOrChangeWithoutAllowedBoundary", "DenyBoundaryPolicyEdit", "NoBoundaryDelete"}
		}

		if !slices.Equal(ids[len(ids)-len(want):], want) {
			t.Errorf("%s: the document ends with %v, want %v", name, ids[len(ids)-len(want):], want)
		}

		if tc.guard {
			raw := docs(t, s)[tc.e.Name]
			frag := `{"Sid":"DenyCreateOrChangeWithoutAllowedBoundary","Effect":"Deny","Action":` +
				`["iam:CreateRole","iam:CreateUser","iam:PutRolePermissionsBoundary","iam:PutUserPermissionsBoundary"],"Resource":"*"}`

			if !strings.Contains(raw, frag) {
				t.Errorf("%s: the leaf guard is not the unconditional deny:\n%s", name, raw)
			}
		}
	}
}

func TestExtraAccounts(t *testing.T) {
	only := leafExtra(t)
	only.Accounts = []string{"alpha"}

	everywhere := topExtra()
	everywhere.Delegates = nil

	for account, want := range map[string][]string{
		"":      {extraLeaf, extraTop},
		"alpha": {extraLeaf, extraTop},
		"beta":  {extraTop},
	} {
		s := extraSpec()
		s.Account = account
		s.Extra = []boundary.Extra{only, everywhere}

		d := docs(t, s)

		for _, name := range []string{extraLeaf, extraTop} {
			_, has := d[name]
			if has != slices.Contains(want, name) {
				t.Errorf("account %q: %s rendered = %v", account, name, has)
			}

			listed := strings.Contains(d[extraAdmin], "policy/"+name+`"`)
			if listed != slices.Contains(want, name) {
				t.Errorf("account %q: role-admin lists %s = %v", account, name, listed)
			}
		}
	}

	// An Extra that delegates one the account does not carry fails there.
	top := topExtra()
	s := extraSpec()
	s.Account = "beta"
	s.Extra = []boundary.Extra{only, top}

	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), `delegates to undefined boundary "bound@tech-grun"`) {
		t.Errorf("err = %v", err)
	}
}

func TestExtraDocumentsFitAndValidate(t *testing.T) {
	s := extraSpec()
	s.Extra = []boundary.Extra{topExtra(), leafExtra(t)}

	for name, raw := range docs(t, s) {
		if len(raw) > maxPolicyChars {
			t.Errorf("%s: %d characters", name, len(raw))
		}

		var d policy.Document
		if err := json.Unmarshal([]byte(raw), &d); err != nil || d.Validate() != nil {
			t.Errorf("%s: %v %v", name, err, d.Validate())
		}
	}
}
