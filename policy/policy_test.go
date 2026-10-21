package policy_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/truvity/aws-structure/policy"
)

func marshal(t *testing.T, d policy.Document) string {
	t.Helper()

	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}

	return string(b)
}

func TestMarshalCanonicalForm(t *testing.T) {
	for name, tc := range map[string]struct {
		doc  policy.Document
		want string
	}{
		"version defaults and one value is a bare string": {
			policy.Document{Statement: []policy.Statement{
				{Sid: "A", Effect: policy.Allow, Action: []string{"*"}, Resource: []string{"*"}},
			}},
			`{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"*","Resource":"*"}]}`,
		},
		"many values stay a list": {
			policy.Document{Statement: []policy.Statement{
				{Sid: "A", Effect: policy.Deny, Action: []string{"s3:Get*", "s3:Put*"}, Resource: []string{"*"}},
			}},
			`{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Deny","Action":["s3:Get*","s3:Put*"],"Resource":"*"}]}`,
		},
		"Arrays keeps one value a list": {
			policy.Document{Statement: []policy.Statement{
				{
					Sid: "A", Effect: policy.Deny, Action: []string{"iam:X"}, NotResource: []string{"r"},
					Arrays: policy.ArrayAction | policy.ArrayNotResource,
				},
			}},
			`{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Deny","Action":["iam:X"],"NotResource":["r"]}]}`,
		},
		"an explicit version is kept": {
			policy.Document{Version: "2012-10-17", Statement: []policy.Statement{
				{Sid: "A", Effect: policy.Allow, NotAction: []string{"iam:*"}, Resource: []string{"*"}},
			}},
			`{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`,
		},
		"conditions are grouped by operator then key, in byte order": {
			policy.Document{Statement: []policy.Statement{
				{
					Sid: "A", Effect: policy.Deny, Action: []string{"iam:X"}, Resource: []string{"*"},
					Condition: []policy.Condition{
						{Operator: "StringNotEquals", Key: "b:key", Values: []string{"v"}},
						{Operator: "Null", Key: "z:key", Values: []string{"true"}},
						{Operator: "StringNotEquals", Key: "a:key", Values: []string{"v1", "v2"}},
						{Operator: "Null", Key: "a:key", Values: []string{"false"}, Array: true},
					},
				},
			}},
			`{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Deny","Action":"iam:X","Resource":"*",` +
				`"Condition":{"Null":{"a:key":["false"],"z:key":"true"},"StringNotEquals":{"a:key":["v1","v2"],"b:key":"v"}}}]}`,
		},
		"policy variables are not escaped": {
			policy.Document{Statement: []policy.Statement{
				{Sid: "A", Effect: policy.Allow, Action: []string{"s3:*"}, Resource: []string{"arn:part:s3:::${aws:PrincipalTag/project}-*"}},
			}},
			`{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"s3:*","Resource":"arn:part:s3:::${aws:PrincipalTag/project}-*"}]}`,
		},
	} {
		if got := marshal(t, tc.doc); got != tc.want {
			t.Errorf("%s:\n got: %s\nwant: %s", name, got, tc.want)
		}
	}
}

func TestMarshalIsDeterministic(t *testing.T) {
	d := policy.Document{Statement: []policy.Statement{{
		Sid: "A", Effect: policy.Deny, Action: []string{"iam:X"}, Resource: []string{"*"},
		Condition: []policy.Condition{
			{Operator: "StringEquals", Key: "k3", Values: []string{"v"}},
			{Operator: "StringEquals", Key: "k1", Values: []string{"v"}},
			{Operator: "Bool", Key: "k2", Values: []string{"true"}},
			{Operator: "StringEquals", Key: "k2", Values: []string{"v"}},
		},
	}}}

	first := marshal(t, d)
	for range 50 {
		if got := marshal(t, d); got != first {
			t.Fatalf("two renderings differ:\n%s\n%s", first, got)
		}
	}
}

func TestMarshalDoesNotAliasTheStatement(t *testing.T) {
	action := []string{"a", "b"}
	d := policy.Document{Statement: []policy.Statement{{Sid: "A", Effect: policy.Allow, Action: action, Resource: []string{"*"}}}}

	b, err := d.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}

	action[0] = "changed"

	if !strings.Contains(string(b), `"a"`) || strings.Contains(string(b), "changed") {
		t.Errorf("output follows the input slice: %s", b)
	}
}

func TestMarshalRefusesTwoConditionsOnOneKey(t *testing.T) {
	d := policy.Document{Statement: []policy.Statement{{
		Sid: "A", Effect: policy.Deny, Action: []string{"iam:X"}, Resource: []string{"*"},
		Condition: []policy.Condition{
			{Operator: "Null", Key: "k", Values: []string{"true"}},
			{Operator: "Null", Key: "k", Values: []string{"false"}},
		},
	}}}

	if _, err := d.MarshalJSON(); err == nil || !strings.Contains(err.Error(), "two conditions Null on k") {
		t.Errorf("err = %v", err)
	}

	if _, err := d.Size(); err == nil {
		t.Error("Size of an unwritable document did not fail")
	}
}

func TestSize(t *testing.T) {
	d := policy.Document{Statement: []policy.Statement{{Sid: "A", Effect: policy.Allow, Action: []string{"*"}, Resource: []string{"*"}}}}
	want := len(`{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"*","Resource":"*"}]}`)

	got, err := d.Size()
	if err != nil || got != want {
		t.Errorf("Size = %d, %v; want %d", got, err, want)
	}
}

// ok returns a valid statement; each table case breaks it in one way.
func ok() policy.Statement {
	return policy.Statement{Sid: "AllowAll", Effect: policy.Allow, Action: []string{"*"}, Resource: []string{"*"}}
}

func TestValidate(t *testing.T) {
	doc := func(s ...policy.Statement) policy.Document { return policy.Document{Statement: s} }

	if err := doc(ok()).Validate(); err != nil {
		t.Fatalf("a valid document was refused: %v", err)
	}

	for name, tc := range map[string]struct {
		doc  policy.Document
		want string
	}{
		"no statement":   {policy.Document{}, "no statement"},
		"bad version":    {policy.Document{Version: "2008-10-17", Statement: []policy.Statement{ok()}}, `Version is "2008-10-17"`},
		"no sid":         {doc(func() policy.Statement { s := ok(); s.Sid = ""; return s }()), "has no Sid"},
		"sid with space": {doc(func() policy.Statement { s := ok(); s.Sid = "Deny All"; return s }()), "letters and digits only"},
		"sid with dash":  {doc(func() policy.Statement { s := ok(); s.Sid = "Deny-All"; return s }()), "letters and digits only"},
		"duplicate sid":  {doc(ok(), ok()), `Sid "AllowAll" is also the Sid of statement 0`},
		"no effect":      {doc(func() policy.Statement { s := ok(); s.Effect = ""; return s }()), "Effect is"},
		"bad effect":     {doc(func() policy.Statement { s := ok(); s.Effect = "allow"; return s }()), `Effect is "allow"`},
		"no action":      {doc(func() policy.Statement { s := ok(); s.Action = nil; return s }()), "neither Action nor NotAction"},
		"both actions": {doc(func() policy.Statement { s := ok(); s.NotAction = []string{"x"}; return s }()),
			"both Action and NotAction"},
		"no resource": {doc(func() policy.Statement { s := ok(); s.Resource = nil; return s }()), "neither Resource nor NotResource"},
		"both resources": {doc(func() policy.Statement { s := ok(); s.NotResource = []string{"x"}; return s }()),
			"both Resource and NotResource"},
		"empty action":   {doc(func() policy.Statement { s := ok(); s.Action = []string{"a", ""}; return s }()), "Action has an empty entry"},
		"empty resource": {doc(func() policy.Statement { s := ok(); s.Resource = []string{""}; return s }()), "Resource has an empty entry"},
		"empty not-resource": {doc(func() policy.Statement {
			s := ok()
			s.Resource, s.NotResource = nil, []string{""}

			return s
		}()), "NotResource has an empty entry"},
		"condition without operator": {doc(func() policy.Statement {
			s := ok()
			s.Condition = []policy.Condition{{Key: "k", Values: []string{"v"}}}

			return s
		}()), "has no operator"},
		"condition without key": {doc(func() policy.Statement {
			s := ok()
			s.Condition = []policy.Condition{{Operator: "Null", Values: []string{"v"}}}

			return s
		}()), "has no key"},
		"condition without value": {doc(func() policy.Statement {
			s := ok()
			s.Condition = []policy.Condition{{Operator: "Null", Key: "k"}}

			return s
		}()), "has no value"},
		"condition empty value": {doc(func() policy.Statement {
			s := ok()
			s.Condition = []policy.Condition{{Operator: "Null", Key: "k", Values: []string{"a", ""}}}

			return s
		}()), "has an empty value"},
		"condition twice": {doc(func() policy.Statement {
			s := ok()
			s.Condition = []policy.Condition{
				{Operator: "Null", Key: "k", Values: []string{"a"}}, {Operator: "Null", Key: "k", Values: []string{"b"}},
			}

			return s
		}()), "two conditions Null on k"},
	} {
		err := tc.doc.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want containing %q", name, err, tc.want)
		}
	}

	t.Run("every problem is reported", func(t *testing.T) {
		bad := policy.Statement{}

		var joined interface{ Unwrap() []error }
		if err := doc(bad).Validate(); !errors.As(err, &joined) || len(joined.Unwrap()) < 4 {
			t.Errorf("err = %v, want the joined problems", err)
		}
	})
}

func TestUnmarshalRefusals(t *testing.T) {
	for name, in := range map[string]string{
		"principal":       `{"Statement":[{"Sid":"A","Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}`,
		"unknown key":     `{"Id":"x","Statement":[]}`,
		"bool value":      `{"Statement":[{"Sid":"A","Effect":"Deny","Action":"*","Resource":"*","Condition":{"Bool":{"k":true}}}]}`,
		"number in list":  `{"Statement":[{"Sid":"A","Effect":"Deny","Action":[1],"Resource":"*"}]}`,
		"single object":   `{"Statement":{"Sid":"A","Effect":"Deny","Action":"*","Resource":"*"}}`,
		"trailing data":   `{"Statement":[]} {}`,
		"not an object":   `[]`,
		"object as value": `{"Statement":[{"Sid":"A","Effect":"Deny","Action":{"a":"b"},"Resource":"*"}]}`,
	} {
		var d policy.Document
		if err := json.Unmarshal([]byte(in), &d); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	var d policy.Document

	err := json.Unmarshal([]byte(`{"Statement":[{"Sid":"A","Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}`), &d)
	if !errors.Is(err, policy.ErrUnsupported) {
		t.Errorf("err = %v, want it to wrap ErrUnsupported", err)
	}
}

func TestUnmarshalKeepsTheForm(t *testing.T) {
	in := `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Deny","Action":"x","NotResource":["y"],` +
		`"Condition":{"StringLike":{"k":["v"]},"Null":{"j":"true"}}}]}`

	var d policy.Document
	if err := json.Unmarshal([]byte(in), &d); err != nil {
		t.Fatal(err)
	}

	s := d.Statement[0]
	if s.Arrays != policy.ArrayNotResource {
		t.Errorf("Arrays = %b, want only NotResource", s.Arrays)
	}

	if !slices.Equal(s.Action, []string{"x"}) || !slices.Equal(s.NotResource, []string{"y"}) {
		t.Errorf("statement = %+v", s)
	}

	want := []policy.Condition{
		{Operator: "Null", Key: "j", Values: []string{"true"}},
		{Operator: "StringLike", Key: "k", Values: []string{"v"}, Array: true},
	}
	if len(s.Condition) != 2 || s.Condition[0].Operator != want[0].Operator || s.Condition[1].Array != true {
		t.Errorf("conditions = %+v, want %+v", s.Condition, want)
	}

	// Only the order of the Condition block differs from the input.
	if got := marshal(t, d); got == in {
		t.Error("the condition block was not put in byte order")
	}
}

// TestGoldenRoundTrip reads each golden file (documents rendered by the
// boundary package of this repository, indented), validates it, writes it
// again and expects the same bytes, minified and indented.
func TestGoldenRoundTrip(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no golden files: %v", err)
	}

	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}

		var d policy.Document
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatalf("%s: %v", f, err)
		}

		if err := d.Validate(); err != nil {
			t.Errorf("%s: %v", f, err)
		}

		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err != nil {
			t.Fatal(err)
		}

		if got := marshal(t, d); got != compact.String() {
			t.Errorf("%s minified differs:\n got: %s\nwant: %s", f, got, compact.String())
		}

		indented, err := json.MarshalIndent(d, "", "  ")
		if err != nil {
			t.Fatal(err)
		}

		if got := string(indented) + "\n"; got != string(raw) {
			t.Errorf("%s indented differs", f)
		}

		if n, err := d.Size(); err != nil || n != compact.Len() {
			t.Errorf("%s: Size = %d, %v; want %d", f, n, err, compact.Len())
		}
	}
}
