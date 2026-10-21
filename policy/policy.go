package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

// Version is the policy language version every document uses: the only one
// that supports policy variables such as ${aws:PrincipalTag/project}.
const Version = "2012-10-17"

// Effect is whether a statement allows or denies.
type Effect string

// The two effects.
const (
	Allow Effect = "Allow"
	Deny  Effect = "Deny"
)

// Arrays names the elements of a statement that stay a JSON array when they
// hold one value. The zero value writes a one-value list as a bare string.
type Arrays uint8

// The elements [Statement.Arrays] can name.
const (
	ArrayAction Arrays = 1 << iota
	ArrayNotAction
	ArrayResource
	ArrayNotResource
)

// Document is an IAM policy document.
type Document struct {
	// Version defaults to [Version] when empty.
	Version   string
	Statement []Statement
}

// Statement is one statement of a [Document]. Each statement has a Sid, an
// Effect, one of Action and NotAction and one of Resource and NotResource;
// [Document.Validate] checks that.
type Statement struct {
	Sid         string
	Effect      Effect
	Action      []string
	NotAction   []string
	Resource    []string
	NotResource []string
	Condition   []Condition

	// Arrays keeps the named elements an array when they hold one value. See
	// the package comment.
	Arrays Arrays
}

// Condition is one key of one operator in a statement's Condition block:
//
//	{Operator: "StringEquals", Key: "aws:RequestTag/project", Values: []string{"x"}}
//
// is "Condition": {"StringEquals": {"aws:RequestTag/project": "x"}}. Two
// conditions of one statement may share an operator but not an operator and a
// key.
type Condition struct {
	Operator string
	Key      string
	Values   []string

	// Array keeps Values an array when it holds one value. See the package
	// comment.
	Array bool
}

type (
	wireDocument struct {
		Version   string          `json:"Version"`
		Statement []wireStatement `json:"Statement"`
	}

	wireStatement struct {
		Sid         string                    `json:"Sid,omitempty"`
		Effect      Effect                    `json:"Effect"`
		Action      any                       `json:"Action,omitempty"`
		NotAction   any                       `json:"NotAction,omitempty"`
		Resource    any                       `json:"Resource,omitempty"`
		NotResource any                       `json:"NotResource,omitempty"`
		Condition   map[string]map[string]any `json:"Condition,omitempty"`
	}
)

// value is the JSON form of a list: nothing when empty, the bare string for
// one value unless array is set, the array otherwise.
func value(v []string, array bool) any {
	switch {
	case len(v) == 0:
		return nil
	case len(v) == 1 && !array:
		return v[0]
	default:
		return slices.Clone(v)
	}
}

// MarshalJSON writes the canonical, minified form (see the package comment).
// It fails only where a document cannot be written: two conditions with one
// operator and key. It does not check the rest; see [Document.Validate].
func (d Document) MarshalJSON() ([]byte, error) {
	w := wireDocument{Version: d.Version, Statement: make([]wireStatement, 0, len(d.Statement))}
	if w.Version == "" {
		w.Version = Version
	}

	for i := range d.Statement {
		s := &d.Statement[i]
		ws := wireStatement{
			Sid: s.Sid, Effect: s.Effect,
			Action:      value(s.Action, s.Arrays&ArrayAction != 0),
			NotAction:   value(s.NotAction, s.Arrays&ArrayNotAction != 0),
			Resource:    value(s.Resource, s.Arrays&ArrayResource != 0),
			NotResource: value(s.NotResource, s.Arrays&ArrayNotResource != 0),
		}

		if len(s.Condition) > 0 {
			ws.Condition = make(map[string]map[string]any)
		}

		for _, c := range s.Condition {
			keys := ws.Condition[c.Operator]
			if keys == nil {
				keys = make(map[string]any)
				ws.Condition[c.Operator] = keys
			}

			if _, dup := keys[c.Key]; dup {
				return nil, fmt.Errorf("policy: statement %q has two conditions %s on %s", s.Sid, c.Operator, c.Key)
			}

			keys[c.Key] = value(c.Values, c.Array)
		}

		w.Statement = append(w.Statement, ws)
	}

	b, err := json.Marshal(w)
	if err != nil {
		return nil, fmt.Errorf("policy: marshal: %w", err)
	}

	return b, nil
}

// Size returns the length of the canonical minified document in characters,
// the number IAM's limit on a managed policy (6,144) applies to: IAM does not
// count white space.
func (d Document) Size() (int, error) {
	b, err := d.MarshalJSON()
	if err != nil {
		return 0, err
	}

	return len(b), nil
}

// ErrUnsupported is wrapped by the errors of [Document.UnmarshalJSON] for
// JSON the model cannot hold without losing meaning.
var ErrUnsupported = errors.New("policy: unsupported policy element")
