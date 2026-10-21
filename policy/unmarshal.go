package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// list is a JSON value that is a string or an array of strings.
type list struct {
	values []string
	array  bool // written as an array of one value
}

func (l *list) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)

	switch {
	case bytes.Equal(b, []byte("null")):
		return nil
	case len(b) > 0 && b[0] == '[':
		if err := json.Unmarshal(b, &l.values); err != nil {
			return fmt.Errorf("%w: a list holds only strings: %v", ErrUnsupported, err)
		}

		l.array = len(l.values) == 1

		return nil
	default:
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return fmt.Errorf("%w: %s is neither a string nor a list of strings", ErrUnsupported, b)
		}

		l.values = []string{s}

		return nil
	}
}

type (
	readDocument struct {
		Version   string          `json:"Version"`
		Statement []readStatement `json:"Statement"`
	}

	readStatement struct {
		Sid         string                     `json:"Sid"`
		Effect      Effect                     `json:"Effect"`
		Action      list                       `json:"Action"`
		NotAction   list                       `json:"NotAction"`
		Resource    list                       `json:"Resource"`
		NotResource list                       `json:"NotResource"`
		Condition   map[string]map[string]list `json:"Condition"`
	}
)

// UnmarshalJSON reads a document. A string where a list may stand is a list of
// one; a list of one value sets the matching [Statement.Arrays] or
// [Condition.Array] flag, so that [Document.MarshalJSON] writes back what was
// read. Conditions come out in operator, key order. It refuses what the model
// cannot hold (Principal, a single Statement object, a condition value that
// is not a string) with an error wrapping [ErrUnsupported].
func (d *Document) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()

	var r readDocument
	if err := dec.Decode(&r); err != nil {
		return fmt.Errorf("%w: %v", ErrUnsupported, err)
	}

	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("policy: trailing data after the document")
	}

	out := Document{Version: r.Version, Statement: make([]Statement, 0, len(r.Statement))}

	for i := range r.Statement {
		rs := &r.Statement[i]
		s := Statement{
			Sid: rs.Sid, Effect: rs.Effect,
			Action: rs.Action.values, NotAction: rs.NotAction.values,
			Resource: rs.Resource.values, NotResource: rs.NotResource.values,
		}

		for _, f := range []struct {
			set  bool
			flag Arrays
		}{
			{rs.Action.array, ArrayAction}, {rs.NotAction.array, ArrayNotAction},
			{rs.Resource.array, ArrayResource}, {rs.NotResource.array, ArrayNotResource},
		} {
			if f.set {
				s.Arrays |= f.flag
			}
		}

		ops := make([]string, 0, len(rs.Condition))
		for op := range rs.Condition {
			ops = append(ops, op)
		}

		sort.Strings(ops)

		for _, op := range ops {
			keys := make([]string, 0, len(rs.Condition[op]))
			for k := range rs.Condition[op] {
				keys = append(keys, k)
			}

			sort.Strings(keys)

			for _, k := range keys {
				v := rs.Condition[op][k]
				s.Condition = append(s.Condition, Condition{Operator: op, Key: k, Values: v.values, Array: v.array})
			}
		}

		out.Statement = append(out.Statement, s)
	}

	*d = out

	return nil
}
