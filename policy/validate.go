package policy

import (
	"errors"
	"fmt"
	"regexp"
)

var sidPattern = regexp.MustCompile(`^[A-Za-z0-9]+$`)

// Validate reports every problem with d at once, or returns nil. It checks
// what IAM refuses and the shape this model relies on:
//
//   - Version is empty or [Version];
//   - there is at least one statement;
//   - every statement has a Sid of ASCII letters and digits, unique in the
//     document (a system that appends statements finds its own by Sid);
//   - Effect is [Allow] or [Deny];
//   - exactly one of Action and NotAction is set, and exactly one of Resource
//     and NotResource;
//   - no list holds an empty string;
//   - every condition has an operator, a key and at least one value, and no
//     operator and key appear twice in a statement.
func (d Document) Validate() error {
	var errs []error

	if d.Version != "" && d.Version != Version {
		errs = append(errs, fmt.Errorf("policy: Version is %q, want %q", d.Version, Version))
	}

	if len(d.Statement) == 0 {
		errs = append(errs, errors.New("policy: no statement"))
	}

	seen := map[string]int{}

	for i := range d.Statement {
		errs = append(errs, d.Statement[i].validate(i, seen)...)
	}

	return errors.Join(errs...)
}

func (s Statement) validate(i int, seen map[string]int) []error {
	var errs []error

	label := fmt.Sprintf("statement %d", i)
	if s.Sid != "" {
		label = fmt.Sprintf("statement %d (%s)", i, s.Sid)
	}

	switch {
	case s.Sid == "":
		errs = append(errs, fmt.Errorf("policy: %s has no Sid", label))
	case !sidPattern.MatchString(s.Sid):
		errs = append(errs, fmt.Errorf("policy: %s: Sid %q is not ASCII letters and digits only", label, s.Sid))
	default:
		if first, dup := seen[s.Sid]; dup {
			errs = append(errs, fmt.Errorf("policy: %s: Sid %q is also the Sid of statement %d", label, s.Sid, first))
		} else {
			seen[s.Sid] = i
		}
	}

	if s.Effect != Allow && s.Effect != Deny {
		errs = append(errs, fmt.Errorf("policy: %s: Effect is %q, want %q or %q", label, s.Effect, Allow, Deny))
	}

	errs = append(errs, exactlyOne(label, "Action", s.Action, "NotAction", s.NotAction)...)
	errs = append(errs, exactlyOne(label, "Resource", s.Resource, "NotResource", s.NotResource)...)

	seenCond := map[[2]string]bool{}

	for j, c := range s.Condition {
		switch {
		case c.Operator == "":
			errs = append(errs, fmt.Errorf("policy: %s: condition %d has no operator", label, j))
		case c.Key == "":
			errs = append(errs, fmt.Errorf("policy: %s: condition %d (%s) has no key", label, j, c.Operator))
		case len(c.Values) == 0:
			errs = append(errs, fmt.Errorf("policy: %s: condition %s on %s has no value", label, c.Operator, c.Key))
		}

		for _, v := range c.Values {
			if v == "" {
				errs = append(errs, fmt.Errorf("policy: %s: condition %s on %s has an empty value", label, c.Operator, c.Key))
			}
		}

		id := [2]string{c.Operator, c.Key}
		if seenCond[id] {
			errs = append(errs, fmt.Errorf("policy: %s: two conditions %s on %s", label, c.Operator, c.Key))
		}

		seenCond[id] = true
	}

	return errs
}

func exactlyOne(label, aName string, a []string, bName string, b []string) []error {
	var errs []error

	switch {
	case len(a) == 0 && len(b) == 0:
		errs = append(errs, fmt.Errorf("policy: %s has neither %s nor %s", label, aName, bName))
	case len(a) > 0 && len(b) > 0:
		errs = append(errs, fmt.Errorf("policy: %s has both %s and %s", label, aName, bName))
	}

	for _, e := range []struct {
		name string
		v    []string
	}{{aName, a}, {bName, b}} {
		for _, x := range e.v {
			if x == "" {
				errs = append(errs, fmt.Errorf("policy: %s: %s has an empty entry", label, e.name))

				break
			}
		}
	}

	return errs
}
