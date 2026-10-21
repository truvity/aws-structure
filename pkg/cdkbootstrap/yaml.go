package cdkbootstrap

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"go.yaml.in/yaml/v3"
)

// decodeTemplate parses a CloudFormation template in YAML into the generic
// shape encoding/json produces for the same template written as JSON. The
// short-form intrinsic functions are rewritten to their long form: "!Ref x"
// becomes {"Ref": "x"}, "!GetAtt a.b" becomes {"Fn::GetAtt": ["a", "b"]}, and
// every other "!Name v" becomes {"Fn::Name": v}; "!Condition x" becomes
// {"Condition": "x"}.
func decodeTemplate(raw []byte) (map[string]any, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))

	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}

	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse template: more than one YAML document")
	}

	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, errors.New("parse template: empty document")
	}

	v, err := convert(doc.Content[0])
	if err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}

	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("parse template: the document is not a mapping")
	}

	return m, nil
}

// intrinsicName returns the long form of a short-form tag, and whether the tag
// is one.
func intrinsicName(tag string) (string, bool) {
	if !strings.HasPrefix(tag, "!") || strings.HasPrefix(tag, "!!") || len(tag) == 1 {
		return "", false
	}

	name := tag[1:]

	switch name {
	case "Ref", "Condition":
		return name, true
	default:
		return "Fn::" + name, true
	}
}

func convert(n *yaml.Node) (any, error) {
	if n.Kind == yaml.AliasNode {
		return convert(n.Alias)
	}

	name, intrinsic := intrinsicName(n.Tag)

	inner, err := convertPlain(n, intrinsic)
	if err != nil {
		return nil, err
	}

	if !intrinsic {
		return inner, nil
	}

	if name == "Fn::GetAtt" {
		if s, ok := inner.(string); ok {
			// "!GetAtt Resource.Attribute": the attribute may itself hold dots.
			res, attr, found := strings.Cut(s, ".")
			if !found {
				return nil, fmt.Errorf("line %d: !GetAtt %q has no attribute", n.Line, s)
			}

			inner = []any{res, attr}
		}
	}

	return map[string]any{name: inner}, nil
}

// convertPlain converts the node's value, ignoring a short-form tag on the
// node itself (the caller wraps it). A scalar under a short-form tag is taken
// as the string it spells.
func convertPlain(n *yaml.Node, tagged bool) (any, error) {
	switch n.Kind {
	case yaml.ScalarNode:
		if tagged {
			return n.Value, nil
		}

		var v any
		if err := n.Decode(&v); err != nil {
			return nil, fmt.Errorf("line %d: %w", n.Line, err)
		}

		return v, nil
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))

		for _, c := range n.Content {
			v, err := convert(c)
			if err != nil {
				return nil, err
			}

			out = append(out, v)
		}

		return out, nil
	case yaml.MappingNode:
		out := make(map[string]any, len(n.Content)/2)

		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("line %d: a mapping key is not a scalar", k.Line)
			}

			if _, dup := out[k.Value]; dup {
				return nil, fmt.Errorf("line %d: key %q is repeated", k.Line, k.Value)
			}

			v, err := convert(n.Content[i+1])
			if err != nil {
				return nil, err
			}

			out[k.Value] = v
		}

		return out, nil
	default:
		return nil, fmt.Errorf("line %d: unexpected YAML node", n.Line)
	}
}
