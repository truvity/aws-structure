package cdkbootstrap

import (
	"bytes"
	_ "embed" // the vendored template
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

//go:embed template/bootstrap-template.yaml
var upstream []byte

//go:embed template/VERSION
var version string

// Version is the aws-cdk release the vendored template comes from.
func Version() string { return strings.TrimSpace(version) }

// Upstream returns the vendored template exactly as CDK ships it.
func Upstream() []byte { return bytes.Clone(upstream) }

const (
	// ExecutionRole is the logical id of the CloudFormation execution role, the
	// one resource CDK gives the boundary.
	ExecutionRole = "CloudFormationExecutionRole"

	typeRole = "AWS::IAM::Role"
	typeUser = "AWS::IAM::User"

	boundaryProperty = "PermissionsBoundary"
)

// Render returns the vendored template with the boundary on every role and
// user, as indented JSON ending in a newline.
func Render() ([]byte, error) { return Transform(upstream) }

// Transform copies the PermissionsBoundary of the CloudFormation execution
// role onto every AWS::IAM::Role and AWS::IAM::User of the template that has
// none, and returns the template as indented JSON. It refuses a template whose
// execution role is missing, is not a role, or has no PermissionsBoundary.
func Transform(raw []byte) ([]byte, error) {
	tpl, err := decodeTemplate(raw)
	if err != nil {
		return nil, err
	}

	resources, ok := tpl["Resources"].(map[string]any)
	if !ok {
		return nil, errors.New("transform: the template has no Resources")
	}

	boundary, err := executionBoundary(resources)
	if err != nil {
		return nil, err
	}

	for id, r := range resources {
		res, ok := r.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("transform: resource %s is not a mapping", id)
		}

		if t := res["Type"]; t != typeRole && t != typeUser {
			continue
		}

		props, ok := res["Properties"].(map[string]any)
		if !ok {
			if res["Properties"] != nil {
				return nil, fmt.Errorf("transform: resource %s has Properties that are not a mapping", id)
			}

			props = map[string]any{}
			res["Properties"] = props
		}

		if _, has := props[boundaryProperty]; has {
			continue
		}

		props[boundaryProperty] = deepCopy(boundary)
	}

	var buf bytes.Buffer

	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")

	if err := enc.Encode(tpl); err != nil {
		return nil, fmt.Errorf("transform: %w", err)
	}

	return buf.Bytes(), nil
}

// executionBoundary returns the PermissionsBoundary of the execution role.
func executionBoundary(resources map[string]any) (any, error) {
	exec, ok := resources[ExecutionRole].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("transform: the template has no %s", ExecutionRole)
	}

	if exec["Type"] != typeRole {
		return nil, fmt.Errorf("transform: %s is not an %s", ExecutionRole, typeRole)
	}

	props, _ := exec["Properties"].(map[string]any)

	boundary, ok := props[boundaryProperty]
	if !ok || boundary == nil {
		return nil, fmt.Errorf("transform: %s has no %s: CDK's template changed, and a role without a boundary must not be deployed", ExecutionRole, boundaryProperty)
	}

	return boundary, nil
}

func deepCopy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = deepCopy(x)
		}

		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = deepCopy(x)
		}

		return out
	default:
		return v
	}
}
