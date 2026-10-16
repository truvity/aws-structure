package sso

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/truvity/aws-structure/pkg/registry"
)

// OrgAdminSid is the Sid of the organization-admin inline policy statement.
const OrgAdminSid = "OrganizationAdmin"

// OrgAdminActions returns the action patterns of organization administration:
// the actions a caller grants an admin permission set, by inline policy, so
// that one set is both the member-account admin and the organization
// administrator of the management account. It returns a new slice each call.
//
// The identity policy alone is not what gives the access: the effective
// permission is the identity policy intersected with the permissions
// boundary, and the boundary is resolved by name in each account. Pair this
// with pkg/boundary: boundary.OrgAdminManagement in the management account
// (allows these actions) and boundary.OrgAdminMember in every member account
// (denies them, so the set's permissions there do not change).
func OrgAdminActions() []string {
	return []string{"organizations:*", "account:*", "sso:*", "sso-directory:*", "identitystore:*"}
}

// OrgAdminStatement returns the inline policy statement that allows
// OrgAdminActions on every resource, as a value to place in a policy's
// Statement list.
func OrgAdminStatement() map[string]any {
	return map[string]any{
		"Sid":      OrgAdminSid,
		"Effect":   "Allow",
		"Action":   OrgAdminActions(),
		"Resource": "*",
	}
}

// OrgAdminInlinePolicy returns the inline policy JSON for an admin permission
// set: base (the set's current registry.PermissionSet.InlinePolicy, which may
// be empty) with the OrgAdminStatement added. A base that already carries a
// statement with the Sid OrgAdminSid is returned re-rendered, unchanged in
// meaning. The caller decides whether to use it; nothing in this package
// attaches it.
//
// It refuses a base that is not a JSON policy object, and one over the size
// AWS allows for an inline policy.
func OrgAdminInlinePolicy(base string) (string, error) {
	doc := map[string]any{"Version": "2012-10-17"}

	if len(bytes.TrimSpace([]byte(base))) > 0 {
		if err := json.Unmarshal([]byte(base), &doc); err != nil {
			return "", fmt.Errorf("sso: base inline policy is not a JSON object: %w", err)
		}
	}

	var stmts []any

	switch v := doc["Statement"].(type) {
	case nil:
	case []any:
		stmts = v
	case map[string]any:
		stmts = []any{v}
	default:
		return "", errors.New("sso: base inline policy has a Statement that is neither a list nor an object")
	}

	for _, s := range stmts {
		if m, ok := s.(map[string]any); ok && m["Sid"] == OrgAdminSid {
			doc["Statement"] = stmts

			return render(doc)
		}
	}

	doc["Statement"] = append(stmts, OrgAdminStatement())

	return render(doc)
}

func render(doc map[string]any) (string, error) {
	b, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}

	if len(b) > registry.MaxInlinePolicyBytes {
		return "", fmt.Errorf("sso: inline policy is %d bytes, over the %d AWS allows", len(b), registry.MaxInlinePolicyBytes)
	}

	return string(b), nil
}
