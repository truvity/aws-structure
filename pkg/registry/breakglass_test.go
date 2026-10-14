package registry_test

import (
	"strings"
	"testing"

	"github.com/truvity/aws-structure/pkg/registry"
)

const breakGlass = `
  break_glass:
    principal: admins
    permission_set: admin
waivers:
  - guard: scp-on-management
    target: platform
    reason: the deny-leave policy is safe on the management OU
    exit_condition: the management account moves to its own OU
    expires: "2027-01-31"
`

const bgLines = "    principal: admins\n    permission_set: admin"

func withBreakGlass() string {
	return strings.Replace(valid, "      ous: [workloads]\n", "      ous: [workloads]\n"+strings.TrimPrefix(breakGlass, "\n"), 1)
}

func TestBreakGlassAndWaiversParse(t *testing.T) {
	r, err := registry.Parse([]byte(withBreakGlass()))
	if err != nil {
		t.Fatal(err)
	}

	bg := r.IdentityCenter.BreakGlass
	if bg == nil || bg.Principal != "admins" || bg.PermissionSet != "admin" || bg.PrincipalType != "group" {
		t.Fatalf("break glass = %+v", bg)
	}

	if len(r.Waivers) != 1 || r.Waivers[0].Expires != "2027-01-31" {
		t.Fatalf("waivers = %+v", r.Waivers)
	}
}

func TestBreakGlassAndWaiverRefusals(t *testing.T) {
	tests := []struct{ name, old, new, want string }{
		{"break glass unknown group", bgLines, "    principal: ghost\n    permission_set: admin", "break_glass: group \"ghost\""},
		{"break glass unknown set", bgLines, "    principal: admins\n    permission_set: ghost", "break_glass: permission set \"ghost\""},
		{"break glass bad type", bgLines, "    principal: admins\n    principal_type: robot\n    permission_set: admin", "not group or user"},
		{"waiver unknown guard", "guard: scp-on-management", "guard: anything", "is not \"scp-on-management\""},
		{"waiver unknown target", "target: platform", "target: ghost", "not root or a declared"},
		{"waiver without reason", "    reason: the deny-leave policy is safe on the management OU\n", "", "has no reason"},
		{"waiver without exit", "    exit_condition: the management account moves to its own OU\n", "", "has no exit_condition"},
		{"waiver bad date", `expires: "2027-01-31"`, `expires: "next year"`, "not YYYY-MM-DD"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := withBreakGlass()
			if !strings.Contains(doc, tt.old) {
				t.Fatalf("test bug: %q not in the fixture", tt.old)
			}

			_, err := registry.Parse([]byte(strings.Replace(doc, tt.old, tt.new, 1)))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want an error mentioning %q", err, tt.want)
			}
		})
	}
}

func TestWaiverRootTargetAccepted(t *testing.T) {
	doc := strings.Replace(withBreakGlass(), "target: platform", "target: root", 1)
	if _, err := registry.Parse([]byte(doc)); err != nil {
		t.Fatal(err)
	}
}
