package cdkbootstrap_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/truvity/aws-structure/pkg/cdkbootstrap"
)

func decodeJSON(t *testing.T, raw []byte) map[string]any {
	t.Helper()

	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("not JSON: %v", err)
	}

	return m
}

func render(t *testing.T) map[string]any {
	t.Helper()

	out, err := cdkbootstrap.Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	return decodeJSON(t, out)
}

func resources(t *testing.T, tpl map[string]any) map[string]map[string]any {
	t.Helper()

	out := map[string]map[string]any{}

	for id, r := range tpl["Resources"].(map[string]any) {
		out[id] = r.(map[string]any)
	}

	return out
}

func isIAMPrincipal(res map[string]any) bool {
	return res["Type"] == "AWS::IAM::Role" || res["Type"] == "AWS::IAM::User"
}

// The vendored template is the one PROVENANCE names, and PROVENANCE is for the
// release VERSION names: a Renovate bump of VERSION alone fails here until
// hack/update-cdk-bootstrap.sh has fetched that release's template.
func TestVendoredTemplateMatchesProvenance(t *testing.T) {
	prov, err := os.ReadFile("template/PROVENANCE")
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(string(prov)), "\n")
	if len(lines) != 4 {
		t.Fatalf("PROVENANCE has %d lines, want 4:\n%s", len(lines), prov)
	}

	if want := "aws-cdk " + cdkbootstrap.Version(); lines[0] != want {
		t.Errorf("PROVENANCE names %q but template/VERSION is %q: run hack/update-cdk-bootstrap.sh", lines[0], want)
	}

	sum := sha256.Sum256(cdkbootstrap.Upstream())
	if want := "sha256-" + base64.StdEncoding.EncodeToString(sum[:]); lines[3] != want {
		t.Errorf("the template's digest is %s but PROVENANCE says %s: the template was edited; run hack/update-cdk-bootstrap.sh", want, lines[3])
	}

	if !strings.HasPrefix(lines[2], "sha512-") {
		t.Errorf("PROVENANCE integrity %q is not sha512", lines[2])
	}
}

// Every role and user carries the execution role's boundary, which is the
// condition on the template's InputPermissionsBoundary parameter.
func TestEveryRoleCarriesTheBoundary(t *testing.T) {
	res := resources(t, render(t))

	exec := res[cdkbootstrap.ExecutionRole]["Properties"].(map[string]any)["PermissionsBoundary"]
	if exec == nil {
		t.Fatal("the execution role has no boundary")
	}

	roles := 0

	for id, r := range res {
		if !isIAMPrincipal(r) {
			continue
		}

		roles++

		got := r["Properties"].(map[string]any)["PermissionsBoundary"]
		if !reflect.DeepEqual(got, exec) {
			t.Errorf("%s: PermissionsBoundary = %v, want %v", id, got, exec)
		}
	}

	// File and image publishing, lookup, deployment action and execution.
	if roles != 5 {
		t.Errorf("the template has %d IAM roles or users, want 5: CDK's template changed, read it", roles)
	}

	b, _ := json.Marshal(exec)
	if !strings.Contains(string(b), "InputPermissionsBoundary") || !strings.Contains(string(b), "PermissionsBoundarySet") {
		t.Errorf("the boundary %s is not the condition on InputPermissionsBoundary", b)
	}
}

// The only difference from upstream is the added property. Upstream is parsed
// here by a plain YAML decoder, independent of the package's own, and the two
// trees are compared path by path.
func TestOnlyDifferenceFromUpstreamIsTheBoundary(t *testing.T) {
	var up any
	if err := yaml.Unmarshal(cdkbootstrap.Upstream(), &up); err != nil {
		t.Fatal(err)
	}

	// Normalize the types the way a JSON round trip does (ints become floats).
	raw, err := json.Marshal(up)
	if err != nil {
		t.Fatal(err)
	}

	var base any

	if err := json.Unmarshal(raw, &base); err != nil {
		t.Fatal(err)
	}

	var diffs []string

	walk("", base, render(t), &diffs)
	slices.Sort(diffs)

	want := []string{
		"Resources.DeploymentActionRole.Properties.PermissionsBoundary",
		"Resources.FilePublishingRole.Properties.PermissionsBoundary",
		"Resources.ImagePublishingRole.Properties.PermissionsBoundary",
		"Resources.LookupRole.Properties.PermissionsBoundary",
	}

	if !slices.Equal(diffs, want) {
		t.Errorf("the output differs from upstream at\n  %s\nwant\n  %s", strings.Join(diffs, "\n  "), strings.Join(want, "\n  "))
	}
}

// walk records the paths at which b differs from a. A key only b has is a path;
// anything else that differs is too.
func walk(path string, a, b any, out *[]string) {
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)

	if aok && bok {
		for k, av := range am {
			bv, ok := bm[k]
			if !ok {
				*out = append(*out, join(path, k)+" (removed)")

				continue
			}

			walk(join(path, k), av, bv, out)
		}

		for k := range bm {
			if _, ok := am[k]; !ok {
				*out = append(*out, join(path, k))
			}
		}

		return
	}

	if !reflect.DeepEqual(a, b) {
		*out = append(*out, path)
	}
}

func join(path, k string) string {
	if path == "" {
		return k
	}

	return path + "." + k
}

// The output is the reviewed bootstrap template: what a CfnInclude of the same
// CDK release, with the boundary copied to every role, synthesizes.
func TestEqualsReviewedReference(t *testing.T) {
	ref, err := os.ReadFile("testdata/reference.json")
	if err != nil {
		t.Fatal(err)
	}

	got := render(t)
	want := decodeJSON(t, ref)

	if !reflect.DeepEqual(got, want) {
		gb, _ := json.MarshalIndent(got, "", " ")
		wb, _ := json.MarshalIndent(want, "", " ")
		t.Errorf("rendered template differs from testdata/reference.json\n got %d bytes, want %d bytes", len(gb), len(wb))
		_ = os.WriteFile(t.TempDir()+"/got.json", gb, 0o600)
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	a, err := cdkbootstrap.Render()
	if err != nil {
		t.Fatal(err)
	}

	b, _ := cdkbootstrap.Render()
	if !bytes.Equal(a, b) {
		t.Error("two renders differ")
	}

	if !bytes.HasSuffix(a, []byte("}\n")) {
		t.Error("output does not end in a newline")
	}
}
