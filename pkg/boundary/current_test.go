package boundary_test

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/truvity/aws-structure/pkg/boundary"
)

// maxPolicyChars is IAM's limit on a managed policy document (white space
// removed).
const maxPolicyChars = 6144

// currentSpec names the role/controller/project shapes only.
func currentSpec() boundary.Spec {
	admin := []string{
		"bound@role-deployer", "bound@role-auditor", "bound@default", "bound@tech-ack-iam", "bound@tech-ack-eks",
		"bound@tech-ack-s3", "bound@tech-ack-kms", "bound@tech-ack-dynamodb", "bound@tech-project-ack",
		"bound@tech-employee-ack", "bound@tech-project-workload", "bound@tech-node",
	}

	return boundary.Spec{
		Partition: "part",
		Prefix:    "bound@",
		Names: boundary.Names{
			Default: "bound@default", EKSAutoNode: "bound@tech-node",
			RoleAdmin: "bound@role-admin", RoleDeployer: "bound@role-deployer", RoleAuditor: "bound@role-auditor",
			ACKControllerIAM: "bound@tech-ack-iam", ACKControllerEKS: "bound@tech-ack-eks",
			ACKControllerS3: "bound@tech-ack-s3", ACKControllerKMS: "bound@tech-ack-kms",
			ACKControllerDynamoDB: "bound@tech-ack-dynamodb",
			ProjectACK:            "bound@tech-project-ack", EmployeeACK: "bound@tech-employee-ack",
			ProjectWorkload: "bound@tech-project-workload",
		},
		Hierarchy: []boundary.Entry{
			{Name: "bound@role-admin", Delegates: admin},
			{Name: "bound@role-deployer", Delegates: []string{"bound@tech-project-workload"}, EnforcesTags: []string{"project", "cluster"}},
			{Name: "bound@role-auditor"},
			{Name: "bound@default"},
			{Name: "bound@tech-node"},
			{Name: "bound@tech-ack-iam", Delegates: []string{"bound@default"}},
			{Name: "bound@tech-ack-eks"},
			{Name: "bound@tech-ack-s3"},
			{Name: "bound@tech-ack-kms"},
			{Name: "bound@tech-ack-dynamodb"},
			{Name: "bound@tech-project-ack", Delegates: []string{"bound@tech-project-workload"}},
			{Name: "bound@tech-employee-ack", Delegates: []string{"bound@tech-project-workload"}},
			{Name: "bound@tech-project-workload"},
		},
		ProjectBucketPrefix: "acme-",
		ACK: boundary.ACKScope{
			BuilderRoles:         []string{"*-builder-*", "*-sandbox-*"},
			IAMNamespace:         "db-system",
			IAMRoleSlugs:         []string{"db"},
			PodIdentityRoleSlugs: []string{"lab"},
			Buckets:              []string{"acme-*-cache", "acme-*-scratch"},
		},
	}
}

// transitionSpec is currentSpec in its transition form: the legacy names of
// project roles and buckets are accepted, and the role boundaries still
// delegate the legacy boundaries.
func transitionSpec() boundary.Spec {
	s := currentSpec()
	s.LegacyProjectNames = true
	s.Hierarchy[0].Delegates = append(s.Hierarchy[0].Delegates, "bound@project", "bound@old")
	s.Hierarchy[1].Delegates = append(s.Hierarchy[1].Delegates, "bound@project", "bound@default")
	s.Hierarchy = append(s.Hierarchy, boundary.Entry{Name: "bound@project"}, boundary.Entry{Name: "bound@old"})

	return s
}

// bothSpec carries both generations.
func bothSpec() boundary.Spec {
	l, c := spec(), currentSpec()
	l.Names.RoleAdmin, l.Names.RoleDeployer, l.Names.RoleAuditor = c.Names.RoleAdmin, c.Names.RoleDeployer, c.Names.RoleAuditor
	l.Names.ACKControllerIAM, l.Names.ACKControllerEKS = c.Names.ACKControllerIAM, c.Names.ACKControllerEKS
	l.Names.ACKControllerS3, l.Names.ACKControllerKMS = c.Names.ACKControllerS3, c.Names.ACKControllerKMS
	l.Names.ACKControllerDynamoDB = c.Names.ACKControllerDynamoDB
	l.Names.ProjectACK, l.Names.EmployeeACK, l.Names.ProjectWorkload = c.Names.ProjectACK, c.Names.EmployeeACK, c.Names.ProjectWorkload
	l.ProjectBucketPrefix, l.ACK = c.ProjectBucketPrefix, c.ACK

	// One hierarchy: the current entries, then the legacy ones. Default is shared.
	for _, e := range l.Hierarchy {
		if e.Name != "bound@default" {
			c.Hierarchy = append(c.Hierarchy, e)
		}
	}

	c.Hierarchy[0].Delegates = append(c.Hierarchy[0].Delegates, "bound@admin", "bound@deploy", "bound@project", "bound@tech-iam", "bound@tech-capa")
	l.Hierarchy = c.Hierarchy

	return l
}

func docs(t *testing.T, s boundary.Spec) map[string]string {
	t.Helper()

	ps, err := boundary.Policies(s)
	if err != nil {
		t.Fatal(err)
	}

	out := map[string]string{}
	for _, p := range ps {
		out[p.Name] = p.Document
	}

	return out
}

// goldenIndented compares got with testdata/<name>, written indented so that a
// review reads the document.
func goldenIndented(t *testing.T, name, got string) {
	t.Helper()

	var b bytes.Buffer
	if err := json.Indent(&b, []byte(got), "", "  "); err != nil {
		t.Fatal(err)
	}

	golden(t, name, strings.TrimSuffix(b.String(), "\n"))
}

// variants are every rendered form of the role/controller/project shapes.
func variants(t *testing.T) map[string]string {
	t.Helper()

	out := map[string]string{}

	add := func(prefix string, s boundary.Spec, names ...string) {
		d := docs(t, s)

		for _, n := range names {
			doc, ok := d[n]
			if !ok {
				t.Fatalf("no document %s", n)
			}

			out[prefix+strings.TrimPrefix(n, "bound@")] = doc
		}
	}

	member, mgmt := currentSpec(), currentSpec()
	member.OrgAdmin, mgmt.OrgAdmin = boundary.OrgAdminMember, boundary.OrgAdminManagement

	trMember := transitionSpec()
	trMember.OrgAdmin = boundary.OrgAdminMember

	all := []string{
		"bound@role-admin", "bound@role-deployer", "bound@role-auditor", "bound@tech-ack-iam", "bound@tech-ack-eks",
		"bound@tech-ack-s3", "bound@tech-ack-kms", "bound@tech-ack-dynamodb", "bound@tech-project-ack",
		"bound@tech-employee-ack", "bound@tech-project-workload",
	}

	add("final-member-", member, all...)
	add("final-management-", mgmt, "bound@role-admin")
	add("transition-member-", trMember, all...)

	return out
}

func TestCurrentGoldens(t *testing.T) {
	for name, doc := range variants(t) {
		goldenIndented(t, filepath.Join("current", name+".json"), doc)
	}
}

func TestEveryDocumentFitsTheManagedPolicyLimit(t *testing.T) {
	for name, doc := range variants(t) {
		if !json.Valid([]byte(doc)) {
			t.Errorf("%s is not valid JSON", name)
		}

		var b bytes.Buffer
		if err := json.Compact(&b, []byte(doc)); err != nil {
			t.Fatal(err)
		}

		if n := b.Len(); n > maxPolicyChars {
			t.Errorf("%s is %d characters, over IAM's %d", name, n, maxPolicyChars)
		} else {
			t.Logf("%-40s %5d", name, n)
		}
	}
}

// The legacy documents are unchanged by naming the new shapes beside them, so
// both generations can run during a migration.
func TestLegacyDocumentsUnchangedByCurrentShapes(t *testing.T) {
	legacy := docs(t, spec())
	both := docs(t, bothSpec())

	for name, doc := range legacy {
		if both[name] != doc {
			t.Errorf("%s changed when the role shapes were added", name)
		}
	}

	if len(both) != len(legacy)+len(docs(t, currentSpec()))-2 {
		t.Errorf("both generations render %d documents, legacy %d, current %d", len(both), len(legacy), len(docs(t, currentSpec())))
	}

	for _, name := range []string{"bound@default", "bound@tech-node"} {
		if docs(t, currentSpec())[name] != legacy[name] {
			t.Errorf("%s differs between the generations", name)
		}
	}
}

func TestPoliciesOrderCurrent(t *testing.T) {
	ps, err := boundary.Policies(currentSpec())
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	for _, p := range ps {
		got = append(got, p.Name)
	}

	want := []string{
		"bound@default", "bound@tech-node", "bound@role-admin", "bound@role-deployer", "bound@role-auditor",
		"bound@tech-ack-iam", "bound@tech-ack-eks", "bound@tech-ack-s3", "bound@tech-ack-kms",
		"bound@tech-ack-dynamodb", "bound@tech-project-ack", "bound@tech-employee-ack", "bound@tech-project-workload",
	}

	if !slices.Equal(got, want) {
		t.Errorf("policies = %v\nwant %v", got, want)
	}
}

// Renaming changes nothing but the name: the role boundaries are the legacy
// documents with an exact delegation list.
func TestRoleBoundariesAreTheLegacyDocuments(t *testing.T) {
	cur := docs(t, bothSpec())

	if cur["bound@role-auditor"] != cur["bound@audit"] {
		t.Error("role-auditor is the audit document")
	}

	for _, mode := range []boundary.OrgAdminMode{boundary.OrgAdminOff, boundary.OrgAdminMember, boundary.OrgAdminManagement} {
		s := bothSpec()
		s.OrgAdmin = mode
		d := docs(t, s)

		a, b := parse(t, d["bound@admin"]), parse(t, d["bound@role-admin"])
		if !slices.Equal(sids(a), sids(b)) {
			t.Errorf("mode %q: role-admin statements %v, admin %v", mode, sids(b), sids(a))
		}
	}
}

func TestRoleAdminDelegatesExactNames(t *testing.T) {
	s := currentSpec()
	got := s.DelegateARNs("bound@role-admin")

	if got[0] != "arn:part:iam::*:policy/bound@role-admin" {
		t.Errorf("role-admin does not name itself first: %v", got)
	}

	if len(got) != 13 {
		t.Errorf("role-admin delegates %d boundaries, want itself and 12: %v", len(got), got)
	}

	for _, a := range got {
		if strings.ContainsAny(a, "*?") && !strings.Contains(a, "iam::*:policy/") {
			t.Errorf("wildcard in a delegation: %s", a)
		}

		if strings.Contains(strings.TrimPrefix(a, "arn:part:iam::*:policy/"), "*") {
			t.Errorf("delegation %q is a pattern, not a name", a)
		}
	}

	doc := docs(t, s)["bound@role-admin"]
	if strings.Contains(doc, "bound@tech-*") || strings.Contains(doc, "bound@tech-\\u002a") {
		t.Error("role-admin delegates a class by wildcard")
	}

	// A boundary that is not in the list is not delegated: a future
	// "bound@tech-project-evil" is out of reach.
	if slices.Contains(got, "arn:part:iam::*:policy/bound@tech-project-evil") {
		t.Error("an unlisted boundary is delegated")
	}
}

func TestDelegationWildcardsRefused(t *testing.T) {
	s := currentSpec()
	s.Hierarchy[0].Delegates = append(s.Hierarchy[0].Delegates, "bound@tech-*")
	s.Hierarchy = append(s.Hierarchy, boundary.Entry{Name: "bound@tech-*"})

	err := s.Validate()
	if err == nil || !strings.Contains(err.Error(), "is a pattern") {
		t.Errorf("a wildcard delegate was accepted: %v", err)
	}
}

// A project boundary delegates exactly the workload boundary, by exact name:
// anything wider lets a project mint a role under a boundary that mints roles.
func TestBuildersDelegateOnlyTheWorkloadBoundary(t *testing.T) {
	for _, mk := range []func() boundary.Spec{currentSpec, transitionSpec} {
		s := mk()

		for _, name := range []string{"bound@tech-project-ack", "bound@tech-employee-ack"} {
			got := s.DelegateARNs(name)
			if len(got) != 1 || got[0] != "arn:part:iam::*:policy/bound@tech-project-workload" {
				t.Errorf("%s delegates %v", name, got)
			}

			doc := docs(t, s)[name]
			// Once to create a role and once to set the boundary on one, nowhere else.
			if n := strings.Count(doc, "policy/bound@tech-project-workload"); n != 2 {
				t.Errorf("%s names the workload boundary %d times, want 2", name, n)
			}
		}
	}

	for name, mutate := range map[string]func(*boundary.Spec){
		"wider": func(s *boundary.Spec) {
			s.Hierarchy[10].Delegates = []string{"bound@tech-project-workload", "bound@default"}
		},
		"none":      func(s *boundary.Spec) { s.Hierarchy[11].Delegates = nil },
		"different": func(s *boundary.Spec) { s.Hierarchy[10].Delegates = []string{"bound@default"} },
	} {
		s := currentSpec()
		mutate(&s)

		if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "must delegate to exactly") {
			t.Errorf("%s: builder hierarchy accepted: %v", name, err)
		}
	}

	// Controllers that reach IAM and the deployer need a boundary to hand out.
	s := currentSpec()
	s.Hierarchy[5].Delegates = nil

	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "must delegate to at least one") {
		t.Errorf("an IAM controller without delegates was accepted: %v", err)
	}
}

func actionsOfEffect(t *testing.T, document, effect string) []string {
	t.Helper()

	var d struct {
		Statement []struct {
			Effect string
			Action any
		}
	}

	if err := json.Unmarshal([]byte(document), &d); err != nil {
		t.Fatal(err)
	}

	var out []string

	for _, s := range d.Statement {
		if s.Effect == effect {
			out = append(out, actions(s.Action)...)
		}
	}

	return out
}

type fullStatement struct {
	Sid         string
	Effect      string
	Action      any
	Resource    any
	NotResource any
	Condition   map[string]map[string]any
}

func statements(t *testing.T, document string) map[string]fullStatement {
	t.Helper()

	var d struct{ Statement []fullStatement }
	if err := json.Unmarshal([]byte(document), &d); err != nil {
		t.Fatal(err)
	}

	out := map[string]fullStatement{}
	for _, s := range d.Statement {
		if _, dup := out[s.Sid]; dup {
			t.Fatalf("statement id %s twice", s.Sid)
		}

		out[s.Sid] = s
	}

	return out
}

func asList(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, e.(string))
		}

		return out
	}

	return nil
}

// project and cluster are the anchor: a builder may not set them to anything
// but its own value, nor remove them, however it is spelled.
func TestBuildersGuardTheProjectAndClusterTags(t *testing.T) {
	for form, s := range map[string]boundary.Spec{"final": currentSpec(), "transition": transitionSpec()} {
		for _, name := range []string{"bound@tech-project-ack", "bound@tech-employee-ack"} {
			st := statements(t, docs(t, s)[name])

			for _, key := range []string{"project", "cluster"} {
				sid := map[string]string{"project": "DenyRetagProjectOrCluster", "cluster": "DenyRetagClusterTag"}[key]

				d, ok := st[sid]
				if !ok || d.Effect != "Deny" {
					t.Errorf("%s %s: no Deny %s", form, name, sid)

					continue
				}

				if !slices.Contains(asList(d.Action), "iam:TagRole") || !slices.Contains(asList(d.Action), "iam:CreateRole") {
					t.Errorf("%s %s: %s does not cover TagRole and CreateRole: %v", form, name, sid, d.Action)
				}

				if asList(d.Resource)[0] != "*" {
					t.Errorf("%s %s: %s is scoped to %v", form, name, sid, d.Resource)
				}

				own := "${aws:PrincipalTag/" + key + "}"
				if got := d.Condition["StringNotEquals"]["aws:RequestTag/"+key]; got != own {
					t.Errorf("%s %s: %s compares with %v, want the builder's own %s", form, name, sid, got, own)
				}

				if d.Condition["Null"]["aws:RequestTag/"+key] != "false" {
					t.Errorf("%s %s: %s applies to requests without the tag", form, name, sid)
				}
			}

			un, ok := st["DenyUntagProjectOrCluster"]
			if !ok || un.Effect != "Deny" || asList(un.Action)[0] != "iam:UntagRole" {
				t.Errorf("%s %s: no Deny of UntagRole", form, name)
			} else if keys := asList(un.Condition["ForAnyValue:StringEquals"]["aws:TagKeys"]); !slices.Equal(keys, []string{"project", "cluster"}) {
				t.Errorf("%s %s: untag guard covers tag keys %v", form, name, keys)
			}

			// Nothing that can re-tag is allowed without the project tag on the target.
			for sid, s := range st {
				if s.Effect != "Allow" {
					continue
				}

				for _, a := range asList(s.Action) {
					if a != "iam:TagRole" && a != "iam:UntagRole" {
						continue
					}

					if s.Condition["StringEquals"]["aws:ResourceTag/project"] != "${aws:PrincipalTag/project}" {
						t.Errorf("%s %s: %s allows %s on a role that does not carry the builder's project", form, name, sid, a)
					}
				}
			}
		}
	}
}

func TestBuildersCannotRetireKeysEditKeyPoliciesOrReachData(t *testing.T) {
	for _, name := range []string{"bound@tech-project-ack", "bound@tech-employee-ack"} {
		doc := docs(t, transitionSpec())[name]
		allowed := actionsOfEffect(t, doc, "Allow")

		for _, banned := range []string{
			"kms:PutKeyPolicy", "kms:CreateGrant", "kms:ScheduleKeyDeletion", "kms:DisableKey", "kms:Decrypt",
			"s3:GetObject", "s3:PutObject", "iam:CreateUser", "iam:CreateOpenIDConnectProvider",
			"iam:CreateInstanceProfile", "ssm:*", "dynamodb:*", "sqs:*", "*",
		} {
			if slices.Contains(allowed, banned) {
				t.Errorf("%s allows %s", name, banned)
			}
		}

		for _, wild := range allowed {
			if wild == "kms:*" || wild == "s3:*" || wild == "iam:*" {
				t.Errorf("%s allows %s", name, wild)
			}
		}

		denied := actionsOfEffect(t, doc, "Deny")
		for _, want := range []string{"kms:ScheduleKeyDeletion", "kms:DisableKey"} {
			if !slices.Contains(denied, want) {
				t.Errorf("%s does not deny %s", name, want)
			}
		}
	}
}

func TestWorkloadBoundaryHasNoIAMAndKeysOnTheRoleTags(t *testing.T) {
	for form, s := range map[string]boundary.Spec{"final": currentSpec(), "transition": transitionSpec()} {
		doc := docs(t, s)["bound@tech-project-workload"]
		st := statements(t, doc)

		if d := st["DenyIAM"]; d.Effect != "Deny" || asList(d.Action)[0] != "iam:*" {
			t.Errorf("%s: no Deny of iam:*", form)
		}

		if k := st["AllowKMSUseOwnProjectKeys"]; k.Condition["StringEquals"]["aws:ResourceTag/project"] != "${aws:PrincipalTag/project}" {
			t.Errorf("%s: keys are not scoped to the principal's project tag", form)
		}

		for _, a := range actionsOfEffect(t, doc, "Allow") {
			if strings.HasPrefix(a, "iam:") || strings.HasPrefix(a, "sts:") || a == "*" {
				t.Errorf("%s: workload allows %s", form, a)
			}
		}
	}
}

func TestTransitionDiffersOnlyByLegacyNames(t *testing.T) {
	final, tr := docs(t, currentSpec()), docs(t, transitionSpec())

	for _, name := range []string{"bound@tech-project-ack", "bound@tech-project-workload", "bound@role-deployer"} {
		if final[name] == tr[name] {
			t.Errorf("%s: the transition form equals the final form", name)
		}
	}

	for _, name := range []string{
		"bound@tech-employee-ack", "bound@role-auditor", "bound@tech-ack-iam", "bound@tech-ack-eks",
		"bound@tech-ack-s3", "bound@tech-ack-kms", "bound@tech-ack-dynamodb",
	} {
		if final[name] != tr[name] {
			t.Errorf("%s changes with LegacyProjectNames", name)
		}
	}

	const legacyRole = "role/${aws:PrincipalTag/cluster}-*${aws:PrincipalTag/project}-*"

	for _, name := range []string{"bound@tech-project-ack", "bound@tech-project-workload"} {
		if strings.Contains(final[name], "-*${aws:PrincipalTag/project}-*") {
			t.Errorf("%s (final) accepts a legacy name", name)
		}
	}

	if !strings.Contains(tr["bound@tech-project-ack"], legacyRole) ||
		!strings.Contains(tr["bound@tech-project-ack"], "policy/${aws:PrincipalTag/cluster}-*${aws:PrincipalTag/project}-*") ||
		!strings.Contains(tr["bound@tech-project-ack"], "acme-${aws:PrincipalTag/cluster}-*${aws:PrincipalTag/project}-*") {
		t.Error("the transition builder lacks a legacy role, policy or bucket pattern")
	}

	if !strings.Contains(tr["bound@tech-project-workload"], "acme-${aws:PrincipalTag/cluster}-*${aws:PrincipalTag/project}-*/*") {
		t.Error("the transition workload lacks the legacy bucket pattern")
	}

	// The legacy patterns also fit platform roles; the transition builder denies them.
	if d := statements(t, tr["bound@tech-project-ack"])["DenyPlatformMintedRoles"]; d.Effect != "Deny" ||
		!slices.Contains(asList(d.Resource), "arn:part:iam::*:role/${aws:PrincipalTag/cluster}-db-*") {
		t.Errorf("transition builder: DenyPlatformMintedRoles = %+v", d)
	}

	if _, ok := statements(t, final["bound@tech-project-ack"])["DenyPlatformMintedRoles"]; ok {
		t.Error("the final builder carries the transition deny")
	}

	// The deployer's name rule exists only in the final form.
	if _, ok := statements(t, final["bound@role-deployer"])["DenyCreateRoleOutsideProjectName"]; !ok {
		t.Error("the final deployer has no name rule")
	}

	if _, ok := statements(t, tr["bound@role-deployer"])["DenyCreateRoleOutsideProjectName"]; ok {
		t.Error("the transition deployer has the name rule")
	}
}

func TestControllerBoundariesAreAllowlists(t *testing.T) {
	d := docs(t, currentSpec())

	for _, name := range []string{
		"bound@tech-ack-iam", "bound@tech-ack-eks", "bound@tech-ack-s3", "bound@tech-ack-kms", "bound@tech-ack-dynamodb",
	} {
		st := statements(t, d[name])

		if _, ok := st["AllowAll"]; ok {
			t.Errorf("%s allows everything", name)
		}

		for _, a := range actionsOfEffect(t, d[name], "Allow") {
			if a == "*" || a == "iam:*" {
				t.Errorf("%s allows %s", name, a)
			}
		}

		as := st["AllowAssumeProjectBuilders"]
		if got := asList(as.Resource); !slices.Equal(got, []string{"arn:part:iam::*:role/*-builder-*", "arn:part:iam::*:role/*-sandbox-*"}) {
			t.Errorf("%s may assume %v", name, got)
		}

		for _, sid := range []string{"DenyBoundaryPolicyEdit", "NoBoundaryDelete"} {
			if st[sid].Effect != "Deny" {
				t.Errorf("%s lacks %s", name, sid)
			}
		}
	}

	iam := statements(t, d["bound@tech-ack-iam"])
	if got := asList(iam["AllowCreateManagedRole"].Resource); !slices.Equal(got, []string{"arn:part:iam::*:role/*-db-*"}) {
		t.Errorf("ack-iam creates %v", got)
	}

	if iam["AllowCreateManagedRole"].Condition["StringEquals"]["aws:RequestTag/services.k8s.aws/namespace"] != "db-system" {
		t.Error("ack-iam creates roles for a namespace other than the configured one")
	}

	if iam["AllowCreateManagedRole"].Condition["ArnLike"]["iam:PermissionsBoundary"] != "arn:part:iam::*:policy/bound@default" {
		t.Error("ack-iam may attach a boundary other than the one it delegates")
	}

	for _, a := range actionsOfEffect(t, d["bound@tech-ack-iam"], "Allow") {
		if strings.Contains(a, "Attach") || a == "iam:PassRole" || strings.Contains(a, "User") {
			t.Errorf("ack-iam allows %s", a)
		}
	}

	eks := statements(t, d["bound@tech-ack-eks"])
	if got := asList(eks["AllowPassPlatformRoles"].Resource); !slices.Equal(got, []string{"arn:part:iam::*:role/*-db-*", "arn:part:iam::*:role/*-lab-*"}) {
		t.Errorf("ack-eks passes %v", got)
	}

	if eks["AllowPassPlatformRoles"].Condition["StringEqualsIfExists"]["iam:PassedToService"] != "pods.eks.amazonaws.com" {
		t.Error("PassRole is not conditioned on the service, as StringEqualsIfExists")
	}

	s3 := statements(t, d["bound@tech-ack-s3"])
	if got := asList(s3["AllowOwnBuckets"].Resource); !slices.Equal(got, []string{"arn:part:s3:::acme-*-cache", "arn:part:s3:::acme-*-scratch"}) {
		t.Errorf("ack-s3 administers %v", got)
	}
}

func TestSpecRefusalsCurrent(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*boundary.Spec)
		want   string
	}{
		"half a generation": {func(s *boundary.Spec) { s.Names.RoleAuditor = "" }, "Names.RoleAuditor is empty"},
		"no bucket prefix":  {func(s *boundary.Spec) { s.ProjectBucketPrefix = "" }, "ProjectBucketPrefix is empty"},
		"no namespace":      {func(s *boundary.Spec) { s.ACK.IAMNamespace = "" }, "ACK.IAMNamespace is empty"},
		"no builders":       {func(s *boundary.Spec) { s.ACK.BuilderRoles = nil }, "ACK.BuilderRoles is empty"},
		"no slugs":          {func(s *boundary.Spec) { s.ACK.IAMRoleSlugs = nil }, "ACK.IAMRoleSlugs is empty"},
		"no buckets":        {func(s *boundary.Spec) { s.ACK.Buckets = nil }, "ACK.Buckets is empty"},
		"empty entry":       {func(s *boundary.Spec) { s.ACK.Buckets = []string{""} }, "ACK.Buckets has an empty entry"},
		"no default":        {func(s *boundary.Spec) { s.Names.Default = "" }, "Names.Default is empty"},
		"same name twice": {func(s *boundary.Spec) { s.Names.EmployeeACK = s.Names.ProjectACK },
			"Names.ProjectACK and Names.EmployeeACK are both named"},
		"no admin entry": {func(s *boundary.Spec) { s.Hierarchy = s.Hierarchy[1:] }, `no entry for "bound@role-admin"`},
		"leaf delegates": {func(s *boundary.Spec) { s.Hierarchy[2].Delegates = []string{"bound@default"} },
			`leaf boundary "bound@role-auditor" must not have delegates`},
		"workload delegates": {func(s *boundary.Spec) { s.Hierarchy[12].Delegates = []string{"bound@default"} },
			`leaf boundary "bound@tech-project-workload" must not have delegates`},
	} {
		s := currentSpec()
		tc.mutate(&s)

		_, err := boundary.Policies(s)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want containing %q", name, err, tc.want)
		}
	}

	if _, err := boundary.Policies(boundary.Spec{Partition: "part", Prefix: "bound@", Names: boundary.Names{
		Default: "bound@default", EKSAutoNode: "bound@node",
	}}); err == nil || !strings.Contains(err.Error(), "no shape is named") {
		t.Errorf("a spec naming no shape was accepted: %v", err)
	}
}

func TestCurrentDocumentsNameNoPartitionOfTheirOwn(t *testing.T) {
	for name, doc := range variants(t) {
		if strings.Contains(doc, "arn:"+"aws") {
			t.Errorf("%s names a partition the caller did not give", name)
		}
	}
}

func TestLegacyOnlyStillRendersNineDocuments(t *testing.T) {
	if n := len(docs(t, spec())); n != 9 {
		t.Errorf("a legacy spec renders %d documents, want 9", n)
	}
}

func TestEmployeeBuilderIgnoresLegacyNames(t *testing.T) {
	tr := docs(t, transitionSpec())["bound@tech-employee-ack"]

	if strings.Contains(tr, "-*${aws:PrincipalTag/project}-*") || strings.Contains(tr, "DenyPlatformMintedRoles") {
		t.Error("the employee builder accepts legacy names")
	}
}

// A key can be created with tags, which AWS authorizes as kms:TagResource on a
// key that has no tag yet; and a key without a project tag belongs to no
// project, so a builder must not claim it by tagging it.
func TestBuildersTagKeysOnCreateButCannotClaimUntaggedKeys(t *testing.T) {
	for form, s := range map[string]boundary.Spec{"final": currentSpec(), "transition": transitionSpec()} {
		for _, name := range []string{"bound@tech-project-ack", "bound@tech-employee-ack"} {
			st := statements(t, docs(t, s)[name])

			create := st["AllowCreateKey"]
			if create.Effect != "Allow" || !slices.Contains(asList(create.Action), "kms:CreateKey") ||
				!slices.Contains(asList(create.Action), "kms:TagResource") {
				t.Errorf("%s %s: AllowCreateKey does not allow kms:CreateKey and kms:TagResource: %v", form, name, create.Action)
			}

			if create.Condition["StringEquals"]["aws:RequestTag/project"] != "${aws:PrincipalTag/project}" {
				t.Errorf("%s %s: key creation is not bound to the request tag", form, name)
			}

			// Never a retag of a key that already has a project.
			if create.Condition["Null"]["aws:ResourceTag/project"] != "true" {
				t.Errorf("%s %s: AllowCreateKey can retag a key that has a project", form, name)
			}

			claim := st["DenyClaimUntaggedKey"]
			if claim.Effect != "Deny" || asList(claim.Action)[0] != "kms:TagResource" ||
				claim.Condition["Null"]["aws:ResourceTag/project"] != "true" {
				t.Errorf("%s %s: no Deny of kms:TagResource on a key without a project tag: %+v", form, name, claim)
			}

			// The ordinary retag of an own key stays.
			if !slices.Contains(asList(st["AllowManageOwnKey"].Action), "kms:TagResource") {
				t.Errorf("%s %s: kms:TagResource on an own key is gone", form, name)
			}
		}
	}
}
