package boundary

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/truvity/aws-structure/pkg/registry"
)

// Names are the names the caller gives each shape, as they appear in IAM.
//
// The names form two generations that may be used at the same time, so that
// an organization can create the new boundaries beside the old ones, move its
// roles over and delete the old ones later:
//
//   - the legacy shapes: Admin, Deploy, Viewer, Project, Audit, ACKIAM and
//     CAPA. Each is all-or-nothing: leave all seven empty to render none of
//     them;
//   - the role/controller/project shapes: RoleAdmin, RoleDeployer,
//     RoleAuditor, the five ACKController* names, ProjectACK, EmployeeACK and
//     ProjectWorkload. Also all-or-nothing, and they need Spec.ProjectBucketPrefix
//     and Spec.ACK.
//
// Default and EKSAutoNode are shared by both generations and always required.
type Names struct {
	Admin, Deploy, Default, Viewer, Project, Audit string
	// ACKIAM, CAPA and EKSAutoNode are the provisioner boundaries.
	ACKIAM, CAPA, EKSAutoNode string

	// RoleAdmin, RoleDeployer and RoleAuditor are the human boundaries that
	// replace Admin, Deploy and Audit.
	RoleAdmin, RoleDeployer, RoleAuditor string
	// ACKControllerIAM, ACKControllerEKS, ACKControllerS3, ACKControllerKMS and
	// ACKControllerDynamoDB are the boundaries of the ACK controllers' own
	// roles, one per controller.
	ACKControllerIAM, ACKControllerEKS, ACKControllerS3, ACKControllerKMS, ACKControllerDynamoDB string
	// ProjectACK is the boundary of a project's builder role, the role every
	// ACK controller assumes to act for that project's namespaces. EmployeeACK
	// is the same for an employee sandbox. ProjectWorkload bounds the roles a
	// builder creates for the project's pods.
	ProjectACK, EmployeeACK, ProjectWorkload string
	// Grun is the boundary of the roles the self-hosted runners stack
	// (cdk-github-runners) creates; see GrunScope. Optional and independent of
	// both generations: leave it empty to render none. Needs Spec.Grun.
	Grun string
}

// ACKScope names the platform's own ACK-managed resources: what the
// controllers' own roles (not the project builders) may touch. Every value is
// a caller input; the package knows only the shapes.
type ACKScope struct {
	// BuilderRoles are the role-name patterns of the builder roles (project
	// and employee) that every controller may assume and tag a session on,
	// such as "*-builder-*". Required.
	BuilderRoles []string
	// IAMNamespace is the value of the "services.k8s.aws/namespace" tag
	// (ACK's own resource tag) on the roles the IAM controller manages on its
	// own role. Required.
	IAMNamespace string
	// IAMRoleSlugs are the name slugs of those roles: the slug "x" stands for
	// the role names "*-x-*" (and, for the legacy deny, "<cluster>-x-*").
	// Required.
	IAMRoleSlugs []string
	// PodIdentityRoleSlugs are further slugs of roles the EKS controller may
	// bind to a pod beside IAMRoleSlugs. Optional.
	PodIdentityRoleSlugs []string
	// Buckets are the bucket-name patterns (no ARN prefix) the S3 controller's
	// own role administers. Required.
	Buckets []string
}

// Entry is one boundary of the hierarchy: whom it may delegate to and which tags
// it requires on a created role.
type Entry struct {
	Name         string
	Delegates    []string
	EnforcesTags []string
}

// Spec configures Policies.
type Spec struct {
	// Partition is the ARN partition. Required.
	Partition string
	// Prefix is what every boundary name starts with, such as "bound@". The
	// documents deny editing any policy named Prefix + "*". Required.
	Prefix string
	// ClassPrefix is what the names of the provisioner boundaries start with
	// (it extends Prefix). The admin boundary delegates to the whole class by
	// one wildcard. Required.
	ClassPrefix string
	Names       Names
	// Hierarchy lists who may delegate to whom. Required: it must contain
	// an entry for each shape that delegates (Names.Admin, Names.Deploy and
	// Names.ACKIAM; Names.RoleAdmin, Names.RoleDeployer,
	// Names.ACKControllerIAM, Names.ProjectACK and Names.EmployeeACK).
	Hierarchy []Entry
	// ProjectBucketPrefix is what the name of every project bucket starts
	// with, before the cluster: "<prefix><cluster>-<project>-<name>". Required
	// for the role/controller/project shapes.
	ProjectBucketPrefix string
	// ACK scopes the controllers' own roles. Required for the
	// role/controller/project shapes.
	ACK ACKScope
	// LegacyProjectNames renders the transition form of the project
	// shapes: ProjectACK and ProjectWorkload also accept the legacy names of
	// roles, policies and buckets ("<cluster>-*<project>-*" and
	// "<prefix><cluster>-*<project>-*"), ProjectACK denies the platform roles
	// those patterns would reach, and RoleDeployer drops its name rule.
	// The final form (false) is the same policy name at a new version, so no
	// role has to be re-attached. EmployeeACK has no legacy names and ignores
	// the flag.
	LegacyProjectNames bool
	// OrgAdmin selects the variant of the admin boundary. The zero value
	// (OrgAdminOff) is the admin boundary every existing caller gets. See
	// OrgAdminMode.
	OrgAdmin OrgAdminMode
	// Grun scopes the Grun boundary. Required when Names.Grun is set.
	Grun GrunScope
}

// legacyNames returns the legacy generation by field name, in a stable order.
func (s *Spec) legacyNames() [][2]string {
	return [][2]string{
		{"Names.Admin", s.Names.Admin}, {"Names.Deploy", s.Names.Deploy}, {"Names.Viewer", s.Names.Viewer},
		{"Names.Project", s.Names.Project}, {"Names.Audit", s.Names.Audit},
		{"Names.ACKIAM", s.Names.ACKIAM}, {"Names.CAPA", s.Names.CAPA},
	}
}

// currentNames returns the role/controller/project generation by field name,
// in the order Policies renders it.
func (s *Spec) currentNames() [][2]string {
	return [][2]string{
		{"Names.RoleAdmin", s.Names.RoleAdmin}, {"Names.RoleDeployer", s.Names.RoleDeployer},
		{"Names.RoleAuditor", s.Names.RoleAuditor},
		{"Names.ACKControllerIAM", s.Names.ACKControllerIAM}, {"Names.ACKControllerEKS", s.Names.ACKControllerEKS},
		{"Names.ACKControllerS3", s.Names.ACKControllerS3}, {"Names.ACKControllerKMS", s.Names.ACKControllerKMS},
		{"Names.ACKControllerDynamoDB", s.Names.ACKControllerDynamoDB},
		{"Names.ProjectACK", s.Names.ProjectACK}, {"Names.EmployeeACK", s.Names.EmployeeACK},
		{"Names.ProjectWorkload", s.Names.ProjectWorkload},
	}
}

func anySet(group [][2]string) bool {
	for _, n := range group {
		if n[1] != "" {
			return true
		}
	}

	return false
}

// hasLegacy and hasCurrent report which generation of shapes is rendered.
func (s *Spec) hasLegacy() bool  { return anySet(s.legacyNames()) }
func (s *Spec) hasCurrent() bool { return anySet(s.currentNames()) }

// Validate reports every problem with s at once, or returns nil.
func (s *Spec) Validate() error {
	var errs []error

	for name, v := range map[string]string{
		"Partition": s.Partition, "Prefix": s.Prefix,
		"Names.Default": s.Names.Default, "Names.EKSAutoNode": s.Names.EKSAutoNode,
	} {
		if v == "" {
			errs = append(errs, fmt.Errorf("spec: %s is empty", name))
		}
	}

	if !s.hasLegacy() && !s.hasCurrent() {
		errs = append(errs, errors.New("spec: no shape is named: set the legacy names (Names.Admin, ...) or the role names (Names.RoleAdmin, ...)"))
	}

	have := map[string]bool{}
	for _, e := range s.Hierarchy {
		have[e.Name] = true
	}

	var needEntries []string

	if s.hasLegacy() {
		for _, n := range s.legacyNames() {
			if n[1] == "" {
				errs = append(errs, fmt.Errorf("spec: %s is empty", n[0]))
			}
		}

		if s.ClassPrefix == "" {
			errs = append(errs, errors.New("spec: ClassPrefix is empty"))
		} else if !strings.HasPrefix(s.ClassPrefix, s.Prefix) {
			errs = append(errs, fmt.Errorf("spec: ClassPrefix %q does not extend Prefix %q", s.ClassPrefix, s.Prefix))
		}

		needEntries = append(needEntries, s.Names.Admin, s.Names.Deploy, s.Names.ACKIAM)
	}

	if s.hasCurrent() {
		for _, n := range s.currentNames() {
			if n[1] == "" {
				errs = append(errs, fmt.Errorf("spec: %s is empty", n[0]))
			}
		}

		errs = append(errs, s.validateCurrent()...)

		needEntries = append(needEntries, s.Names.RoleAdmin, s.Names.RoleDeployer, s.Names.ACKControllerIAM,
			s.Names.ProjectACK, s.Names.EmployeeACK)
	}

	if s.Names.Grun != "" {
		needEntries = append(needEntries, s.Names.Grun)
	}

	errs = append(errs, s.validateGrun()...)

	for _, n := range needEntries {
		if n != "" && !have[n] {
			errs = append(errs, fmt.Errorf("spec: Hierarchy has no entry for %q", n))
		}
	}

	errs = append(errs, s.validateDistinctNames()...)
	errs = append(errs, s.validateHierarchy()...)

	return errors.Join(errs...)
}

// validateCurrent checks the inputs only the role/controller/project shapes
// use.
func (s *Spec) validateCurrent() []error {
	var errs []error

	if s.ProjectBucketPrefix == "" {
		errs = append(errs, errors.New("spec: ProjectBucketPrefix is empty"))
	}

	if s.ACK.IAMNamespace == "" {
		errs = append(errs, errors.New("spec: ACK.IAMNamespace is empty"))
	}

	for name, v := range map[string][]string{
		"ACK.BuilderRoles": s.ACK.BuilderRoles, "ACK.IAMRoleSlugs": s.ACK.IAMRoleSlugs,
		"ACK.PodIdentityRoleSlugs": s.ACK.PodIdentityRoleSlugs, "ACK.Buckets": s.ACK.Buckets,
	} {
		if len(v) == 0 && name != "ACK.PodIdentityRoleSlugs" {
			errs = append(errs, fmt.Errorf("spec: %s is empty", name))
		}

		for _, x := range v {
			if x == "" {
				errs = append(errs, fmt.Errorf("spec: %s has an empty entry", name))
			}
		}
	}

	return errs
}

// validateDistinctNames refuses one name given to two shapes: two documents of
// one name cannot both be created.
func (s *Spec) validateDistinctNames() []error {
	var errs []error

	seen := map[string]string{}

	all := append([][2]string{{"Names.Default", s.Names.Default}, {"Names.EKSAutoNode", s.Names.EKSAutoNode}, {"Names.Grun", s.Names.Grun}},
		append(s.legacyNames(), s.currentNames()...)...)

	for _, n := range all {
		if n[1] == "" {
			continue
		}

		if prev, ok := seen[n[1]]; ok {
			errs = append(errs, fmt.Errorf("spec: %s and %s are both named %q", prev, n[0], n[1]))

			continue
		}

		seen[n[1]] = n[0]
	}

	return errs
}

// leaves returns the boundaries that delegate to nothing.
func (s *Spec) leaves() map[string]bool {
	leaves := map[string]bool{
		s.Names.Default: true, s.Names.Project: true, s.Names.Audit: true,
		s.Names.RoleAuditor: true, s.Names.ProjectWorkload: true,
		s.Names.ACKControllerEKS: true, s.Names.ACKControllerS3: true,
		s.Names.ACKControllerKMS: true, s.Names.ACKControllerDynamoDB: true,
		s.Names.Grun: true,
	}
	delete(leaves, "") // an empty name is reported by the required-names check

	return leaves
}

// validateHierarchy checks the delegation graph: every delegate is an entry of
// the hierarchy and a name, not a pattern, the leaf shapes delegate to
// nothing, the builders (ProjectACK, EmployeeACK) delegate to exactly
// ProjectWorkload, and no boundary can reach itself through its delegates.
func (s *Spec) validateHierarchy() []error {
	var errs []error

	adj := make(map[string][]string, len(s.Hierarchy))
	for _, e := range s.Hierarchy {
		adj[e.Name] = e.Delegates
	}

	leaves := s.leaves()
	undefined := false

	for _, e := range s.Hierarchy {
		if strings.ContainsAny(e.Name, "*?") {
			errs = append(errs, fmt.Errorf("spec: boundary name %q is a pattern: boundaries are named exactly", e.Name))
		}

		for _, d := range e.Delegates {
			if strings.ContainsAny(d, "*?") {
				errs = append(errs, fmt.Errorf("spec: boundary %q delegates to the pattern %q: delegates are exact names", e.Name, d))
			}

			if _, ok := adj[d]; !ok {
				undefined = true

				errs = append(errs, fmt.Errorf("spec: boundary %q delegates to undefined boundary %q", e.Name, d))
			}
		}

		if leaves[e.Name] && len(e.Delegates) > 0 {
			errs = append(errs, fmt.Errorf("spec: leaf boundary %q must not have delegates", e.Name))
		}

		if e.Name != "" && (e.Name == s.Names.ACKControllerIAM || e.Name == s.Names.RoleDeployer) && len(e.Delegates) == 0 {
			errs = append(errs, fmt.Errorf("spec: boundary %q must delegate to at least one boundary", e.Name))
		}

		if s.isBuilder(e.Name) && (len(e.Delegates) != 1 || e.Delegates[0] != s.Names.ProjectWorkload) {
			errs = append(errs, fmt.Errorf("spec: builder boundary %q must delegate to exactly %q, got %v",
				e.Name, s.Names.ProjectWorkload, e.Delegates))
		}
	}

	if undefined {
		return errs
	}

	const (
		white = iota
		gray
		black
	)

	colors := make(map[string]int, len(adj))

	var visit func(name string, path []string) error

	visit = func(name string, path []string) error {
		colors[name] = gray
		path = append(path, name)

		for _, target := range adj[name] {
			switch colors[target] {
			case gray:
				return fmt.Errorf("spec: boundary hierarchy cycle: %s", strings.Join(append(path, target), " -> "))
			case white:
				if err := visit(target, path); err != nil {
					return err
				}
			}
		}

		colors[name] = black

		return nil
	}

	for _, e := range s.Hierarchy {
		if colors[e.Name] == white {
			if err := visit(e.Name, nil); err != nil {
				errs = append(errs, err)

				break
			}
		}
	}

	return errs
}

// isBuilder reports whether name is a builder boundary: a role that creates
// other roles for a project or an employee sandbox.
func (s *Spec) isBuilder(name string) bool {
	return name != "" && (name == s.Names.ProjectACK || name == s.Names.EmployeeACK)
}

// arn is the ARN pattern of a boundary policy of any account.
func (s *Spec) arn(name string) string {
	return fmt.Sprintf("arn:%s:iam::*:policy/%s", s.Partition, name)
}

// DelegateARNs returns the ARN patterns of the boundaries name may attach, or
// nil for a leaf.
//
// The legacy admin boundary (Names.Admin) also names itself and replaces its
// delegates of the provisioner class with one wildcard (the root boundary may
// delegate to any of them, present or future). The role admin boundary
// (Names.RoleAdmin) names itself and its delegates, every one by its exact
// name, and no wildcard: adding a boundary to the hierarchy is a reviewed edit
// of the document.
func (s *Spec) DelegateARNs(name string) []string {
	var delegates []string

	for _, e := range s.Hierarchy {
		if e.Name != name {
			continue
		}

		for _, d := range e.Delegates {
			delegates = append(delegates, s.arn(d))
		}
	}

	if len(delegates) == 0 {
		return nil
	}

	if name == s.Names.RoleAdmin && name != "" {
		self := s.arn(name)
		if slices.Contains(delegates, self) {
			return delegates
		}

		return append([]string{self}, delegates...)
	}

	if name != s.Names.Admin || name == "" {
		return delegates
	}

	arns := []string{s.arn(s.Names.Admin)}
	arns = append(arns, delegates...)

	classARN := s.arn(s.ClassPrefix)
	wildcard := s.arn(s.ClassPrefix + "*")

	var out []string

	wildcarded := false

	for _, a := range arns {
		if len(a) > len(classARN) && strings.HasPrefix(a, classARN) {
			if !wildcarded {
				out = append(out, wildcard)
				wildcarded = true
			}

			continue
		}

		out = append(out, a)
	}

	return out
}

// EnforcedTags returns the tags a boundary requires on a created role.
func (s *Spec) EnforcedTags(name string) []string {
	for _, e := range s.Hierarchy {
		if e.Name == name {
			return e.EnforcesTags
		}
	}

	return nil
}

type (
	document struct {
		Version   string      `json:"Version"`
		Statement []statement `json:"Statement"`
	}

	statement struct {
		Sid         string         `json:"Sid"`
		Effect      string         `json:"Effect"`
		Action      any            `json:"Action,omitempty"`
		NotAction   any            `json:"NotAction,omitempty"`
		Resource    any            `json:"Resource,omitempty"`
		NotResource any            `json:"NotResource,omitempty"`
		Condition   map[string]any `json:"Condition,omitempty"`
	}
)

const (
	policyVersion = "2012-10-17"
	allow         = "Allow"
	deny          = "Deny"

	sidAllowAll         = "AllowAll"
	sidDenyBoundaryEdit = "DenyBoundaryPolicyEdit"
	sidNoBoundaryDelete = "NoBoundaryDelete"

	actionCreateRole        = "iam:CreateRole"
	actionPutRoleBoundary   = "iam:PutRolePermissionsBoundary"
	actionCreateUser        = "iam:CreateUser"
	actionPutUserBoundary   = "iam:PutUserPermissionsBoundary"
	condStringNotLike       = "StringNotLike"
	condStringEquals        = "StringEquals"
	condPermissionsBoundary = "iam:PermissionsBoundary"
)

func allowAll() statement {
	return statement{Sid: sidAllowAll, Effect: allow, Action: "*", Resource: "*"}
}

func (s *Spec) denyBoundaryEdit() statement {
	return statement{
		Sid:    sidDenyBoundaryEdit,
		Effect: deny,
		Action: []string{
			"iam:CreatePolicyVersion",
			"iam:DeletePolicy",
			"iam:DeletePolicyVersion",
			"iam:SetDefaultPolicyVersion",
		},
		Resource: []string{s.arn(s.Prefix + "*")},
	}
}

func noBoundaryDelete() statement {
	return statement{
		Sid:      sidNoBoundaryDelete,
		Effect:   deny,
		Action:   []string{"iam:DeleteRolePermissionsBoundary", "iam:DeleteUserPermissionsBoundary"},
		Resource: "*",
	}
}

func denyWithoutBoundary(sid string, allowed []string) statement {
	return statement{
		Sid:    sid,
		Effect: deny,
		Action: []string{
			actionCreateRole,
			actionPutRoleBoundary,
			actionCreateUser,
			actionPutUserBoundary,
		},
		Resource: "*",
		Condition: map[string]any{
			condStringNotLike: map[string]any{condPermissionsBoundary: allowed},
		},
	}
}

var iamWriteDenied = []string{
	"iam:Create*", "iam:Delete*", "iam:Put*", "iam:Update*", "iam:Attach*", "iam:Detach*", "iam:Add*",
	"iam:Remove*", "iam:Set*", "iam:Tag*", "iam:Untag*", "iam:Upload*", "iam:Enable*", "iam:Disable*",
	"iam:Resync*", "iam:Pass*", "iam:Deactivate*", "iam:Generate*",
}

var destructiveActions = []string{
	"cloudtrail:DeleteTrail",
	"cloudtrail:StopLogging",
	"ec2:DeleteVpc",
	"kms:DisableKey",
	"kms:ScheduleKeyDeletion",
	"route53:DeleteHostedZone",
}

func marshal(name string, d document) (string, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return "", fmt.Errorf("marshal %s policy: %w", name, err)
	}

	return string(b), nil
}

func (s *Spec) admin() (string, error) { return s.adminAs(s.Names.Admin) }

// roleAdmin is the admin boundary under the role name: the same document, its
// delegation list exact (see DelegateARNs).
func (s *Spec) roleAdmin() (string, error) { return s.adminAs(s.Names.RoleAdmin) }

func (s *Spec) adminAs(name string) (string, error) {
	stmts := []statement{
		allowAll(),
	}

	if s.OrgAdmin == OrgAdminManagement {
		stmts = append(stmts, s.allowOrgAdmin(), s.allowBoundaryEdit())
	}

	stmts = append(stmts,
		statement{
			Sid:    "DenyChangePermissionsSetsRoles",
			Effect: deny,
			Action: []string{
				"iam:AttachRolePolicy", actionCreateRole, "iam:DeleteRole", "iam:DeleteRolePolicy",
				"iam:DetachRolePolicy", actionPutRoleBoundary, "iam:PutRolePolicy", "iam:TagRole",
				"iam:UntagRole", "iam:UpdateAssumeRolePolicy", "iam:UpdateRole", "iam:UpdateRoleDescription",
			},
			Resource: s.denyPermissionSetRoleResources(),
		},
		denyWithoutBoundary("DenyCreateOrChangeWithoutBoundary", s.DelegateARNs(name)),
	)

	if s.OrgAdmin != OrgAdminManagement {
		stmts = append(stmts, s.denyBoundaryEdit())
	}

	stmts = append(stmts,
		noBoundaryDelete(),
		statement{Sid: "DenyDestructiveActions", Effect: deny, Action: destructiveActions, Resource: "*"},
		statement{
			Sid: "DenyDeletePulumiStateBuckets", Effect: deny, Action: "s3:DeleteBucket",
			Resource: fmt.Sprintf("arn:%s:s3:::pulumi-state-*", s.Partition),
		},
	)

	if s.OrgAdmin == OrgAdminMember {
		stmts = append(stmts, denyOrgAdmin())
	}

	return marshal(name, document{Version: policyVersion, Statement: stmts})
}

func (s *Spec) viewer() (string, error) {
	return marshal(s.Names.Default, document{Version: policyVersion, Statement: []statement{
		allowAll(),
		{Sid: "DenyAllIAMWrite", Effect: deny, Action: iamWriteDenied, Resource: "*"},
	}})
}

func (s *Spec) ackIAM() (string, error) {
	return marshal(s.Names.ACKIAM, document{Version: policyVersion, Statement: []statement{
		allowAll(),
		denyWithoutBoundary("DenyCreateWithoutAllowedBoundary", s.DelegateARNs(s.Names.ACKIAM)),
		s.denyBoundaryEdit(),
		noBoundaryDelete(),
	}})
}

// capa allows everything plus the IAM actions provisioning needs, with NotAction:
// an explicit Deny always wins over an Allow, so exceptions are carved out of
// the deny instead of allowed separately.
func (s *Spec) capa() (string, error) {
	return marshal(s.Names.CAPA, document{Version: policyVersion, Statement: []statement{
		allowAll(),
		{
			Sid:    "DenyIAMWriteExceptAllowed",
			Effect: deny,
			NotAction: []string{
				"iam:PassRole", "iam:CreateServiceLinkedRole", "iam:Get*", "iam:List*",
				"iam:SimulateCustomPolicy", "iam:SimulatePrincipalPolicy", "sts:*",
			},
			Resource: fmt.Sprintf("arn:%s:iam::*:*", s.Partition),
		},
	}})
}

func (s *Spec) eksAutoNode() (string, error) {
	return marshal(s.Names.EKSAutoNode, document{Version: policyVersion, Statement: []statement{allowAll()}})
}

func (s *Spec) deploy() (string, error) {
	return marshal(s.Names.Deploy, document{Version: policyVersion, Statement: []statement{
		allowAll(),
		{
			Sid: "DenyCreateRoleWithoutProjectTag", Effect: deny, Action: actionCreateRole, Resource: "*",
			Condition: map[string]any{"Null": map[string]any{"aws:RequestTag/project": "true"}},
		},
		{
			Sid: "DenyCreateRoleWithoutClusterTag", Effect: deny, Action: actionCreateRole, Resource: "*",
			Condition: map[string]any{"Null": map[string]any{"aws:RequestTag/cluster": "true"}},
		},
		denyWithoutBoundary("DenyCreateOrChangeWithoutAllowedBoundary", s.DelegateARNs(s.Names.Deploy)),
		s.denyBoundaryEdit(),
		noBoundaryDelete(),
	}})
}

// project restricts every resource access to the principal's own project, by
// the ${aws:PrincipalTag/project} variable, and denies IAM entirely.
func (s *Spec) project() (string, error) {
	const tag = "${aws:PrincipalTag/project}"

	byProject := map[string]any{condStringEquals: map[string]any{"aws:ResourceTag/project": tag}}

	return marshal(s.Names.Project, document{Version: policyVersion, Statement: []statement{
		{
			Sid: "AllowSSMByProject", Effect: allow, Action: "ssm:*",
			Resource: fmt.Sprintf("arn:%s:ssm:*:*:parameter/%s/*", s.Partition, tag),
		},
		{Sid: "AllowSMByProject", Effect: allow, Action: "secretsmanager:*", Resource: "*", Condition: byProject},
		{Sid: "AllowKMSByProject", Effect: allow, Action: "kms:*", Resource: "*", Condition: byProject},
		{
			Sid: "AllowS3ByProject", Effect: allow, Action: "s3:*",
			Resource: []string{
				fmt.Sprintf("arn:%s:s3:::%s-*", s.Partition, tag),
				fmt.Sprintf("arn:%s:s3:::%s-*/*", s.Partition, tag),
			},
		},
		{Sid: "DenyAllIAM", Effect: deny, Action: "iam:*", Resource: "*"},
	}})
}

func (s *Spec) audit() (string, error) { return s.auditAs(s.Names.Audit) }

// roleAuditor is the audit boundary under the role name: the same document.
func (s *Spec) roleAuditor() (string, error) { return s.auditAs(s.Names.RoleAuditor) }

func (s *Spec) auditAs(name string) (string, error) {
	return marshal(name, document{Version: policyVersion, Statement: []statement{
		allowAll(),
		{Sid: "DenyAllIAMWrite", Effect: deny, Action: iamWriteDenied, Resource: "*"},
		{Sid: "DenyDestructiveActions", Effect: deny, Action: destructiveActions, Resource: "*"},
		{
			Sid: "DenyDeletePulumiStateBuckets", Effect: deny, Action: "s3:DeleteBucket",
			Resource: fmt.Sprintf("arn:%s:s3:::pulumi-state-*", s.Partition),
		},
	}})
}

// Policies returns the boundary policies every account carries, each as a
// registry.Boundary, in a stable order: the legacy shapes (admin, viewer,
// default, ACK IAM, CAPA, EKS Auto Mode node, deploy, project, audit), then the
// role/controller/project shapes (role admin, role deployer, role auditor, the
// five ACK controllers, the project builder, the employee builder, the project
// workload), then Grun. A generation whose names are all empty is left out, except Default
// and EKSAutoNode, which are always rendered. The viewer is deprecated (use the
// default) and kept for existing roles; it is the default's document.
func Policies(s Spec) ([]registry.Boundary, error) {
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("boundary: %w", err)
	}

	type shape struct {
		name  string
		build func() (string, error)
	}

	var (
		out  []registry.Boundary
		errs []error
	)

	for _, sh := range []shape{
		{s.Names.Admin, s.admin},
		{s.Names.Viewer, s.viewer},
		{s.Names.Default, s.viewer},
		{s.Names.ACKIAM, s.ackIAM},
		{s.Names.CAPA, s.capa},
		{s.Names.EKSAutoNode, s.eksAutoNode},
		{s.Names.Deploy, s.deploy},
		{s.Names.Project, s.project},
		{s.Names.Audit, s.audit},
		{s.Names.RoleAdmin, s.roleAdmin},
		{s.Names.RoleDeployer, s.roleDeployer},
		{s.Names.RoleAuditor, s.roleAuditor},
		{s.Names.ACKControllerIAM, s.controllerIAM},
		{s.Names.ACKControllerEKS, s.controllerEKS},
		{s.Names.ACKControllerS3, s.controllerS3},
		{s.Names.ACKControllerKMS, s.controllerKMS},
		{s.Names.ACKControllerDynamoDB, s.controllerDynamoDB},
		{s.Names.ProjectACK, s.projectACK},
		{s.Names.EmployeeACK, s.employeeACK},
		{s.Names.ProjectWorkload, s.projectWorkload},
		{s.Names.Grun, s.grun},
	} {
		if sh.name == "" {
			continue
		}

		doc, err := sh.build()
		if err != nil {
			errs = append(errs, err)

			continue
		}

		out = append(out, registry.Boundary{Name: sh.name, Document: doc})
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	return out, nil
}

// denyPermissionSetRoleResources returns the roles DenyChangePermissionsSetsRoles
// protects: the roles Identity Center reserves for permission sets and the
// service-linked roles. In the management account Identity Center writes a
// permission set's policies and boundary onto its reserved roles with the
// permissions of the caller, so the management variant of the admin boundary
// leaves the reserved roles out and keeps the service-linked roles (the
// provisioning path does not change them). Member accounts are provisioned
// through the service-linked role, so every other variant lists both.
func (s *Spec) denyPermissionSetRoleResources() any {
	serviceLinked := fmt.Sprintf("arn:%s:iam::*:role/AWSServiceRoleFor*", s.Partition)
	if s.OrgAdmin == OrgAdminManagement {
		return serviceLinked
	}

	return []string{
		fmt.Sprintf("arn:%s:iam::*:role/aws-reserved/sso.amazonaws.com/*", s.Partition),
		serviceLinked,
	}
}
