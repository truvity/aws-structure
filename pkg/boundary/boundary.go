package boundary

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/truvity/aws-structure/pkg/registry"
)

// Names are the names the caller gives each shape, as they appear in IAM.
type Names struct {
	Admin, Deploy, Default, Viewer, Project, Audit string
	// ACKIAM, CAPA and EKSAutoNode are the provisioner boundaries.
	ACKIAM, CAPA, EKSAutoNode string
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
	// Names.Admin, Names.Deploy and Names.ACKIAM.
	Hierarchy []Entry
}

// Validate reports every problem with s at once, or returns nil.
func (s *Spec) Validate() error {
	var errs []error

	for name, v := range map[string]string{
		"Partition": s.Partition, "Prefix": s.Prefix, "ClassPrefix": s.ClassPrefix,
		"Names.Admin": s.Names.Admin, "Names.Deploy": s.Names.Deploy, "Names.Default": s.Names.Default,
		"Names.Viewer": s.Names.Viewer, "Names.Project": s.Names.Project, "Names.Audit": s.Names.Audit,
		"Names.ACKIAM": s.Names.ACKIAM, "Names.CAPA": s.Names.CAPA, "Names.EKSAutoNode": s.Names.EKSAutoNode,
	} {
		if v == "" {
			errs = append(errs, fmt.Errorf("spec: %s is empty", name))
		}
	}

	if !strings.HasPrefix(s.ClassPrefix, s.Prefix) {
		errs = append(errs, fmt.Errorf("spec: ClassPrefix %q does not extend Prefix %q", s.ClassPrefix, s.Prefix))
	}

	have := map[string]bool{}
	for _, e := range s.Hierarchy {
		have[e.Name] = true
	}

	for _, n := range []string{s.Names.Admin, s.Names.Deploy, s.Names.ACKIAM} {
		if !have[n] {
			errs = append(errs, fmt.Errorf("spec: Hierarchy has no entry for %q", n))
		}
	}

	errs = append(errs, s.validateHierarchy()...)

	return errors.Join(errs...)
}

// validateHierarchy checks the delegation graph: every delegate is an entry of
// the hierarchy, the leaf shapes (Names.Default, Names.Project and
// Names.Audit) delegate to nothing, and no boundary can reach itself through
// its delegates.
func (s *Spec) validateHierarchy() []error {
	var errs []error

	adj := make(map[string][]string, len(s.Hierarchy))
	for _, e := range s.Hierarchy {
		adj[e.Name] = e.Delegates
	}

	leaves := map[string]bool{s.Names.Default: true, s.Names.Project: true, s.Names.Audit: true}
	delete(leaves, "") // an empty name is reported by the required-names check

	undefined := false

	for _, e := range s.Hierarchy {
		for _, d := range e.Delegates {
			if _, ok := adj[d]; !ok {
				undefined = true

				errs = append(errs, fmt.Errorf("spec: boundary %q delegates to undefined boundary %q", e.Name, d))
			}
		}

		if leaves[e.Name] && len(e.Delegates) > 0 {
			errs = append(errs, fmt.Errorf("spec: leaf boundary %q must not have delegates", e.Name))
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

// arn is the ARN pattern of a boundary policy of any account.
func (s *Spec) arn(name string) string {
	return fmt.Sprintf("arn:%s:iam::*:policy/%s", s.Partition, name)
}

// DelegateARNs returns the ARN patterns of the boundaries name may attach, or
// nil for a leaf. The admin boundary also names itself and replaces its
// delegates of the provisioner class with one wildcard (the root boundary may
// delegate to any of them, present or future).
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

	if name != s.Names.Admin {
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
		Sid       string         `json:"Sid"`
		Effect    string         `json:"Effect"`
		Action    any            `json:"Action,omitempty"`
		NotAction any            `json:"NotAction,omitempty"`
		Resource  any            `json:"Resource"`
		Condition map[string]any `json:"Condition,omitempty"`
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

func (s *Spec) admin() (string, error) {
	return marshal(s.Names.Admin, document{Version: policyVersion, Statement: []statement{
		allowAll(),
		{
			Sid:    "DenyChangePermissionsSetsRoles",
			Effect: deny,
			Action: []string{
				"iam:AttachRolePolicy", actionCreateRole, "iam:DeleteRole", "iam:DeleteRolePolicy",
				"iam:DetachRolePolicy", actionPutRoleBoundary, "iam:PutRolePolicy", "iam:TagRole",
				"iam:UntagRole", "iam:UpdateAssumeRolePolicy", "iam:UpdateRole", "iam:UpdateRoleDescription",
			},
			Resource: []string{
				fmt.Sprintf("arn:%s:iam::*:role/aws-reserved/sso.amazonaws.com/*", s.Partition),
				fmt.Sprintf("arn:%s:iam::*:role/AWSServiceRoleFor*", s.Partition),
			},
		},
		denyWithoutBoundary("DenyCreateOrChangeWithoutBoundary", s.DelegateARNs(s.Names.Admin)),
		s.denyBoundaryEdit(),
		noBoundaryDelete(),
		{Sid: "DenyDestructiveActions", Effect: deny, Action: destructiveActions, Resource: "*"},
		{
			Sid: "DenyDeletePulumiStateBuckets", Effect: deny, Action: "s3:DeleteBucket",
			Resource: fmt.Sprintf("arn:%s:s3:::pulumi-state-*", s.Partition),
		},
	}})
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

func (s *Spec) audit() (string, error) {
	return marshal(s.Names.Audit, document{Version: policyVersion, Statement: []statement{
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
// registry.Boundary, in a stable order: admin, viewer, default, ACK IAM, CAPA,
// EKS Auto Mode node, deploy, project, audit. The viewer is deprecated (use
// the default) and kept for existing roles; it is the default's document.
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
	} {
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
