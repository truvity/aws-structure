package org

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"

	"github.com/truvity/aws-structure/pkg/registry"
)

const (
	policyVersion = "2012-10-17"
	effectDeny    = "Deny"

	// stackSetRole is the name AWS gives the role CloudFormation StackSets
	// assume in a member account.
	stackSetRole = "AWSCloudFormationStackSetExecutionRole"
)

var (
	partitionRE = regexp.MustCompile(`^[a-z][a-z-]*$`)
	accountIDRE = regexp.MustCompile(`^[0-9]{12}$`)
)

// SCPParams are the particulars the policy documents are built from. Every
// field is required: none has a default, because each is a fact about an
// estate.
type SCPParams struct {
	// Partition is the AWS partition the ARNs in the documents name, the
	// word between "arn:" and the service.
	Partition string
	// ManagementAccountID is the 12-digit id of the one account allowed to
	// change CloudTrail.
	ManagementAccountID string
	// AllowedRegions are the only regions the region restriction permits, in
	// the order they are written into the document.
	AllowedRegions []string
	// ReplicationExemptBuckets is the S3 bucket name pattern, wildcards
	// allowed, whose replication configuration may still change.
	ReplicationExemptBuckets string
	// PublicAccessBlockExemptBuckets is the S3 bucket name pattern, wildcards
	// allowed, whose bucket-level public access block may still change.
	PublicAccessBlockExemptBuckets string
}

// strs marshals to a JSON string when it holds one value and to an array
// otherwise: the two shapes AWS policies accept.
type strs []string

func (s strs) MarshalJSON() ([]byte, error) {
	if len(s) == 1 {
		return json.Marshal(s[0])
	}

	return json.Marshal([]string(s))
}

// condition maps an operator to its key and values.
type condition map[string]map[string]strs

type statement struct {
	Sid         string    `json:"Sid"`
	Effect      string    `json:"Effect"`
	Action      strs      `json:"Action"`
	Resource    strs      `json:"Resource,omitempty"`
	NotResource strs      `json:"NotResource,omitempty"`
	Condition   condition `json:"Condition,omitempty"`
}

type document struct {
	Version   string      `json:"Version"`
	Statement []statement `json:"Statement"`
}

// deny is a Deny statement on every resource.
func deny(sid string, actions ...string) statement {
	return statement{Sid: sid, Effect: effectDeny, Action: actions, Resource: strs{"*"}}
}

func (p *SCPParams) validate() error {
	var errs []error

	if !partitionRE.MatchString(p.Partition) {
		errs = append(errs, fmt.Errorf("scp params: Partition %q is not a partition name", p.Partition))
	}

	if !accountIDRE.MatchString(p.ManagementAccountID) {
		errs = append(errs, fmt.Errorf("scp params: ManagementAccountID %q is not 12 digits", p.ManagementAccountID))
	}

	if len(p.AllowedRegions) == 0 {
		errs = append(errs, errors.New("scp params: AllowedRegions is empty"))
	}

	seen := map[string]bool{}

	for _, r := range p.AllowedRegions {
		switch {
		case r == "":
			errs = append(errs, errors.New("scp params: AllowedRegions has an empty region"))
		case seen[r]:
			errs = append(errs, fmt.Errorf("scp params: AllowedRegions lists %q twice", r))
		}

		seen[r] = true
	}

	if p.ReplicationExemptBuckets == "" {
		errs = append(errs, errors.New("scp params: ReplicationExemptBuckets is empty"))
	}

	if p.PublicAccessBlockExemptBuckets == "" {
		errs = append(errs, errors.New("scp params: PublicAccessBlockExemptBuckets is empty"))
	}

	return errors.Join(errs...)
}

// SCPs returns the eight service control policies, in a fixed order, with
// their documents rendered as indented JSON:
//
//   - deny-leave-org: no member account may leave the organization;
//   - protect-cloudtrail: CloudTrail may not be changed except by the
//     management account or the StackSet execution role;
//   - protect-audit-logs: audit objects and log groups may not be deleted;
//   - deny-root-user: the root user of a member account may do nothing;
//   - restrict-regions: nothing outside AllowedRegions, root user excepted;
//   - deny-data-export: no S3 replication changes outside
//     ReplicationExemptBuckets and no DynamoDB export;
//   - require-encryption: no unencrypted S3 upload or EBS volume;
//   - deny-public-access: no change to S3 public access blocks (bucket-level
//     outside PublicAccessBlockExemptBuckets) and no public EC2 instance.
//
// Which organizational units each attaches to is the registry's business
// (OU.SCPs), not this function's: nothing here attaches anything. The intended
// scope in the estate this was extracted from was the organization root for
// the first, second, third and fifth, every unit but the management one for
// deny-root-user, and the customer unit alone for the last three.
//
// Every problem is reported at once: a bad parameter, or a document that is
// not JSON or is over registry.MaxSCPBytes.
func SCPs(p SCPParams) ([]registry.SCP, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}

	arn := func(rest string) string { return "arn:" + p.Partition + ":" + rest }
	root := arn("iam::*:root")

	docs := []struct {
		name       string
		statements []statement
	}{
		{"deny-leave-org", []statement{
			deny("DenyLeaveOrganization", "organizations:LeaveOrganization"),
		}},
		{"protect-cloudtrail", []statement{
			func() statement {
				s := deny("ProtectCloudTrail",
					"cloudtrail:DeleteTrail", "cloudtrail:StopLogging",
					"cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors")
				s.Condition = condition{
					"StringNotEquals": {"aws:PrincipalAccount": {p.ManagementAccountID}},
					"ArnNotLike":      {"aws:PrincipalArn": {arn("iam::*:role/" + stackSetRole)}},
				}

				return s
			}(),
		}},
		{"protect-audit-logs", []statement{
			{
				Sid: "DenyDeleteAuditS3Objects", Effect: effectDeny, Action: strs{"s3:DeleteObject"},
				Resource: strs{arn("s3:::*-audit-*/*")},
			},
			{
				Sid: "DenyDeleteAuditLogGroups", Effect: effectDeny, Action: strs{"logs:DeleteLogGroup"},
				Resource: strs{arn("logs:*:*:log-group:*audit*")},
			},
		}},
		{"deny-root-user", []statement{
			func() statement {
				s := deny("DenyRootUser", "*")
				s.Condition = condition{"StringLike": {"aws:PrincipalArn": {root}}}

				return s
			}(),
		}},
		{"restrict-regions", []statement{
			func() statement {
				s := deny("RestrictRegions", "*")
				s.Condition = condition{
					"StringNotEquals": {"aws:RequestedRegion": slices.Clone(p.AllowedRegions)},
					"ArnNotLike":      {"aws:PrincipalArn": {root}},
				}

				return s
			}(),
		}},
		{"deny-data-export", []statement{
			{
				Sid: "DenyS3ReplicationOutsideOrg", Effect: effectDeny, Action: strs{"s3:PutReplicationConfiguration"},
				NotResource: strs{arn("s3:::" + p.ReplicationExemptBuckets)},
			},
			deny("DenyDynamoDBExport", "dynamodb:ExportTableToPointInTime"),
		}},
		{"require-encryption", []statement{
			func() statement {
				s := deny("DenyS3UnencryptedUploads", "s3:PutObject")
				s.Condition = condition{"StringNotEquals": {"s3:x-amz-server-side-encryption": {"aws:kms", "AES256"}}}

				return s
			}(),
			func() statement {
				s := deny("DenyUnencryptedEBSVolumes", "ec2:CreateVolume")
				s.Condition = condition{"Bool": {"ec2:Encrypted": {"false"}}}

				return s
			}(),
		}},
		{"deny-public-access", []statement{
			deny("DenyChangeAccountPublicAccess", "s3:PutAccountPublicAccessBlock"),
			{
				Sid: "DenyChangeBucketPublicAccess", Effect: effectDeny, Action: strs{"s3:PutBucketPublicAccessBlock"},
				NotResource: strs{arn("s3:::" + p.PublicAccessBlockExemptBuckets)},
			},
			func() statement {
				s := deny("DenyPublicEC2Instances", "ec2:RunInstances")
				s.Condition = condition{"Bool": {"ec2:AssociatePublicIpAddress": {"true"}}}

				return s
			}(),
		}},
	}

	out := make([]registry.SCP, 0, len(docs))

	var errs []error

	for _, d := range docs {
		b, err := json.MarshalIndent(document{Version: policyVersion, Statement: d.statements}, "", "  ")
		if err != nil {
			errs = append(errs, fmt.Errorf("scp %s: %w", d.name, err))

			continue
		}

		if !json.Valid(b) {
			errs = append(errs, fmt.Errorf("scp %s: document is not valid JSON", d.name))
		}

		if len(b) > registry.MaxSCPBytes {
			errs = append(errs, fmt.Errorf("scp %s: document is %d bytes, over the %d-byte limit",
				d.name, len(b), registry.MaxSCPBytes))
		}

		out = append(out, registry.SCP{Name: d.name, Description: "SCP: " + d.name, Document: string(b)})
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	return out, nil
}
