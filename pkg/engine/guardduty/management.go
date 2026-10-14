package guardduty

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// ManagementRuleDescription is the description of every rule NewManagement
// creates.
const ManagementRuleDescription = "Route the management account's GuardDuty findings to the security-alerts topic"

// ManagementTargetID is the id of the target of every rule NewManagement
// creates.
const ManagementTargetID = "guardduty-management-sns"

// ManagementRuleName is the physical name of the EventBridge rule
// NewManagement creates in region. A topic policy that admits the rule names
// its ARN.
func ManagementRuleName(region string) string {
	return "guardduty-findings-" + region
}

// ManagementArgs configures NewManagement.
type ManagementArgs struct {
	// Profile is the AWS profile of the organization's management account.
	// Required.
	Profile string
	// Regions are the regions to adopt a detector in, in order. Required.
	Regions []string
	// DetectorIDs are the ids of the management account's existing detectors
	// by region. Every region of Regions needs one, and no other region may
	// have one. A detector id is unique per account and region and exists
	// before this code runs, which is why it is an input.
	DetectorIDs map[string]string
	// TopicARNs are the topics findings are published to, by region (as
	// pkg/alerting returns them). Every region of Regions needs one.
	TopicARNs map[string]pulumi.StringOutput
	// Partition is the ARN partition. Required.
	Partition string
	// BoundaryName is the permissions boundary policy set on each region's
	// EventBridge role; it must exist in the management account. Required.
	BoundaryName string
	// FindingPublishingFrequency is how often updates of a finding are
	// published: FIFTEEN_MINUTES, ONE_HOUR or SIX_HOURS. Empty: the provider
	// default.
	FindingPublishingFrequency string
}

// Validate reports every problem with a at once, or returns nil.
func (a *ManagementArgs) Validate() error {
	var errs []error

	for name, v := range map[string]string{
		"Profile": a.Profile, "Partition": a.Partition, "BoundaryName": a.BoundaryName,
	} {
		if v == "" {
			errs = append(errs, fmt.Errorf("args: %s is empty", name))
		}
	}

	if len(a.Regions) == 0 {
		errs = append(errs, errors.New("args: Regions is empty"))
	}

	seen := make(map[string]bool, len(a.Regions))

	for _, region := range a.Regions {
		switch {
		case region == "":
			errs = append(errs, errors.New("args: Regions has an empty region"))
		case seen[region]:
			errs = append(errs, fmt.Errorf("args: Regions has %s twice", region))
		}

		seen[region] = true

		if a.DetectorIDs[region] == "" {
			errs = append(errs, fmt.Errorf("args: no detector id for %s", region))
		}

		if _, ok := a.TopicARNs[region]; !ok {
			errs = append(errs, fmt.Errorf("args: no topic ARN for %s", region))
		}
	}

	extra := make([]string, 0)

	for region := range a.DetectorIDs {
		if !slices.Contains(a.Regions, region) {
			extra = append(extra, region)
		}
	}

	sort.Strings(extra)

	for _, region := range extra {
		errs = append(errs, fmt.Errorf("args: detector id for %s, which is not in Regions", region))
	}

	return errors.Join(errs...)
}

// NewManagement adopts the existing GuardDuty detector of the organization's
// management account in every region and routes its findings to that region's
// topic, one NewImported per region. The management account has no delegated
// administrator and is not one of the member accounts New serves, so its
// detectors exist outside the program and are imported, never created.
//
// The names, per region: provider guardduty-management-provider-<region>;
// children with the prefix guardduty-management-<region> (see NewImported);
// rule ManagementRuleName(region); target id ManagementTargetID.
func NewManagement(ctx *pulumi.Context, logger *slog.Logger, a ManagementArgs) error {
	if err := a.Validate(); err != nil {
		return fmt.Errorf("guardduty management: %w", err)
	}

	for _, region := range a.Regions {
		if err := NewImported(ctx, logger, ImportedArgs{
			Region:                     region,
			Profile:                    a.Profile,
			ProviderName:               "guardduty-management-provider-" + region,
			DetectorID:                 a.DetectorIDs[region],
			SNSTopicARN:                a.TopicARNs[region],
			Partition:                  a.Partition,
			BoundaryName:               a.BoundaryName,
			Prefix:                     "guardduty-management-" + region,
			RuleName:                   ManagementRuleName(region),
			RuleDescription:            ManagementRuleDescription,
			TargetID:                   ManagementTargetID,
			FindingPublishingFrequency: a.FindingPublishingFrequency,
		}); err != nil {
			return fmt.Errorf("management GuardDuty in %s: %w", region, err)
		}
	}

	return nil
}
