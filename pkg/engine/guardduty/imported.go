package guardduty

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/cloudwatch"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/guardduty"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/iam"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// ImportedArgs configures NewImported.
type ImportedArgs struct {
	// Region is the AWS region of the detector. Required.
	Region string
	// Profile is the AWS profile of the provider this function creates, in the
	// account that owns the detector. Required.
	Profile string
	// ProviderName is the logical name of that provider. Required.
	ProviderName string
	// DetectorID is the id of the existing detector. Required.
	DetectorID string
	// SNSTopicARN is the topic findings are published to. Required.
	SNSTopicARN pulumi.StringInput
	// Partition is the ARN partition, for the boundary's ARN. Required.
	Partition string
	// BoundaryName is the name of the permissions boundary policy set on the
	// EventBridge role; it must exist in the account. Required.
	BoundaryName string
	// Prefix is the logical-name prefix of the detector, the rule, the role,
	// its policy and the target: "<Prefix>-detector", "<Prefix>-rule",
	// "<Prefix>-eventbridge-role", "<Prefix>-eventbridge-policy",
	// "<Prefix>-target". Required.
	Prefix string
	// RuleName is the physical name of the EventBridge rule. Required.
	RuleName string
	// RuleDescription describes the rule.
	RuleDescription string
	// TargetID is the id of the rule's target. Required.
	TargetID string
	// FindingPublishingFrequency is how often updates of a finding are
	// published: FIFTEEN_MINUTES, ONE_HOUR or SIX_HOURS. Empty: the provider
	// default.
	FindingPublishingFrequency string
}

// NewImported adopts the existing GuardDuty detector of an account that is not
// a member (the organization's management account has no delegated administrator
// and is not among the member accounts the component serves) and routes its
// findings like the component does:
//
//   - the detector is IMPORTED with Enable=true, never created, and retained
//     on delete, so removing this code never disables GuardDuty;
//   - a rule matches every finding;
//   - the rule's target publishes to the topic as the account's
//     eventbridge-sns-<region> role (the role and its sns:Publish policy are
//     created here, bounded by the boundary the caller names), which the
//     topic's policy must admit.
//
// It creates its own provider (the account is known by profile) and looks up
// the account id from it.
func NewImported(ctx *pulumi.Context, logger *slog.Logger, a ImportedArgs) error {
	if err := a.validate(); err != nil {
		return fmt.Errorf("guardduty imported %s: %w", a.Prefix, err)
	}

	provider, err := aws.NewProvider(ctx, a.ProviderName, &aws.ProviderArgs{
		Region:  pulumi.String(a.Region),
		Profile: pulumi.String(a.Profile),
	})
	if err != nil {
		return fmt.Errorf("create provider for %s: %w", a.Region, err)
	}

	id, err := aws.GetCallerIdentity(ctx, nil, pulumi.Provider(provider))
	if err != nil {
		return fmt.Errorf("get caller identity in %s: %w", a.Region, err)
	}

	detector := &guardduty.DetectorArgs{Enable: pulumi.Bool(true)}
	if a.FindingPublishingFrequency != "" {
		detector.FindingPublishingFrequency = pulumi.String(a.FindingPublishingFrequency)
	}

	if _, err := guardduty.NewDetector(ctx, a.Prefix+"-detector", detector,
		pulumi.Provider(provider),
		pulumi.Import(pulumi.ID(a.DetectorID)),
		pulumi.RetainOnDelete(true),
	); err != nil {
		return fmt.Errorf("import GuardDuty detector in %s: %w", a.Region, err)
	}

	rule, err := cloudwatch.NewEventRule(ctx, a.Prefix+"-rule", &cloudwatch.EventRuleArgs{
		Name:         pulumi.String(a.RuleName),
		Description:  pulumi.String(a.RuleDescription),
		EventPattern: pulumi.String(findingsPattern),
	}, pulumi.Provider(provider))
	if err != nil {
		return fmt.Errorf("create GuardDuty rule in %s: %w", a.Region, err)
	}

	assume, err := assumeRolePolicy()
	if err != nil {
		return err
	}

	role, err := iam.NewRole(ctx, a.Prefix+"-eventbridge-role", &iam.RoleArgs{
		Name:             pulumi.Sprintf("eventbridge-sns-%s", a.Region),
		AssumeRolePolicy: pulumi.String(assume),
		PermissionsBoundary: pulumi.Sprintf("arn:%s:iam::%s:policy/%s",
			a.Partition, id.AccountId, a.BoundaryName),
	}, pulumi.Provider(provider))
	if err != nil {
		return fmt.Errorf("create EventBridge role in %s: %w", a.Region, err)
	}

	if _, err := iam.NewRolePolicy(ctx, a.Prefix+"-eventbridge-policy", &iam.RolePolicyArgs{
		Name:   pulumi.String("sns-publish"),
		Role:   role.Name,
		Policy: a.SNSTopicARN.ToStringOutput().ApplyT(snsPublishPolicy).(pulumi.StringOutput),
	}, pulumi.Provider(provider)); err != nil {
		return fmt.Errorf("create EventBridge role policy in %s: %w", a.Region, err)
	}

	if _, err := cloudwatch.NewEventTarget(ctx, a.Prefix+"-target", &cloudwatch.EventTargetArgs{
		Rule:     rule.Name,
		Arn:      a.SNSTopicARN,
		RoleArn:  role.Arn,
		TargetId: pulumi.String(a.TargetID),
	}, pulumi.Provider(provider)); err != nil {
		return fmt.Errorf("create GuardDuty target in %s: %w", a.Region, err)
	}

	logger.InfoContext(ctx.Context(), "imported GuardDuty detector routed", slog.String("region", a.Region))

	return nil
}

func (a *ImportedArgs) validate() error {
	var errs []error

	for name, v := range map[string]string{
		"Region": a.Region, "Profile": a.Profile, "ProviderName": a.ProviderName, "DetectorID": a.DetectorID,
		"Partition": a.Partition, "BoundaryName": a.BoundaryName, "Prefix": a.Prefix, "RuleName": a.RuleName,
		"TargetID": a.TargetID,
	} {
		if v == "" {
			errs = append(errs, fmt.Errorf("args: %s is empty", name))
		}
	}

	if a.SNSTopicARN == nil {
		errs = append(errs, errors.New("args: SNSTopicARN is unset"))
	}

	return errors.Join(errs...)
}
