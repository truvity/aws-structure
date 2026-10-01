package guardduty

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/cloudwatch"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/guardduty"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/iam"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// TypeToken is the Pulumi type of the component.
const TypeToken = "truvity:aws-structure:AccountRegionGuardDuty"

const (
	policyVersion   = "2012-10-17"
	eventsSvc       = "events.amazonaws.com"
	findingsPattern = `{"source":["aws.guardduty"],"detail-type":["GuardDuty Finding"]}`
)

// Kind names which child a logical name is for.
type Kind string

const (
	// KindDetector is the GuardDuty detector.
	KindDetector Kind = "detector"
	// KindRole is the role EventBridge assumes to publish.
	KindRole Kind = "eventbridge-role"
	// KindRolePolicy is the inline policy of that role.
	KindRolePolicy Kind = "eventbridge-policy"
	// KindRule is the EventBridge rule matching findings.
	KindRule Kind = "rule"
	// KindTarget is the rule's target, the topic.
	KindTarget Kind = "target"
)

// kinds lists every child in registration order.
var kinds = []Kind{KindDetector, KindRole, KindRolePolicy, KindRule, KindTarget}

// Child identifies one child for a NameFunc.
type Child struct {
	// Component is the logical name the component was registered with.
	Component string
	Kind      Kind
	// Account is Args.Account.
	Account string
	// Region is Args.Region.
	Region string
}

// NameFunc returns the Pulumi logical name of a child. The returned name must
// be unique among the component's children; it is part of the child's URN.
type NameFunc func(Child) string

// DefaultName names a child "<c>-<kind>": "<c>-detector",
// "<c>-eventbridge-role", "<c>-eventbridge-policy", "<c>-rule" and
// "<c>-target". These names are API.
func DefaultName(c Child) string {
	return c.Component + "-" + string(c.Kind)
}

// Args configures the component.
type Args struct {
	// Account is the account's name. Required; it only feeds Child.Account.
	Account string
	// Region is the AWS region of Provider, such as "region-a". Required; it
	// is part of the physical names of the role ("eventbridge-sns-<region>")
	// and of the rule ("guardduty-findings-<region>").
	Region string

	// SNSTopicARN is the ARN of the topic findings are published to. It may
	// be in another account. Required.
	SNSTopicARN pulumi.StringInput
	// PermissionsBoundary is the ARN of the boundary policy set on the
	// EventBridge role. Required: a role without a boundary can grow past it.
	PermissionsBoundary pulumi.StringInput

	// Provider is the AWS provider of the account in Region. Required.
	Provider pulumi.ProviderResource

	// Names overrides the logical names of the children. Nil uses
	// DefaultName.
	Names NameFunc
	// LegacyTopLevel makes every child carry an alias from the URN it has
	// when it is registered directly under the stack (no parent), with the
	// same type and the name Names gives it. Set it when adopting resources
	// that were created before they were wrapped in this component.
	LegacyTopLevel bool
}

// AccountRegionGuardDuty is the component.
type AccountRegionGuardDuty struct {
	pulumi.ResourceState
}

// Validate reports every problem with args at once, or returns nil.
func (a *Args) Validate() error {
	var errs []error

	if a.Account == "" {
		errs = append(errs, errors.New("args: Account is empty"))
	}

	if a.Region == "" {
		errs = append(errs, errors.New("args: Region is empty"))
	}

	if a.Provider == nil {
		errs = append(errs, errors.New("args: Provider is nil"))
	}

	if a.SNSTopicARN == nil {
		errs = append(errs, errors.New("args: SNSTopicARN is unset"))
	}

	if a.PermissionsBoundary == nil {
		errs = append(errs, errors.New("args: PermissionsBoundary is unset"))
	}

	errs = append(errs, a.checkNames("")...)

	return errors.Join(errs...)
}

// checkNames refuses a naming hook that returns an empty or repeated name.
func (a *Args) checkNames(component string) []error {
	names := a.Names
	if names == nil {
		names = DefaultName
	}

	var errs []error

	seen := map[string]Kind{}

	for _, k := range kinds {
		n := names(Child{Component: component, Kind: k, Account: a.Account, Region: a.Region})

		if n == "" {
			errs = append(errs, fmt.Errorf("args: Names returned an empty name for %s", k))

			continue
		}

		if prev, dup := seen[n]; dup {
			errs = append(errs, fmt.Errorf("args: Names returned %q for both %s and %s", n, prev, k))
		}

		seen[n] = k
	}

	return errs
}

// New registers the component and its children. It returns an error,
// registering nothing, when args.Validate does or when Names returns an empty
// or repeated name.
//
// The provider comes from Args, not from pulumi.Providers.
func New(ctx *pulumi.Context, name string, args *Args, opts ...pulumi.ResourceOption) (*AccountRegionGuardDuty, error) {
	if args == nil {
		return nil, errors.New("guardduty: args is nil")
	}

	if err := args.Validate(); err != nil {
		return nil, fmt.Errorf("guardduty %s: %w", name, err)
	}

	if err := errors.Join(args.checkNames(name)...); err != nil {
		return nil, fmt.Errorf("guardduty %s: %w", name, err)
	}

	names := args.Names
	if names == nil {
		names = DefaultName
	}

	comp := &AccountRegionGuardDuty{}
	if err := ctx.RegisterComponentResource(TypeToken, name, comp, opts...); err != nil {
		return nil, err
	}

	child := func(k Kind) string {
		return names(Child{Component: name, Kind: k, Account: args.Account, Region: args.Region})
	}

	opt := func() []pulumi.ResourceOption {
		o := []pulumi.ResourceOption{pulumi.Parent(comp), pulumi.Provider(args.Provider)}
		if args.LegacyTopLevel {
			o = append(o, pulumi.Aliases([]pulumi.Alias{{NoParent: pulumi.Bool(true)}}))
		}

		return o
	}

	if _, err := guardduty.NewDetector(ctx, child(KindDetector), &guardduty.DetectorArgs{
		Enable: pulumi.Bool(true),
	}, opt()...); err != nil {
		return nil, fmt.Errorf("create detector in %s/%s: %w", args.Account, args.Region, err)
	}

	assume, err := assumeRolePolicy()
	if err != nil {
		return nil, err
	}

	role, err := iam.NewRole(ctx, child(KindRole), &iam.RoleArgs{
		Name:                pulumi.Sprintf("eventbridge-sns-%s", args.Region),
		AssumeRolePolicy:    pulumi.String(assume),
		PermissionsBoundary: args.PermissionsBoundary,
	}, opt()...)
	if err != nil {
		return nil, fmt.Errorf("create EventBridge role in %s/%s: %w", args.Account, args.Region, err)
	}

	publish := args.SNSTopicARN.ToStringOutput().ApplyT(snsPublishPolicy).(pulumi.StringOutput)

	if _, err := iam.NewRolePolicy(ctx, child(KindRolePolicy), &iam.RolePolicyArgs{
		Name:   pulumi.String("sns-publish"),
		Role:   role.Name,
		Policy: publish,
	}, opt()...); err != nil {
		return nil, fmt.Errorf("create EventBridge role policy in %s/%s: %w", args.Account, args.Region, err)
	}

	rule, err := cloudwatch.NewEventRule(ctx, child(KindRule), &cloudwatch.EventRuleArgs{
		Name:         pulumi.Sprintf("guardduty-findings-%s", args.Region),
		Description:  pulumi.String("Route GuardDuty findings to root SNS topic"),
		EventPattern: pulumi.String(findingsPattern),
	}, opt()...)
	if err != nil {
		return nil, fmt.Errorf("create EventBridge rule in %s/%s: %w", args.Account, args.Region, err)
	}

	if _, err := cloudwatch.NewEventTarget(ctx, child(KindTarget), &cloudwatch.EventTargetArgs{
		Rule:     rule.Name,
		Arn:      args.SNSTopicARN,
		RoleArn:  role.Arn,
		TargetId: pulumi.String("security-alerts-sns"),
	}, opt()...); err != nil {
		return nil, fmt.Errorf("create EventBridge target in %s/%s: %w", args.Account, args.Region, err)
	}

	if err := ctx.RegisterResourceOutputs(comp, pulumi.Map{}); err != nil {
		return nil, err
	}

	return comp, nil
}

// assumeRolePolicy is the trust policy letting EventBridge assume the role.
func assumeRolePolicy() (string, error) {
	type statement struct {
		Sid       string            `json:"Sid"`
		Effect    string            `json:"Effect"`
		Principal map[string]string `json:"Principal"`
		Action    string            `json:"Action"`
	}

	type document struct {
		Version   string      `json:"Version"`
		Statement []statement `json:"Statement"`
	}

	b, err := json.Marshal(document{
		Version: policyVersion,
		Statement: []statement{{
			Sid:       "EventBridgeAssume",
			Effect:    "Allow",
			Principal: map[string]string{"Service": eventsSvc},
			Action:    "sts:AssumeRole",
		}},
	})
	if err != nil {
		return "", fmt.Errorf("marshal EventBridge assume role policy: %w", err)
	}

	return string(b), nil
}

// snsPublishPolicy is the inline policy allowing sns:Publish on one topic.
func snsPublishPolicy(topicARN string) (string, error) {
	type statement struct {
		Sid      string `json:"Sid"`
		Effect   string `json:"Effect"`
		Action   string `json:"Action"`
		Resource string `json:"Resource"`
	}

	type document struct {
		Version   string      `json:"Version"`
		Statement []statement `json:"Statement"`
	}

	b, err := json.Marshal(document{
		Version: policyVersion,
		Statement: []statement{{
			Sid:      "AllowSNSPublish",
			Effect:   "Allow",
			Action:   "sns:Publish",
			Resource: topicARN,
		}},
	})
	if err != nil {
		return "", fmt.Errorf("marshal SNS publish policy: %w", err)
	}

	return string(b), nil
}
