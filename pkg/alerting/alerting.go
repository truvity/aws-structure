package alerting

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/chatbot"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/cloudwatch"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/iam"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/sns"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

const (
	policyVersion = "2012-10-17"
	eventsService = "events.amazonaws.com"
)

// Heartbeat configures the schedule that proves the whole path from AWS to the
// receiver is alive.
type Heartbeat struct {
	// RuleName is the physical name of the EventBridge rule. Required.
	RuleName string
	// Input is the constant JSON event the schedule publishes. Required.
	Input string
}

// Chatbot configures the Slack channel configuration.
type Chatbot struct {
	// ConfigurationName names the Slack channel configuration. Required.
	ConfigurationName string
	// RoleName is the physical name of the role Chatbot assumes. Required.
	RoleName string
	// SlackTeamID and SlackChannelID name the workspace and the channel.
	// Required.
	SlackTeamID    string
	SlackChannelID string
}

// Args configures Security.
type Args struct {
	// Partition is the ARN partition. Required.
	Partition string
	// Profile is the AWS profile of the management account. Required.
	Profile string
	// Regions are the regions that get a topic, in order. Required; it must
	// contain PrimaryRegion.
	Regions []string
	// PrimaryRegion hosts the heartbeat, the Chatbot role and the Slack
	// channel configuration. Required.
	PrimaryRegion string
	// OrgID is the organization id the topic policies admit. Required.
	OrgID string
	// TopicName is the physical name of every topic. Required.
	TopicName string
	// Endpoint is the receiver's HTTPS URL every topic is subscribed to.
	// Required unless Delivery.DisableHTTPS. The receiver confirms the
	// subscription itself, at creation, so it must already answer.
	Endpoint string
	// Delivery adds an SQS subscription to every topic and can drop the HTTPS
	// ones; the zero value leaves the render as it was.
	Delivery Delivery
	// Heartbeat and Chatbot configure the two optional-looking parts that the
	// estate keeps: both are required.
	Heartbeat Heartbeat
	Chatbot   Chatbot
	// BoundaryName is the name of the permissions boundary policy set on the
	// Chatbot role; it must exist in the account. Required.
	BoundaryName string
}

// Validate reports every problem with a at once, or returns nil.
func (a *Args) Validate() error {
	var errs []error

	for name, v := range map[string]string{
		"Partition": a.Partition, "Profile": a.Profile, "PrimaryRegion": a.PrimaryRegion, "OrgID": a.OrgID,
		"TopicName": a.TopicName, "BoundaryName": a.BoundaryName,
		"Heartbeat.RuleName": a.Heartbeat.RuleName, "Heartbeat.Input": a.Heartbeat.Input,
		"Chatbot.ConfigurationName": a.Chatbot.ConfigurationName, "Chatbot.RoleName": a.Chatbot.RoleName,
		"Chatbot.SlackTeamID": a.Chatbot.SlackTeamID, "Chatbot.SlackChannelID": a.Chatbot.SlackChannelID,
	} {
		if v == "" {
			errs = append(errs, fmt.Errorf("args: %s is empty", name))
		}
	}

	if a.Endpoint == "" && !a.Delivery.DisableHTTPS {
		errs = append(errs, errors.New("args: Endpoint is empty"))
	}

	if err := a.Delivery.Validate(a.Partition); err != nil {
		errs = append(errs, err)
	}

	found := false

	for _, r := range a.Regions {
		found = found || r == a.PrimaryRegion
	}

	if !found {
		errs = append(errs, fmt.Errorf("args: Regions %v does not contain PrimaryRegion %q", a.Regions, a.PrimaryRegion))
	}

	return errors.Join(errs...)
}

// Security deploys the topics, their policies and subscriptions, the heartbeat
// and the Chatbot configuration, and returns the topic ARN of each region.
func Security(ctx *pulumi.Context, logger *slog.Logger, a Args) (map[string]pulumi.StringOutput, error) {
	if err := a.Validate(); err != nil {
		return nil, fmt.Errorf("alerting: %w", err)
	}

	logger.InfoContext(ctx.Context(), "deploying alerting infrastructure", slog.Int("regions", len(a.Regions)))

	topicARNs := make(map[string]pulumi.StringOutput, len(a.Regions))
	snsTopicARNInputs := make(pulumi.StringArray, 0, len(a.Regions))

	for _, region := range a.Regions {
		provider, err := aws.NewProvider(ctx, fmt.Sprintf("alerting-provider-%s", region), &aws.ProviderArgs{
			Region:  pulumi.String(region),
			Profile: pulumi.String(a.Profile),
		})
		if err != nil {
			return nil, fmt.Errorf("create root provider for %s: %w", region, err)
		}

		topic, err := sns.NewTopic(ctx, fmt.Sprintf("security-alerts-%s", region), &sns.TopicArgs{
			Name: pulumi.String(a.TopicName),
		}, pulumi.Provider(provider))
		if err != nil {
			return nil, fmt.Errorf("create SNS topic in %s: %w", region, err)
		}

		// The heartbeat rule lives in the management account itself and
		// publishes without a role, as the events.amazonaws.com service
		// principal. A service principal carries no aws:PrincipalOrgID, so the
		// org-wide statement does not cover it: the primary region's policy
		// gets one extra statement, scoped to that one rule. Every GuardDuty
		// rule publishes through its account's eventbridge-sns-<region> role,
		// which the org statement covers.
		var rules []rulePublish

		if region == a.PrimaryRegion {
			id, idErr := aws.GetCallerIdentity(ctx, nil, pulumi.Provider(provider))
			if idErr != nil {
				return nil, fmt.Errorf("get caller identity in %s: %w", region, idErr)
			}

			rules = append(rules, rulePublish{
				sid: "AllowHeartbeatRulePublish",
				arn: fmt.Sprintf("arn:%s:events:%s:%s:rule/%s", a.Partition, region, id.AccountId, a.Heartbeat.RuleName),
			})
		}

		policyDoc, err := topicPolicy(a.Partition, a.OrgID, region, rules)
		if err != nil {
			return nil, err
		}

		if _, err = sns.NewTopicPolicy(ctx, fmt.Sprintf("security-alerts-policy-%s", region), &sns.TopicPolicyArgs{
			Arn:    topic.Arn,
			Policy: pulumi.String(policyDoc),
		}, pulumi.Provider(provider)); err != nil {
			return nil, fmt.Errorf("create SNS topic policy in %s: %w", region, err)
		}

		// The receiver's door. Confirmation happens ONCE, at creation: the
		// endpoint must already answer, else this stays PendingConfirmation.
		// No endpointAutoConfirms: the receiver confirms allow-listed topics
		// itself.
		if !a.Delivery.DisableHTTPS {
			if _, err = sns.NewTopicSubscription(ctx, fmt.Sprintf("alert-ingress-subscription-%s", region), &sns.TopicSubscriptionArgs{
				Topic:              topic.Arn,
				Protocol:           pulumi.String("https"),
				Endpoint:           pulumi.String(a.Endpoint),
				RawMessageDelivery: pulumi.Bool(false),
				DeliveryPolicy:     pulumi.String(DeliveryPolicy()),
			}, pulumi.Provider(provider)); err != nil {
				return nil, fmt.Errorf("create alert-ingress subscription in %s: %w", region, err)
			}
		}

		if err = a.Delivery.SubscribeQueue(ctx, fmt.Sprintf("alert-ingress-sqs-subscription-%s", region), topic.Arn,
			pulumi.Provider(provider)); err != nil {
			return nil, err
		}

		if region == a.PrimaryRegion {
			if err := heartbeat(ctx, provider, topic.Arn, a.Heartbeat); err != nil {
				return nil, err
			}
		}

		topicARNs[region] = topic.Arn
		snsTopicARNInputs = append(snsTopicARNInputs, topic.Arn)

		logger.InfoContext(ctx.Context(), "SNS topic created", slog.String("region", region))
	}

	if err := chatbotConfiguration(ctx, a, snsTopicARNInputs); err != nil {
		return nil, err
	}

	logger.InfoContext(ctx.Context(), "alerting infrastructure deployed", slog.Int("regions", len(a.Regions)))

	return topicARNs, nil
}

// chatbotConfiguration creates the role Chatbot assumes and the Slack channel
// configuration over the topics. IAM is global: the primary region's provider.
func chatbotConfiguration(ctx *pulumi.Context, a Args, topics pulumi.StringArray) error {
	primary, err := aws.NewProvider(ctx, "alerting-provider-iam", &aws.ProviderArgs{
		Region:  pulumi.String(a.PrimaryRegion),
		Profile: pulumi.String(a.Profile),
	})
	if err != nil {
		return fmt.Errorf("create IAM provider: %w", err)
	}

	// The boundary is created by the account's IAM controls: deploy those
	// first.
	callerIdentity, err := aws.GetCallerIdentity(ctx, nil, pulumi.Provider(primary))
	if err != nil {
		return fmt.Errorf("get caller identity: %w", err)
	}

	boundaryARN := fmt.Sprintf("arn:%s:iam::%s:policy/%s", a.Partition, callerIdentity.AccountId, a.BoundaryName)

	assume, err := chatbotAssumeRolePolicy()
	if err != nil {
		return err
	}

	role, err := iam.NewRole(ctx, "chatbot-slack-role", &iam.RoleArgs{
		Name:                pulumi.String(a.Chatbot.RoleName),
		AssumeRolePolicy:    pulumi.String(assume),
		PermissionsBoundary: pulumi.StringPtr(boundaryARN),
	}, pulumi.Provider(primary))
	if err != nil {
		return fmt.Errorf("create chatbot IAM role: %w", err)
	}

	// Chatbot requires explicit permissions: the boundary only caps, it does
	// not grant. ReadOnlyAccess is the recommended minimum for a
	// notification-only Chatbot.
	if _, err = iam.NewRolePolicyAttachment(ctx, "chatbot-readonly-access", &iam.RolePolicyAttachmentArgs{
		Role:      role.Name,
		PolicyArn: pulumi.Sprintf("arn:%s:iam::aws:policy/ReadOnlyAccess", a.Partition),
	}, pulumi.Provider(primary)); err != nil {
		return fmt.Errorf("attach ReadOnlyAccess to chatbot role: %w", err)
	}

	if _, err = chatbot.NewSlackChannelConfiguration(ctx, "security-alerts-chatbot", &chatbot.SlackChannelConfigurationArgs{
		ConfigurationName: pulumi.String(a.Chatbot.ConfigurationName),
		IamRoleArn:        role.Arn,
		SlackTeamId:       pulumi.String(a.Chatbot.SlackTeamID),
		SlackChannelId:    pulumi.String(a.Chatbot.SlackChannelID),
		SnsTopicArns:      topics,
	}, pulumi.Provider(primary)); err != nil {
		return fmt.Errorf("create Chatbot Slack configuration: %w", err)
	}

	return nil
}

// heartbeat creates the 15-minute schedule that proves the whole AWS -> SNS ->
// receiver path is alive, on the topic that already carries the findings, so a
// silent break of the path (not only of the schedule) is noticed.
func heartbeat(ctx *pulumi.Context, provider *aws.Provider, topicARN pulumi.StringInput, h Heartbeat) error {
	rule, err := cloudwatch.NewEventRule(ctx, "alert-ingress-heartbeat-rule", &cloudwatch.EventRuleArgs{
		Name:               pulumi.String(h.RuleName),
		Description:        pulumi.String("Heartbeat for alert-ingress: proves SNS to the receiver is alive"),
		ScheduleExpression: pulumi.String("rate(15 minutes)"),
	}, pulumi.Provider(provider))
	if err != nil {
		return fmt.Errorf("create alert-ingress heartbeat rule: %w", err)
	}

	if _, err = cloudwatch.NewEventTarget(ctx, "alert-ingress-heartbeat-target", &cloudwatch.EventTargetArgs{
		Rule:     rule.Name,
		Arn:      topicARN,
		TargetId: pulumi.String("alert-ingress-heartbeat-sns"),
		Input:    pulumi.String(h.Input),
	}, pulumi.Provider(provider)); err != nil {
		return fmt.Errorf("create alert-ingress heartbeat target: %w", err)
	}

	return nil
}

// DeliveryPolicy is an HTTP/S subscription's delivery policy. The default (3
// retries, about 20s apart) loses a message when the receiver or its backend
// is down for a few minutes, with nothing to say so.
//
//   - numRetries 12 = 2 at the 20s floor, 5 of exponential backoff 20s -> 600s,
//     5 at the 600s ceiling: about 67 minutes in all, longer than any planned
//     receiver rollout, short enough that a stale finding is not replayed hours
//     later;
//   - throttle 2/s per subscription: a burst drains in seconds.
func DeliveryPolicy() string {
	type (
		retry struct {
			MinDelayTarget     int    `json:"minDelayTarget"`
			MaxDelayTarget     int    `json:"maxDelayTarget"`
			NumRetries         int    `json:"numRetries"`
			NumNoDelayRetries  int    `json:"numNoDelayRetries"`
			NumMinDelayRetries int    `json:"numMinDelayRetries"`
			NumMaxDelayRetries int    `json:"numMaxDelayRetries"`
			BackoffFunction    string `json:"backoffFunction"`
		}
		throttle struct {
			MaxReceivesPerSecond int `json:"maxReceivesPerSecond"`
		}
		policy struct {
			HealthyRetryPolicy retry    `json:"healthyRetryPolicy"`
			ThrottlePolicy     throttle `json:"throttlePolicy"`
		}
	)

	b, err := json.Marshal(policy{
		HealthyRetryPolicy: retry{
			MinDelayTarget:     20,
			MaxDelayTarget:     600,
			NumRetries:         12,
			NumNoDelayRetries:  0,
			NumMinDelayRetries: 2,
			NumMaxDelayRetries: 5,
			BackoffFunction:    "exponential",
		},
		ThrottlePolicy: throttle{MaxReceivesPerSecond: 2},
	})
	if err != nil {
		panic(fmt.Sprintf("marshal delivery policy: %v", err))
	}

	return string(b)
}

func chatbotAssumeRolePolicy() (string, error) {
	type (
		statement struct {
			Sid       string            `json:"Sid"`
			Effect    string            `json:"Effect"`
			Principal map[string]string `json:"Principal"`
			Action    string            `json:"Action"`
		}
		document struct {
			Version   string      `json:"Version"`
			Statement []statement `json:"Statement"`
		}
	)

	b, err := json.Marshal(document{
		Version: policyVersion,
		Statement: []statement{{
			Sid:       "ChatbotAssume",
			Effect:    "Allow",
			Principal: map[string]string{"Service": "chatbot.amazonaws.com"},
			Action:    "sts:AssumeRole",
		}},
	})
	if err != nil {
		return "", fmt.Errorf("marshal chatbot assume role policy: %w", err)
	}

	return string(b), nil
}

// rulePublish is one EventBridge rule of the topic's own account that publishes
// without a role, as the events.amazonaws.com service principal.
type rulePublish struct {
	sid string
	arn string
}

// topicPolicy returns the JSON policy of the region's topic.
//
// AllowEventBridgePublish admits the member accounts' EventBridge targets.
// Those carry RoleArn eventbridge-sns-<region>, and with a role set EventBridge
// publishes AS THAT ROLE, an IAM principal of the member account, not as the
// events.amazonaws.com service. So the statement names the role: any principal
// of the organization (aws:PrincipalOrgID) whose ARN is that role in any
// account. A service principal + aws:PrincipalOrgID could never match: a
// service principal carries no aws:PrincipalOrgID.
//
// Each rule adds one service-principal statement scoped by aws:SourceArn to
// that rule of the topic's own account (no role, so no org condition).
func topicPolicy(partition, orgID, region string, rules []rulePublish) (string, error) {
	type (
		statement struct {
			Sid       string            `json:"Sid"`
			Effect    string            `json:"Effect"`
			Principal map[string]string `json:"Principal"`
			Action    string            `json:"Action"`
			Resource  string            `json:"Resource"`
			Condition map[string]any    `json:"Condition"`
		}
		document struct {
			Version   string      `json:"Version"`
			Statement []statement `json:"Statement"`
		}
	)

	doc := document{
		Version: policyVersion,
		Statement: []statement{{
			Sid:       "AllowEventBridgePublish",
			Effect:    "Allow",
			Principal: map[string]string{"AWS": "*"},
			Action:    "sns:Publish",
			Resource:  "*",
			Condition: map[string]any{
				"StringEquals": map[string]string{"aws:PrincipalOrgID": orgID},
				"ArnLike": map[string]string{
					"aws:PrincipalArn": fmt.Sprintf("arn:%s:iam::*:role/eventbridge-sns-%s", partition, region),
				},
			},
		}},
	}

	for _, r := range rules {
		doc.Statement = append(doc.Statement, statement{
			Sid:       r.sid,
			Effect:    "Allow",
			Principal: map[string]string{"Service": eventsService},
			Action:    "sns:Publish",
			Resource:  "*",
			Condition: map[string]any{
				"ArnEquals": map[string]string{"aws:SourceArn": r.arn},
			},
		})
	}

	b, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("marshal SNS topic policy: %w", err)
	}

	return string(b), nil
}
