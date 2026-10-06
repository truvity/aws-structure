package cost

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/budgets"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/computeoptimizer"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/costexplorer"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/sns"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/alerting"
)

type (
	// Account is one linked account's monthly budget.
	Account struct {
		// Name is the budget's name suffix ("cost-monthly-<Name>") and the
		// suffix of the account's logical names. No spaces: a receiver may
		// read the name from the text with a \S+ pattern.
		Name       string
		ID         string
		MonthlyUSD int
	}

	// Monitor identifies an existing anomaly monitor.
	Monitor struct {
		Name string
		ARN  string
	}

	// ServiceValue maps one AWS service CODE (SERVICE_CODE dimension, such as
	// AmazonEC2; not a display name) to a category value.
	ServiceValue struct {
		Service string
		Value   string
	}

	// NodePool maps one EKS node pool name (tag eks:kubernetes-node-pool-name)
	// to its category value.
	NodePool struct {
		Pool  string
		Value string
	}

	// Category is a cost category that splits one linked account.
	Category struct {
		Name string
		// Account names an entry of Accounts: the account that is split.
		Account string
		// OtherValue is the value of every line outside Account.
		OtherValue string
		// DefaultValue is the value of a line of Account no rule matches.
		DefaultValue string
		// NodePools each get a value of their own.
		NodePools []NodePool
		// Services each get a value of their own for the spend no tag
		// claims, in order.
		Services []ServiceValue
	}

	// Spec is what the estate wants alerted and attributed.
	Spec struct {
		TotalMonthlyUSD int
		Accounts        []Account

		// AnomalyThresholdUSD is the total impact from which an anomaly is
		// alerted at once (ANOMALY_TOTAL_IMPACT_ABSOLUTE).
		AnomalyThresholdUSD int
		// DefaultMonitor is the AWS-created SERVICE monitor to adopt: AWS allows
		// one per account. It is never deleted and its own email subscription
		// is left alone.
		DefaultMonitor     Monitor
		PerAccountMonitors bool

		ComputeOptimizer bool
		// Category is the cost category; nil means none (and then no cost
		// allocation tags are activated either).
		Category *Category
	}

	// Args configures Deploy.
	Args struct {
		// Partition is the ARN partition. Required.
		Partition string
		// Profile is the AWS profile of the payer account. Required.
		Profile string
		// PayerAccountID is the payer account's id. Required.
		PayerAccountID string
		// Region hosts both topics: Cost Explorer (and so the anomaly
		// subscription) is a single-region service and wants its topic
		// there; Budgets is global and publishes to the region the ARN names.
		// Required.
		Region string
		// BudgetsTopic and AnomaliesTopic are the topics' physical names;
		// the receiver's allow-list spells them out. Required.
		BudgetsTopic   string
		AnomaliesTopic string
		// Endpoint is the receiver's HTTPS URL. The receiver confirms a
		// subscription of an allow-listed topic itself, at creation. Required.
		Endpoint string
		Spec     Spec
	}
)

// Tag keys the cost category reads. Every one already exists in the billing
// data: EKS Auto Mode writes the pool name on the instances it launches, the
// EBS CSI driver writes the PVC namespace on a volume, and an ACK controller
// writes the namespace of the CR that made an AWS object. None is written here.
const (
	tagNodePool     = "eks:kubernetes-node-pool-name"
	tagPVCNamespace = "kubernetes.io/created-for/pvc/namespace"
	tagACKNamespace = "services.k8s.aws/namespace"

	dimLinkedAccount = "LINKED_ACCOUNT"
	// SERVICE_CODE takes a service CODE (AmazonEC2), not the display name of
	// the SERVICE dimension, which a cost category refuses.
	dimServiceCode = "SERVICE_CODE"
	dimRecordType  = "RECORD_TYPE"

	matchEquals = "EQUALS"
)

// categoryDimensions are the only dimensions a cost category rule may use (the
// API's own list). Not SERVICE: the first create was refused for it, and a
// preview never validates rules.
var categoryDimensions = map[string]bool{
	"USAGE_TYPE": true, "RECORD_TYPE": true, "LINKED_ACCOUNT_NAME": true,
	"SERVICE_CODE": true, "LINKED_ACCOUNT": true, "BILLING_ENTITY": true, "REGION": true,
}

// allocationTagKeys are the keys activated as cost allocation tags: exactly the
// ones the cost category reads. A tag only reaches the category once active,
// and only for spend from the activation on.
var allocationTagKeys = []string{tagNodePool, tagPVCNamespace, tagACKNamespace}

// tagResourceName makes a tag key a Pulumi resource name.
var tagResourceName = strings.NewReplacer(":", "-", "/", "-", ".", "-")

// Validate reports every problem with a at once, or returns nil.
func (a *Args) Validate() error {
	var errs []error

	for name, v := range map[string]string{
		"Partition": a.Partition, "Profile": a.Profile, "PayerAccountID": a.PayerAccountID, "Region": a.Region,
		"BudgetsTopic": a.BudgetsTopic, "AnomaliesTopic": a.AnomaliesTopic, "Endpoint": a.Endpoint,
		"Spec.DefaultMonitor.ARN": a.Spec.DefaultMonitor.ARN, "Spec.DefaultMonitor.Name": a.Spec.DefaultMonitor.Name,
	} {
		if v == "" {
			errs = append(errs, fmt.Errorf("args: %s is empty", name))
		}
	}

	if a.Spec.TotalMonthlyUSD <= 0 {
		errs = append(errs, errors.New("args: Spec.TotalMonthlyUSD must be positive"))
	}

	if len(a.Spec.Accounts) == 0 {
		errs = append(errs, errors.New("args: Spec.Accounts is empty"))
	}

	if c := a.Spec.Category; c != nil && a.accountID(c.Account) == "" {
		errs = append(errs, fmt.Errorf("args: cost category account %q is not in Spec.Accounts", c.Account))
	}

	return errors.Join(errs...)
}

func (a *Args) accountID(name string) string {
	for _, acct := range a.Spec.Accounts {
		if acct.Name == name {
			return acct.ID
		}
	}

	return ""
}

// Deploy creates the topics, budgets, anomaly detection and, when the spec has
// them, Compute Optimizer enrollment and the cost category.
func Deploy(ctx *pulumi.Context, logger *slog.Logger, a Args) error {
	if err := a.Validate(); err != nil {
		return fmt.Errorf("cost: %w", err)
	}

	logger.InfoContext(ctx.Context(), "deploying cost alerts",
		slog.Int("account_budgets", len(a.Spec.Accounts)),
		slog.Bool("per_account_monitors", a.Spec.PerAccountMonitors),
	)

	provider, err := aws.NewProvider(ctx, "cost-alerts-provider", &aws.ProviderArgs{
		Region:  pulumi.String(a.Region),
		Profile: pulumi.String(a.Profile),
	})
	if err != nil {
		return fmt.Errorf("create cost alerts provider: %w", err)
	}

	opt := pulumi.Provider(provider)

	budgetsTopic, err := sns.NewTopic(ctx, "cost-budgets-topic", &sns.TopicArgs{
		Name: pulumi.String(a.BudgetsTopic),
	}, opt)
	if err != nil {
		return fmt.Errorf("create budgets topic: %w", err)
	}

	anomalyTopic, err := sns.NewTopic(ctx, "cost-anomalies-topic", &sns.TopicArgs{
		Name: pulumi.String(a.AnomaliesTopic),
	}, opt)
	if err != nil {
		return fmt.Errorf("create anomalies topic: %w", err)
	}

	payer := a.PayerAccountID

	if _, err := sns.NewTopicPolicy(ctx, "cost-budgets-topic-policy", &sns.TopicPolicyArgs{
		Arn: budgetsTopic.Arn,
		Policy: budgetsTopic.Arn.ApplyT(func(arn string) string {
			return topicPolicy("AllowBudgetsPublish", "budgets.amazonaws.com", arn, map[string]any{
				"StringEquals": map[string]string{"aws:SourceAccount": payer},
				"ArnLike":      map[string]string{"aws:SourceArn": fmt.Sprintf("arn:%s:budgets::%s:*", a.Partition, payer)},
			})
		}).(pulumi.StringOutput),
	}, opt); err != nil {
		return fmt.Errorf("create budgets topic policy: %w", err)
	}

	if _, err := sns.NewTopicPolicy(ctx, "cost-anomalies-topic-policy", &sns.TopicPolicyArgs{
		Arn: anomalyTopic.Arn,
		Policy: anomalyTopic.Arn.ApplyT(func(arn string) string {
			// No source condition, on purpose: it is unverified that the cost
			// anomaly service sends aws:SourceAccount, and a condition on a
			// key it omits would silently block every anomaly. A forged
			// publish can at most raise one warning alert.
			return topicPolicy("AllowCostAnomalyPublish", "costalerts.amazonaws.com", arn, nil)
		}).(pulumi.StringOutput),
	}, opt); err != nil {
		return fmt.Errorf("create anomalies topic policy: %w", err)
	}

	// The receiver confirms a subscription of an allow-listed topic itself, at
	// creation: the allow-list change must be synced first.
	for _, s := range []struct {
		name  string
		topic *sns.Topic
	}{{"budgets", budgetsTopic}, {"anomalies", anomalyTopic}} {
		if _, err := sns.NewTopicSubscription(ctx, "cost-"+s.name+"-alert-ingress", &sns.TopicSubscriptionArgs{
			Topic:              s.topic.Arn,
			Protocol:           pulumi.String("https"),
			Endpoint:           pulumi.String(a.Endpoint),
			RawMessageDelivery: pulumi.Bool(false),
			DeliveryPolicy:     pulumi.String(alerting.DeliveryPolicy()),
		}, opt); err != nil {
			return fmt.Errorf("create %s subscription: %w", s.name, err)
		}
	}

	if err := deployBudgets(ctx, &a, budgetsTopic, opt); err != nil {
		return err
	}

	if err := deployAnomalyDetection(ctx, &a, anomalyTopic, opt); err != nil {
		return err
	}

	return deployAttribution(ctx, &a, opt)
}

func deployBudgets(ctx *pulumi.Context, a *Args, topic *sns.Topic, opt pulumi.ResourceOption) error {
	notifications := func() budgets.BudgetNotificationArray {
		n := func(kind string, threshold float64) budgets.BudgetNotificationInput {
			return budgets.BudgetNotificationArgs{
				ComparisonOperator:     pulumi.String("GREATER_THAN"),
				NotificationType:       pulumi.String(kind),
				Threshold:              pulumi.Float64(threshold),
				ThresholdType:          pulumi.String("PERCENTAGE"),
				SubscriberSnsTopicArns: pulumi.StringArray{topic.Arn},
			}
		}

		return budgets.BudgetNotificationArray{
			n("FORECASTED", 100),
			n("ACTUAL", 80),
			n("ACTUAL", 100),
		}
	}

	create := func(resource, name string, amount int, filter budgets.BudgetCostFilterArrayInput) error {
		args := &budgets.BudgetArgs{
			AccountId:     pulumi.String(a.PayerAccountID),
			Name:          pulumi.String("cost-monthly-" + name),
			BudgetType:    pulumi.String("COST"),
			TimeUnit:      pulumi.String("MONTHLY"),
			LimitAmount:   pulumi.String(strconv.Itoa(amount)),
			LimitUnit:     pulumi.String("USD"),
			Notifications: notifications(),
		}
		if filter != nil {
			args.CostFilters = filter
		}

		if _, err := budgets.NewBudget(ctx, resource, args, opt); err != nil {
			return fmt.Errorf("create budget %s: %w", name, err)
		}

		return nil
	}

	if err := create("cost-budget-total", "total", a.Spec.TotalMonthlyUSD, nil); err != nil {
		return err
	}

	for _, acct := range a.Spec.Accounts {
		if err := create("cost-budget-"+acct.Name, acct.Name, acct.MonthlyUSD, budgets.BudgetCostFilterArray{
			budgets.BudgetCostFilterArgs{
				Name:   pulumi.String("LinkedAccount"),
				Values: pulumi.StringArray{pulumi.String(acct.ID)},
			},
		}); err != nil {
			return err
		}
	}

	return nil
}

func deployAnomalyDetection(ctx *pulumi.Context, a *Args, topic *sns.Topic, opt pulumi.ResourceOption) error {
	// The AWS-created SERVICE monitor is imported on the first apply, kept
	// (never deleted with the stack) and its inputs mirror what AWS holds, so
	// the import is a no-op diff.
	def := a.Spec.DefaultMonitor

	defaultMonitor, err := costexplorer.NewAnomalyMonitor(ctx, "cost-anomaly-monitor-services", &costexplorer.AnomalyMonitorArgs{
		Name:             pulumi.String(def.Name),
		MonitorType:      pulumi.String("DIMENSIONAL"),
		MonitorDimension: pulumi.String("SERVICE"),
	}, opt, pulumi.Import(pulumi.ID(def.ARN)), pulumi.Protect(true), pulumi.RetainOnDelete(true))
	if err != nil {
		return fmt.Errorf("adopt default services monitor: %w", err)
	}

	monitorARNs := pulumi.StringArray{defaultMonitor.Arn}

	if a.Spec.PerAccountMonitors {
		for _, acct := range a.Spec.Accounts {
			spec, err := json.Marshal(newAccountMonitorSpec(acct.ID))
			if err != nil {
				return fmt.Errorf("marshal monitor specification for %s: %w", acct.Name, err)
			}

			m, err := costexplorer.NewAnomalyMonitor(ctx, "cost-anomaly-monitor-"+acct.Name, &costexplorer.AnomalyMonitorArgs{
				Name:                 pulumi.String("account-" + acct.Name),
				MonitorType:          pulumi.String("CUSTOM"),
				MonitorSpecification: pulumi.String(string(spec)),
			}, opt)
			if err != nil {
				return fmt.Errorf("create monitor %s: %w", acct.Name, err)
			}

			monitorARNs = append(monitorARNs, m.Arn)
		}
	}

	// IMMEDIATE is the only frequency an SNS subscriber accepts.
	_, err = costexplorer.NewAnomalySubscription(ctx, "cost-anomaly-subscription", &costexplorer.AnomalySubscriptionArgs{
		AccountId:       pulumi.String(a.PayerAccountID),
		Name:            pulumi.String("cost-anomalies-alert-ingress"),
		Frequency:       pulumi.String("IMMEDIATE"),
		MonitorArnLists: monitorARNs,
		Subscribers: costexplorer.AnomalySubscriptionSubscriberArray{
			costexplorer.AnomalySubscriptionSubscriberArgs{
				Type:    pulumi.String("SNS"),
				Address: topic.Arn,
			},
		},
		ThresholdExpression: costexplorer.AnomalySubscriptionThresholdExpressionArgs{
			Dimension: costexplorer.AnomalySubscriptionThresholdExpressionDimensionArgs{
				Key:          pulumi.String("ANOMALY_TOTAL_IMPACT_ABSOLUTE"),
				MatchOptions: pulumi.StringArray{pulumi.String("GREATER_THAN_OR_EQUAL")},
				Values:       pulumi.StringArray{pulumi.String(strconv.Itoa(a.Spec.AnomalyThresholdUSD))},
			},
		},
	}, opt)
	if err != nil {
		return fmt.Errorf("create anomaly subscription: %w", err)
	}

	return nil
}

// topicPolicy returns a policy letting one AWS service principal publish to one
// topic, with optional conditions.
func topicPolicy(sid, service, topicARN string, condition map[string]any) string {
	st := map[string]any{
		"Sid":       sid,
		"Effect":    "Allow",
		"Principal": map[string]string{"Service": service},
		"Action":    "SNS:Publish",
		"Resource":  topicARN,
	}
	if condition != nil {
		st["Condition"] = condition
	}

	b, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{st}})
	if err != nil {
		panic(fmt.Sprintf("marshal cost topic policy: %v", err))
	}

	return string(b)
}

type (
	// monitorDimensions is the Dimensions member of an anomaly monitor spec.
	monitorDimensions struct {
		Key          string   `json:"Key"`
		MatchOptions []string `json:"MatchOptions"`
		Values       []string `json:"Values"`
	}

	// monitorSpec mirrors the exact JSON AWS stores for a CUSTOM anomaly
	// monitor: every member present, in this order, unused ones as null. The
	// provider compares monitorSpecification as a string, so anything else
	// (missing nulls, other key order) is a perpetual replace. Do NOT add
	// omitempty.
	monitorSpec struct {
		And            []any              `json:"And"`
		CostCategories *struct{}          `json:"CostCategories"`
		Dimensions     *monitorDimensions `json:"Dimensions"`
		Not            *struct{}          `json:"Not"`
		Or             []any              `json:"Or"`
		Tags           *struct{}          `json:"Tags"`
	}
)

func newAccountMonitorSpec(accountID string) monitorSpec {
	return monitorSpec{Dimensions: &monitorDimensions{
		Key:          "LINKED_ACCOUNT",
		MatchOptions: []string{"EQUALS"},
		Values:       []string{accountID},
	}}
}

// deployAttribution adds Compute Optimizer enrollment, the cost allocation tag
// activation and the one cost category of the account split.
func deployAttribution(ctx *pulumi.Context, a *Args, opt pulumi.ResourceOption) error {
	if a.Spec.ComputeOptimizer {
		// Management account + IncludeMemberAccounts: enrolls every member and
		// turns on Organizations trusted access for the service. The resource
		// has no Pulumi-side delete that un-enrolls safely, so it is retained
		// on destroy.
		if _, err := computeoptimizer.NewEnrollmentStatus(ctx, "compute-optimizer-enrollment", &computeoptimizer.EnrollmentStatusArgs{
			Status:                pulumi.String("Active"),
			IncludeMemberAccounts: pulumi.Bool(true),
		}, opt, pulumi.RetainOnDelete(true)); err != nil {
			return fmt.Errorf("enroll compute optimizer: %w", err)
		}
	}

	cat := a.Spec.Category
	if cat == nil {
		return nil
	}

	tags := make([]pulumi.Resource, 0, len(allocationTagKeys))

	for _, key := range allocationTagKeys {
		t, err := costexplorer.NewCostAllocationTag(ctx, "cost-allocation-tag-"+tagResourceName.Replace(key), &costexplorer.CostAllocationTagArgs{
			TagKey: pulumi.String(key),
			Status: pulumi.String("Active"),
		}, opt)
		if err != nil {
			return fmt.Errorf("activate cost allocation tag %s: %w", key, err)
		}

		tags = append(tags, t)
	}

	rules, err := categoryRules(a)
	if err != nil {
		return err
	}

	// The category reads the tags, so they are active first.
	if _, err := costexplorer.NewCostCategory(ctx, "cost-category-"+cat.Name, &costexplorer.CostCategoryArgs{
		Name:         pulumi.String(cat.Name),
		RuleVersion:  pulumi.String("CostCategoryExpression.v1"),
		DefaultValue: pulumi.String(cat.DefaultValue),
		Rules:        rules,
	}, opt, pulumi.DependsOn(tags)); err != nil {
		return fmt.Errorf("create cost category %s: %w", cat.Name, err)
	}

	return nil
}

// categoryRules builds the ordered rules of the account split. A rule is a Cost
// Category expression: every one but the first two is "in the account AND ...".
func categoryRules(a *Args) (costexplorer.CostCategoryRuleArray, error) {
	cat := a.Spec.Category

	accountID := a.accountID(cat.Account)
	if accountID == "" {
		return nil, fmt.Errorf("cost category account %q is not in the accounts", cat.Account)
	}

	inAccount := func() costexplorer.CostCategoryRuleRuleAndInput {
		return costexplorer.CostCategoryRuleRuleAndArgs{
			Dimension: costexplorer.CostCategoryRuleRuleAndDimensionArgs{
				Key:          pulumi.String(dimLinkedAccount),
				MatchOptions: pulumi.StringArray{pulumi.String(matchEquals)},
				Values:       pulumi.StringArray{pulumi.String(accountID)},
			},
		}
	}

	// Every rule is a plain AND; the account clause is first.
	and := func(clauses ...costexplorer.CostCategoryRuleRuleAndInput) costexplorer.CostCategoryRuleRuleArgs {
		ands := costexplorer.CostCategoryRuleRuleAndArray{inAccount()}
		ands = append(ands, clauses...)

		return costexplorer.CostCategoryRuleRuleArgs{Ands: ands}
	}

	var badDims []string

	dimension := func(key, value string) costexplorer.CostCategoryRuleRuleAndInput {
		if !categoryDimensions[key] {
			badDims = append(badDims, key)
		}

		return costexplorer.CostCategoryRuleRuleAndArgs{
			Dimension: costexplorer.CostCategoryRuleRuleAndDimensionArgs{
				Key:          pulumi.String(key),
				MatchOptions: pulumi.StringArray{pulumi.String(matchEquals)},
				Values:       pulumi.StringArray{pulumi.String(value)},
			},
		}
	}

	tagEquals := func(key string, values []string) costexplorer.CostCategoryRuleRuleAndInput {
		return costexplorer.CostCategoryRuleRuleAndArgs{
			Tags: costexplorer.CostCategoryRuleRuleAndTagsArgs{
				Key:          pulumi.String(key),
				MatchOptions: pulumi.StringArray{pulumi.String(matchEquals)},
				Values:       pulumi.ToStringArray(values),
			},
		}
	}

	var rules costexplorer.CostCategoryRuleArray

	regular := func(value string, rule costexplorer.CostCategoryRuleRuleArgs) {
		rules = append(rules, costexplorer.CostCategoryRuleArgs{
			Type:  pulumi.String("REGULAR"),
			Value: pulumi.String(value),
			Rule:  rule,
		})
	}

	// 1. Tax first: it has no tag and no useful service.
	regular("tax", and(dimension(dimRecordType, "Tax")))

	// 2. A Karpenter / Auto Mode node and its root volume, per pool.
	for _, pool := range cat.NodePools {
		regular(pool.Value, and(tagEquals(tagNodePool, []string{pool.Pool})))
	}

	// 3. Outside the account: one value. It sits BEFORE the inherited rules
	// because those cannot be scoped: AWS requires an INHERITED_VALUE rule to
	// carry neither `rule` nor `value`, so it applies to every line still
	// unmatched, and by first match that must be the split account's only.
	regular(cat.OtherValue, costexplorer.CostCategoryRuleRuleArgs{
		Not: costexplorer.CostCategoryRuleRuleNotArgs{
			Dimension: costexplorer.CostCategoryRuleRuleNotDimensionArgs{
				Key:          pulumi.String(dimLinkedAccount),
				MatchOptions: pulumi.StringArray{pulumi.String(matchEquals)},
				Values:       pulumi.StringArray{pulumi.String(accountID)},
			},
		},
	})

	// 4 and 5. The tag's own value is the category value. Only type and
	// inheritedValue: `rule` and `value` must be null. Where the tag is absent
	// AWS documents nothing; the rule is assumed to not match, so the line
	// falls through to the service rules below.
	for _, key := range []string{tagPVCNamespace, tagACKNamespace} {
		rules = append(rules, costexplorer.CostCategoryRuleArgs{
			Type: pulumi.String("INHERITED_VALUE"),
			InheritedValue: costexplorer.CostCategoryRuleInheritedValueArgs{
				DimensionName: pulumi.String("TAG"),
				DimensionKey:  pulumi.String(key),
			},
		})
	}

	// 6. What no tag claims, by service.
	for _, s := range cat.Services {
		regular(s.Value, and(dimension(dimServiceCode, s.Service)))
	}

	if len(badDims) > 0 {
		return nil, fmt.Errorf("cost category uses dimensions AWS does not accept: %v", badDims)
	}

	return rules, nil
}
