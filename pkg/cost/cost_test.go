package cost

import (
	"encoding/json"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/costexplorer"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type recorder struct {
	mu    sync.Mutex
	names map[string]string
}

func (r *recorder) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	r.mu.Lock()
	r.names[args.Name] = args.TypeToken
	r.mu.Unlock()

	out := args.Inputs.Copy()
	out["arn"] = resource.NewProperty("arn-of-" + args.Name)

	return args.Name + "-id", out, nil
}

func (*recorder) Call(_ pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return resource.PropertyMap{}, nil
}

func args() Args {
	return Args{
		Partition:      "part",
		Profile:        "prof",
		PayerAccountID: "payer-ref",
		Region:         "region-a",
		BudgetsTopic:   "budgets",
		AnomaliesTopic: "anomalies",
		Endpoint:       "https://receiver.example.test/",
		Spec: Spec{
			TotalMonthlyUSD: 1000,
			Accounts: []Account{
				{Name: "main", ID: "111111111111", MonthlyUSD: 600},
				{Name: "side", ID: "222222222222", MonthlyUSD: 100},
			},
			AnomalyThresholdUSD: 50,
			DefaultMonitor:      Monitor{Name: "default-monitor", ARN: "arn:part:ce::111111111111:anomalymonitor/00000000-0000-0000-0000-000000000000"},
			PerAccountMonitors:  true,
			ComputeOptimizer:    true,
			Category: &Category{
				Name: "split", Account: "main", OtherValue: "other", DefaultValue: "rest",
				NodePools: []NodePool{{Pool: "general", Value: "nodes-general"}},
				Services:  []ServiceValue{{Service: "SvcCode", Value: "svc"}},
			},
		},
	}
}

func TestDeployNames(t *testing.T) {
	rec := &recorder{names: map[string]string{}}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		return Deploy(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), args())
	}, pulumi.WithMocks("proj", "stack", rec))
	if err != nil {
		t.Fatal(err)
	}

	var got []string

	for n, typ := range rec.names {
		if typ != "pulumi:providers:aws" && typ != "pulumi:pulumi:Stack" {
			got = append(got, n)
		}
	}

	sort.Strings(got)

	want := []string{
		"compute-optimizer-enrollment",
		"cost-allocation-tag-eks-kubernetes-node-pool-name",
		"cost-allocation-tag-kubernetes-io-created-for-pvc-namespace",
		"cost-allocation-tag-services-k8s-aws-namespace",
		"cost-anomalies-alert-ingress",
		"cost-anomalies-topic",
		"cost-anomalies-topic-policy",
		"cost-anomaly-monitor-main",
		"cost-anomaly-monitor-services",
		"cost-anomaly-monitor-side",
		"cost-anomaly-subscription",
		"cost-budget-main",
		"cost-budget-side",
		"cost-budget-total",
		"cost-budgets-alert-ingress",
		"cost-budgets-topic",
		"cost-budgets-topic-policy",
		"cost-category-split",
	}

	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("logical names:\n got %v\nwant %v", got, want)
	}
}

func TestRefusals(t *testing.T) {
	a := args()
	a.Endpoint = ""
	a.Spec.Accounts = nil
	a.Spec.DefaultMonitor.ARN = ""

	err := a.Validate()
	if err == nil {
		t.Fatal("invalid args accepted")
	}

	for _, frag := range []string{"Endpoint is empty", "Accounts is empty", "DefaultMonitor.ARN is empty"} {
		if !strings.Contains(err.Error(), frag) {
			t.Errorf("error %q lacks %q", err, frag)
		}
	}

	b := args()
	b.Spec.Category.Account = "missing"

	if err := b.Validate(); err == nil || !strings.Contains(err.Error(), "not in Accounts") {
		t.Errorf("a category over an unknown account must be refused: %v", err)
	}
}

func TestAccountMonitorSpecMatchesAWSNormalised(t *testing.T) {
	got, err := json.Marshal(newAccountMonitorSpec("acct-ref"))
	if err != nil {
		t.Fatal(err)
	}

	want := `{"And":null,"CostCategories":null,` +
		`"Dimensions":{"Key":"LINKED_ACCOUNT","MatchOptions":["EQUALS"],"Values":["acct-ref"]},` +
		`"Not":null,"Or":null,"Tags":null}`
	if string(got) != want {
		t.Fatalf("spec drifted from AWS-normalised form\n got: %s\nwant: %s", got, want)
	}
}

func TestCategoryRulesUseAcceptedDimensions(t *testing.T) {
	a := args()

	if _, err := categoryRules(&a); err != nil {
		t.Fatalf("the rules: %v", err)
	}

	for _, d := range []string{"SERVICE", "TAG", "INSTANCE_TYPE"} {
		if categoryDimensions[d] {
			t.Errorf("%s is not an allowed cost category dimension", d)
		}
	}

	for _, d := range []string{dimLinkedAccount, dimRecordType, dimServiceCode} {
		if !categoryDimensions[d] {
			t.Errorf("%s is used and must be allowed", d)
		}
	}
}

func TestInheritedRulesCarryNoRuleOrValueAndFollowTheOtherAccountRule(t *testing.T) {
	a := args()

	rules, err := categoryRules(&a)
	if err != nil {
		t.Fatal(err)
	}

	otherAt, firstInherited, inherited := -1, -1, 0

	for i, r := range rules {
		rule, ok := r.(costexplorer.CostCategoryRuleArgs)
		if !ok {
			t.Fatalf("rule %d is %T", i, r)
		}

		if v, _ := rule.Value.(pulumi.String); string(v) == a.Spec.Category.OtherValue {
			otherAt = i
		}

		if typ, _ := rule.Type.(pulumi.String); string(typ) != "INHERITED_VALUE" {
			continue
		}

		inherited++

		if firstInherited < 0 {
			firstInherited = i
		}

		// AWS: "Rule and Value attributes must be null".
		if rule.Rule != nil || rule.Value != nil || rule.InheritedValue == nil {
			t.Errorf("inherited rule %d: rule=%v value=%v inheritedValue=%v", i, rule.Rule, rule.Value, rule.InheritedValue)
		}
	}

	if inherited != 2 {
		t.Fatalf("%d inherited rules, want 2", inherited)
	}

	if otherAt < 0 || otherAt > firstInherited {
		t.Errorf("the other-account rule is at %d, the first inherited rule at %d: it must come first", otherAt, firstInherited)
	}
}

func TestSpecValidate(t *testing.T) {
	a := args()
	if err := a.Spec.Validate("part"); err != nil {
		t.Fatalf("valid spec refused: %v", err)
	}

	for name, tc := range map[string]struct {
		mutate func(*Spec)
		want   string
	}{
		"bad account id":   {func(s *Spec) { s.Accounts[0].ID = "12" }, "12-digit"},
		"repeated account": {func(s *Spec) { s.Accounts[1] = s.Accounts[0] }, "repeats"},
		"bad name":         {func(s *Spec) { s.Accounts[0].Name = "Main Acct" }, "must match"},
		"zero threshold":   {func(s *Spec) { s.AnomalyThresholdUSD = 0 }, "AnomalyThresholdUSD"},
		"monitor wrong part": {func(s *Spec) {
			s.DefaultMonitor.ARN = "arn:other:ce::111111111111:anomalymonitor/00000000-0000-0000-0000-000000000000"
		}, "partition"},
		"same values":          {func(s *Spec) { s.Category.OtherValue = s.Category.DefaultValue }, "must differ"},
		"slash in value":       {func(s *Spec) { s.Category.NodePools[0].Value = "nodes/ci" }, "AWS's pattern"},
		"service display name": {func(s *Spec) { s.Category.Services[0].Service = "Amazon EC2" }, "not a service code"},
		"duplicate pool":       {func(s *Spec) { s.Category.NodePools = append(s.Category.NodePools, s.Category.NodePools[0]) }, "unique node pool"},
	} {
		a := args()
		tc.mutate(&a.Spec)

		if err := a.Spec.Validate("part"); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want containing %q", name, err, tc.want)
		}
	}

	if NodePoolValue("ci") != "nodes-ci" {
		t.Error("NodePoolValue")
	}
}
