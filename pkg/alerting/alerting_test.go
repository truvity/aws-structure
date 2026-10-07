package alerting_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/alerting"
)

type recorded struct {
	typ, name string
	inputs    resource.PropertyMap
}

type recorder struct {
	mu   sync.Mutex
	regs []recorded
}

func (r *recorder) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	r.mu.Lock()
	r.regs = append(r.regs, recorded{args.TypeToken, args.Name, args.Inputs})
	r.mu.Unlock()

	out := args.Inputs.Copy()
	out["arn"] = resource.NewProperty("arn-of-" + args.Name)

	return args.Name + "-id", out, nil
}

func (*recorder) Call(_ pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return resource.PropertyMap{"accountId": resource.NewProperty("acct-ref")}, nil
}

func (r *recorder) names() []string {
	var out []string

	for _, g := range r.regs {
		if g.typ != "pulumi:providers:aws" && g.typ != "pulumi:pulumi:Stack" {
			out = append(out, g.name)
		}
	}

	sort.Strings(out)

	return out
}

func (r *recorder) input(name, key string) resource.PropertyValue {
	for _, g := range r.regs {
		if g.name == name {
			return g.inputs[resource.PropertyKey(key)]
		}
	}

	return resource.NewNullProperty()
}

func args() alerting.Args {
	return alerting.Args{
		Partition:     "part",
		Profile:       "prof",
		Regions:       []string{"region-a", "region-b"},
		PrimaryRegion: "region-a",
		OrgID:         "org-ref",
		TopicName:     "alerts",
		Endpoint:      "https://receiver.example.test/",
		Heartbeat:     alerting.Heartbeat{RuleName: "beat", Input: `{"source":"beat"}`},
		Chatbot: alerting.Chatbot{
			ConfigurationName: "alerts", RoleName: "chat-role", SlackTeamID: "team-ref", SlackChannelID: "chan-ref",
		},
		BoundaryName: "boundary",
	}
}

func run(t *testing.T, a alerting.Args) (*recorder, map[string]pulumi.StringOutput, error) {
	t.Helper()

	rec := &recorder{}

	var arns map[string]pulumi.StringOutput

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		var err error

		arns, err = alerting.Security(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), a)

		return err
	}, pulumi.WithMocks("proj", "stack", rec))

	return rec, arns, err
}

func TestSecurityNames(t *testing.T) {
	rec, arns, err := run(t, args())
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"alert-ingress-heartbeat-rule",
		"alert-ingress-heartbeat-target",
		"alert-ingress-subscription-region-a",
		"alert-ingress-subscription-region-b",
		"chatbot-readonly-access",
		"chatbot-slack-role",
		"security-alerts-chatbot",
		"security-alerts-policy-region-a",
		"security-alerts-policy-region-b",
		"security-alerts-region-a",
		"security-alerts-region-b",
	}

	if got := rec.names(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("names:\n got %v\nwant %v", got, want)
	}

	if len(arns) != 2 {
		t.Errorf("topic ARNs = %d, want one per region", len(arns))
	}
}

func TestTopicPolicies(t *testing.T) {
	rec, _, err := run(t, args())
	if err != nil {
		t.Fatal(err)
	}

	statements := func(name string) []map[string]any {
		var doc struct{ Statement []map[string]any }
		if err := json.Unmarshal([]byte(rec.input(name, "policy").StringValue()), &doc); err != nil {
			t.Fatal(err)
		}

		return doc.Statement
	}

	primary := statements("security-alerts-policy-region-a")
	if len(primary) != 2 || primary[1]["Sid"] != "AllowHeartbeatRulePublish" {
		t.Errorf("the primary region carries the heartbeat statement: %v", primary)
	}

	other := statements("security-alerts-policy-region-b")
	if len(other) != 1 {
		t.Errorf("other regions carry only the organization statement: %v", other)
	}

	cond, _ := other[0]["Condition"].(map[string]any)
	if got := cond["ArnLike"].(map[string]any)["aws:PrincipalArn"]; got != "arn:part:iam::*:role/eventbridge-sns-region-b" {
		t.Errorf("principal arn = %v", got)
	}

	if got := cond["StringEquals"].(map[string]any)["aws:PrincipalOrgID"]; got != "org-ref" {
		t.Errorf("org id = %v", got)
	}
}

func TestSecurityRefusals(t *testing.T) {
	a := args()
	a.Regions = []string{"region-b"}
	a.Endpoint = ""
	a.Chatbot.SlackTeamID = ""

	_, _, err := run(t, a)
	if err == nil {
		t.Fatal("invalid args accepted")
	}

	for _, frag := range []string{"does not contain PrimaryRegion", "Endpoint is empty", "Chatbot.SlackTeamID is empty"} {
		if !strings.Contains(err.Error(), frag) {
			t.Errorf("error %q lacks %q", err, frag)
		}
	}
}

func TestDeliveryPolicyIsJSON(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(alerting.DeliveryPolicy()), &v); err != nil {
		t.Fatal(err)
	}

	if v["throttlePolicy"].(map[string]any)["maxReceivesPerSecond"] != float64(2) {
		t.Errorf("throttle = %v", v["throttlePolicy"])
	}
}

func TestDeliveryPolicyWithinAWSLimits(t *testing.T) {
	var p struct {
		H map[string]any `json:"healthyRetryPolicy"`
	}
	if err := json.Unmarshal([]byte(alerting.DeliveryPolicy()), &p); err != nil {
		t.Fatal(err)
	}

	n := p.H["numRetries"].(float64)
	if n < 1 || n > 100 {
		t.Fatalf("numRetries %v outside 0-100", n)
	}

	phases := p.H["numNoDelayRetries"].(float64) + p.H["numMinDelayRetries"].(float64) + p.H["numMaxDelayRetries"].(float64)
	if phases > n {
		t.Fatalf("phase retries %v exceed numRetries %v", phases, n)
	}

	if p.H["minDelayTarget"].(float64) < 1 || p.H["maxDelayTarget"].(float64) > 3600 {
		t.Fatal("delay targets outside 1-3600s")
	}
}

// queueARN is built, not spelled: the repository holds no literal account id.
func queueARN() string {
	return "arn:part:sqs:region-c:" + strings.Repeat("3", 12) + ":alerts"
}

func TestSQSSubscriptionIsOptionalAndLeavesHTTPSAlone(t *testing.T) {
	a := args()
	a.Delivery.QueueARN = queueARN()

	rec, _, err := run(t, a)
	if err != nil {
		t.Fatal(err)
	}

	got := strings.Join(rec.names(), ",")
	for _, n := range []string{
		"alert-ingress-sqs-subscription-region-a", "alert-ingress-sqs-subscription-region-b",
		"alert-ingress-subscription-region-a", "alert-ingress-subscription-region-b",
	} {
		if !strings.Contains(got, n+",") && !strings.HasSuffix(got, n) {
			t.Errorf("missing %s in %s", n, got)
		}
	}

	for _, region := range []string{"region-a", "region-b"} {
		sub := "alert-ingress-sqs-subscription-" + region

		if v := rec.input(sub, "protocol").StringValue(); v != "sqs" {
			t.Errorf("%s protocol = %q", sub, v)
		}

		if v := rec.input(sub, "endpoint").StringValue(); v != queueARN() {
			t.Errorf("%s endpoint = %q", sub, v)
		}

		if v := rec.input(sub, "rawMessageDelivery"); !v.IsBool() || v.BoolValue() {
			t.Errorf("%s raw message delivery must be off, got %v", sub, v)
		}

		if v := rec.input("alert-ingress-subscription-"+region, "protocol").StringValue(); v != "https" {
			t.Errorf("the HTTPS subscription changed: %q", v)
		}
	}
}

func TestDisableHTTPSKeepsOnlyTheQueue(t *testing.T) {
	a := args()
	a.Endpoint = ""
	a.Delivery = alerting.Delivery{QueueARN: queueARN(), DisableHTTPS: true}

	rec, _, err := run(t, a)
	if err != nil {
		t.Fatal(err)
	}

	for _, n := range rec.names() {
		if strings.HasPrefix(n, "alert-ingress-subscription-") {
			t.Errorf("HTTPS subscription %s still created", n)
		}
	}

	if rec.input("alert-ingress-sqs-subscription-region-a", "protocol").StringValue() != "sqs" {
		t.Error("the SQS subscription is missing")
	}
}

func TestDeliveryRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		d    alerting.Delivery
		frag string
	}{
		"not an ARN":         {alerting.Delivery{QueueARN: "nope"}, "not an SQS queue ARN"},
		"a topic ARN":        {alerting.Delivery{QueueARN: "arn:part:sns:region-c:" + strings.Repeat("3", 12) + ":t"}, "not an SQS queue ARN"},
		"wrong partition":    {alerting.Delivery{QueueARN: "arn:other:sqs:region-c:" + strings.Repeat("3", 12) + ":q"}, "not in partition"},
		"https off no queue": {alerting.Delivery{DisableHTTPS: true}, "DisableHTTPS needs QueueARN"},
	} {
		a := args()
		a.Delivery = tc.d

		if err := a.Validate(); err == nil || !strings.Contains(err.Error(), tc.frag) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.frag)
		}
	}
}
