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
