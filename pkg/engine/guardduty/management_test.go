package guardduty_test

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/engine/guardduty"
)

func managementArgs() guardduty.ManagementArgs {
	return guardduty.ManagementArgs{
		Profile:                    "mgmt",
		Regions:                    []string{"region-a", "region-b"},
		DetectorIDs:                map[string]string{"region-a": "det-a", "region-b": "det-b"},
		Partition:                  "part",
		BoundaryName:               "boundary",
		FindingPublishingFrequency: "FIFTEEN_MINUTES",
	}
}

func TestManagementAdoptsEveryRegion(t *testing.T) {
	rec := &recorder{}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		a := managementArgs()
		a.TopicARNs = map[string]pulumi.StringOutput{
			"region-a": pulumi.String("topic-a").ToStringOutput(),
			"region-b": pulumi.String("topic-b").ToStringOutput(),
		}

		return guardduty.NewManagement(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), a)
	}, pulumi.WithMocks("proj", "stack", rec))
	if err != nil {
		t.Fatal(err)
	}

	providers := map[string]bool{}

	for _, r := range rec.regs {
		if r.typ == "pulumi:providers:aws" {
			providers[r.name] = true
		}
	}

	got := by(rec.regs)

	for _, region := range []string{"region-a", "region-b"} {
		if !providers["guardduty-management-provider-"+region] {
			t.Errorf("no provider for %s; have %v", region, providers)
		}

		for _, suffix := range []string{"detector", "rule", "eventbridge-role", "eventbridge-policy", "target"} {
			if _, ok := got["guardduty-management-"+region+"-"+suffix]; !ok {
				t.Errorf("missing guardduty-management-%s-%s", region, suffix)
			}
		}

		rule := got["guardduty-management-"+region+"-rule"]
		if n := rule.inputs["name"].StringValue(); n != guardduty.ManagementRuleName(region) || n != "guardduty-findings-"+region {
			t.Errorf("rule name in %s: %q", region, n)
		}

		if d := rule.inputs["description"].StringValue(); d != guardduty.ManagementRuleDescription {
			t.Errorf("rule description in %s: %q", region, d)
		}

		if id := got["guardduty-management-"+region+"-target"].inputs["targetId"].StringValue(); id != "guardduty-management-sns" {
			t.Errorf("target id in %s: %q", region, id)
		}

		if f := got["guardduty-management-"+region+"-detector"].inputs["findingPublishingFrequency"].StringValue(); f != "FIFTEEN_MINUTES" {
			t.Errorf("frequency in %s: %q", region, f)
		}
	}
}

func TestManagementRefusals(t *testing.T) {
	a := managementArgs()
	a.Profile = ""
	a.Regions = []string{"region-a", "region-a", "region-c"}
	a.DetectorIDs["region-z"] = "det-z"
	a.TopicARNs = map[string]pulumi.StringOutput{}

	err := a.Validate()
	if err == nil {
		t.Fatal("bad args accepted")
	}

	for _, want := range []string{
		"Profile is empty", "Regions has region-a twice", "no detector id for region-c",
		"no topic ARN for region-a", "detector id for region-b, which is not in Regions",
		"detector id for region-z, which is not in Regions",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
}
