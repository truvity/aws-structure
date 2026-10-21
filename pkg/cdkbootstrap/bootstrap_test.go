package cdkbootstrap_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/truvity/aws-structure/pkg/cdkbootstrap"
)

// policyARN spells an AWS managed policy's ARN; the partition is an input, as
// in the code under test.
func policyARN(partition, name string) string {
	return fmt.Sprintf("arn:%s:iam::aws:policy/%s", partition, name)
}

func good() cdkbootstrap.Bootstrap {
	return cdkbootstrap.Bootstrap{
		Qualifier:      "app",
		DeployBoundary: "pb@tech-deploy",
		Accounts:       []string{"dev"},
		Regions:        []string{"eu-central-1"},
	}
}

func TestBootstrapValidate(t *testing.T) {
	account := strings.Repeat("1", 12)

	if err := good().Validate(); err != nil {
		t.Fatalf("a valid bootstrap is refused: %v", err)
	}

	for name, tc := range map[string]struct {
		edit func(*cdkbootstrap.Bootstrap)
		want string
	}{
		"empty qualifier":        {func(b *cdkbootstrap.Bootstrap) { b.Qualifier = "" }, "qualifier"},
		"upper case":             {func(b *cdkbootstrap.Bootstrap) { b.Qualifier = "App" }, "qualifier"},
		"too long":               {func(b *cdkbootstrap.Bootstrap) { b.Qualifier = "abcdefghijk" }, "qualifier"},
		"dash":                   {func(b *cdkbootstrap.Bootstrap) { b.Qualifier = "a-b" }, "qualifier"},
		"ten is fine, eleven no": {func(b *cdkbootstrap.Bootstrap) { b.Qualifier = strings.Repeat("a", 11) }, "qualifier"},
		"no boundary":            {func(b *cdkbootstrap.Bootstrap) { b.DeployBoundary = "" }, "DeployBoundary"},
		"boundary with slash":    {func(b *cdkbootstrap.Bootstrap) { b.DeployBoundary = "a/b" }, "DeployBoundary"},
		"no accounts":            {func(b *cdkbootstrap.Bootstrap) { b.Accounts = nil }, "Accounts is empty"},
		"no regions":             {func(b *cdkbootstrap.Bootstrap) { b.Regions = nil }, "Regions is empty"},
		"bad region":             {func(b *cdkbootstrap.Bootstrap) { b.Regions = []string{"europe"} }, "malformed"},
		"repeated account":       {func(b *cdkbootstrap.Bootstrap) { b.Accounts = []string{"dev", "dev"} }, "twice"},
		"empty account":          {func(b *cdkbootstrap.Bootstrap) { b.Accounts = []string{""} }, "empty entry"},
		"bad trusted account":    {func(b *cdkbootstrap.Bootstrap) { b.TrustedAccounts = []string{"123"} }, "malformed"},
		"policy is a name":       {func(b *cdkbootstrap.Bootstrap) { b.ExecutionPolicies = []string{"AdministratorAccess"} }, "not a policy ARN"},
		"policy with comma":      {func(b *cdkbootstrap.Bootstrap) { b.ExecutionPolicies = []string{"arn:p:iam::aws:policy/a,b"} }, "not a policy ARN"},
		"repeated policy":        {func(b *cdkbootstrap.Bootstrap) { b.ExecutionPolicies = []string{"arn:p:x", "arn:p:x"} }, "twice"},
	} {
		t.Run(name, func(t *testing.T) {
			b := good()
			tc.edit(&b)

			err := b.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Validate = %v, want an error containing %q", err, tc.want)
			}
		})
	}

	b := good()
	b.Qualifier = strings.Repeat("a", 10)
	b.TrustedAccounts = []string{account}
	b.ExecutionPolicies = []string{policyARN("aws-cn", "PowerUserAccess")}

	if err := b.Validate(); err != nil {
		t.Errorf("a ten-character qualifier with trusted accounts and policies is refused: %v", err)
	}
}

func TestValidateRefusesTwoBootstrapsOfOneQualifierInOnePlace(t *testing.T) {
	a, b := good(), good()
	b.DeployBoundary = "pb@tech-other"

	err := cdkbootstrap.Validate([]cdkbootstrap.Bootstrap{a, b})
	if err == nil || !strings.Contains(err.Error(), "both bootstrap qualifier") {
		t.Fatalf("Validate = %v", err)
	}

	// The same qualifier in another region, or another qualifier in the same
	// place, is two stacks.
	b.Regions = []string{"eu-west-1"}

	c := good()
	c.Qualifier = "other"

	if err := cdkbootstrap.Validate([]cdkbootstrap.Bootstrap{a, b, c}); err != nil {
		t.Errorf("Validate = %v", err)
	}
}

func TestParameters(t *testing.T) {
	b := good()

	got := b.Parameters("aws")
	want := map[string]string{
		"Qualifier":                       "app",
		"InputPermissionsBoundary":        "pb@tech-deploy",
		"CloudFormationExecutionPolicies": policyARN("aws", "AdministratorAccess"),
		"TrustedAccounts":                 "",
	}

	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}

	if len(got) != len(want) {
		t.Errorf("parameters = %v", got)
	}

	b.ExecutionPolicies = []string{policyARN("aws", "A"), policyARN("aws", "B")}
	b.TrustedAccounts = []string{strings.Repeat("2", 12), strings.Repeat("3", 12)}

	got = b.Parameters("aws")
	if got["CloudFormationExecutionPolicies"] != policyARN("aws", "A")+","+policyARN("aws", "B") ||
		got["TrustedAccounts"] != strings.Repeat("2", 12)+","+strings.Repeat("3", 12) {
		t.Errorf("parameters = %v", got)
	}

	if b.StackName() != "CDKToolkit-app" {
		t.Errorf("StackName = %q", b.StackName())
	}
}

// Every parameter the stack is given is one the template declares, so a
// renamed parameter in a CDK release fails here, not at the apply.
func TestParametersAreDeclaredByTheTemplate(t *testing.T) {
	declared := render(t)["Parameters"].(map[string]any)
	b := good()

	for k := range b.Parameters("aws") {
		if _, ok := declared[k]; !ok {
			t.Errorf("the template does not declare parameter %s", k)
		}
	}
}
