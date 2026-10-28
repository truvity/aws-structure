package iamtrust_test

import (
	"strings"
	"testing"

	"github.com/truvity/aws-structure/pkg/iamtrust"
)

func TestPolicy(t *testing.T) {
	got, err := iamtrust.Policy("", "000000000001", "issuer.example.org", "aws:000000000001:role")
	if err != nil {
		t.Fatal(err)
	}

	want := `{"Statement":[{"Action":["sts:AssumeRoleWithWebIdentity","sts:TagSession","sts:SetSourceIdentity"],` +
		`"Condition":{"StringEquals":{"issuer.example.org:aud":"aws:000000000001:role"}},"Effect":"Allow",` +
		`"Principal":{"Federated":"arn:aws:iam::000000000001:oidc-provider/issuer.example.org"}}],"Version":"2012-10-17"}`
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestPolicyPartitionAndRefusals(t *testing.T) {
	got, err := iamtrust.Policy("aws-cn", "000000000001", "h", "a")
	if err != nil {
		t.Fatal(err)
	}

	if want := "arn:aws-cn:iam::000000000001:oidc-provider/h"; !strings.Contains(got, want) {
		t.Fatalf("%s lacks %s", got, want)
	}

	if _, err := iamtrust.Policy("", "", "h", "a"); err == nil {
		t.Fatal("empty account accepted")
	}
}
