package iam_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/engine/iam"
)

func vanta() iam.VantaSpec {
	return iam.VantaSpec{
		Partition: "part", TrustedAccountID: "vendor-ref", ExternalID: "external-ref",
		RoleName: "auditor", PolicyName: "AdditionalPermissions", BoundaryName: "boundary",
	}
}

func TestVantaAuditorRole(t *testing.T) {
	r, err := iam.VantaAuditorRole(vanta(), pulumi.String("acct-ref"))
	if err != nil {
		t.Fatal(err)
	}

	if r.Name != "auditor" || r.ExternalID != "external-ref" || r.TrustedPrincipal != "arn:part:iam::vendor-ref:root" {
		t.Errorf("role = %+v", r)
	}

	if len(r.ManagedPolicies) != 1 || r.ManagedPolicies[0] != "arn:part:iam::aws:policy/SecurityAudit" {
		t.Errorf("managed policies = %v", r.ManagedPolicies)
	}

	if !json.Valid([]byte(r.Policy.Document)) || !strings.Contains(r.Policy.Document, "identitystore:ListUsers") {
		t.Error("the additional permissions document must be valid JSON naming the identity store reads")
	}
}

func TestVantaSpecRefusals(t *testing.T) {
	v := vanta()
	v.ExternalID = ""
	v.BoundaryName = ""

	if _, err := iam.VantaAuditorRole(v, pulumi.String("acct-ref")); err == nil ||
		!strings.Contains(err.Error(), "ExternalID is empty") || !strings.Contains(err.Error(), "BoundaryName is empty") {
		t.Fatalf("empty fields not refused together: %v", err)
	}
}
