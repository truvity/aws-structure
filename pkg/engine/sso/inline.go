package sso

import (
	"fmt"
	"slices"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/ssoadmin"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// DeployInlinePolicies attaches an inline policy to deployed permission sets:
// policies maps a key of sets to the policy JSON. Each is a
// ssoadmin.PermissionSetInlinePolicy named "ps-<key>-inline-policy", a child of
// the set's PermissionSet component that depends on the set. DeploySets does
// not carry an inline policy, so a caller that wants one (OrgAdminInlinePolicy,
// a Deny) deploys it here.
//
// A key with no deployed set is an error. A set not in policies keeps none.
func DeployInlinePolicies(
	ctx *pulumi.Context,
	instanceARN pulumi.StringInput,
	sets map[string]*PermissionSet,
	policies map[string]string,
	provider pulumi.ProviderResource,
) error {
	keys := make([]string, 0, len(policies))
	for key := range policies {
		keys = append(keys, key)
	}

	slices.Sort(keys)

	for _, key := range keys {
		ps, ok := sets[key]
		if !ok {
			return fmt.Errorf("inline policy for permission set %q: the set is not deployed", key)
		}

		if _, err := ssoadmin.NewPermissionSetInlinePolicy(ctx, "ps-"+key+"-inline-policy", &ssoadmin.PermissionSetInlinePolicyArgs{
			InstanceArn:      instanceARN,
			PermissionSetArn: ps.Arn,
			InlinePolicy:     pulumi.String(policies[key]),
		}, pulumi.Parent(ps), pulumi.Provider(provider), pulumi.DependsOn([]pulumi.Resource{ps.Set})); err != nil {
			return fmt.Errorf("attach inline policy to permission set %s: %w", key, err)
		}
	}

	return nil
}
