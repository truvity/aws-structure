package sso

import (
	"errors"
	"fmt"
	"slices"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/identitystore"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/ssoadmin"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// LookupGroupIDs reads the Identity Store id of each group by display name,
// for groups a directory sync fills and this package therefore never creates.
// It returns a map from display name to id. Repeated names are read once. A
// group that cannot be read is reported with every other one that cannot, and
// nothing is returned.
func LookupGroupIDs(
	ctx *pulumi.Context, identityStoreID string, displayNames []string, provider pulumi.ProviderResource,
) (map[string]pulumi.StringOutput, error) {
	if identityStoreID == "" {
		return nil, errors.New("sso: identity store id is empty")
	}

	if provider == nil {
		return nil, errors.New("sso: provider is nil")
	}

	names := slices.Clone(displayNames)
	slices.Sort(names)
	names = slices.Compact(names)

	out := make(map[string]pulumi.StringOutput, len(names))

	var errs []error

	for _, name := range names {
		if name == "" {
			errs = append(errs, errors.New("sso: a group display name is empty"))

			continue
		}

		g, err := identitystore.LookupGroup(ctx, &identitystore.LookupGroupArgs{
			IdentityStoreId: identityStoreID,
			AlternateIdentifier: &identitystore.GetGroupAlternateIdentifier{
				UniqueAttribute: &identitystore.GetGroupAlternateIdentifierUniqueAttribute{
					AttributePath:  "DisplayName",
					AttributeValue: name,
				},
			},
		}, pulumi.Provider(provider))
		if err != nil {
			errs = append(errs, fmt.Errorf("lookup group %q: %w", name, err))

			continue
		}

		out[name] = pulumi.String(g.GroupId).ToStringOutput()
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	return out, nil
}

// LookupPermissionSetARN reads the ARN of an existing permission set by name,
// for a set that was made by hand and that this package does not manage.
func LookupPermissionSetARN(ctx *pulumi.Context, instanceARN, name string, provider pulumi.ProviderResource) (string, error) {
	var errs []error

	if instanceARN == "" {
		errs = append(errs, errors.New("sso: instance ARN is empty"))
	}

	if name == "" {
		errs = append(errs, errors.New("sso: permission set name is empty"))
	}

	if provider == nil {
		errs = append(errs, errors.New("sso: provider is nil"))
	}

	if err := errors.Join(errs...); err != nil {
		return "", err
	}

	ps, err := ssoadmin.LookupPermissionSet(ctx, &ssoadmin.LookupPermissionSetArgs{
		InstanceArn: instanceARN,
		Name:        pulumi.StringRef(name),
	}, pulumi.Provider(provider))
	if err != nil {
		return "", fmt.Errorf("lookup permission set %q: %w", name, err)
	}

	return ps.Arn, nil
}
