package fleet

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	awsorg "github.com/truvity/aws-structure/pkg/engine/org"
	"github.com/truvity/aws-structure/pkg/registry"
)

// UnitsArgs configures DeployUnits.
type UnitsArgs struct {
	// Profile and Region are the management account's, for the one provider
	// "root-org-provider" the units are created through. Required.
	Profile string
	Region  string
	// OUs are the names of the organizational units to create under the
	// organization root, in order. Required.
	OUs []string
	// Accounts are the member accounts, each in one of OUs (Account.OU). An
	// account in an undeclared unit is refused.
	Accounts []registry.Account
	// Names is the naming hook of every component. Nil: the engine's defaults.
	Names awsorg.NameFunc
}

// DeployUnits creates one OrganizationalUnit component per unit named
// "orgunit-<unit>" under the organization root, with the accounts that sit in
// it, and exports "account-id-<account>" for each. The organization itself is
// only looked up, never managed. Units and accounts are protected and retained
// on delete by the component.
func DeployUnits(ctx *pulumi.Context, logger *slog.Logger, a UnitsArgs) error {
	provider, err := aws.NewProvider(ctx, "root-org-provider", &aws.ProviderArgs{
		Region:  pulumi.String(a.Region),
		Profile: pulumi.String(a.Profile),
	})
	if err != nil {
		return fmt.Errorf("create org provider: %w", err)
	}

	members := make(map[string][]registry.Account, len(a.OUs))
	for _, ou := range a.OUs {
		members[ou] = nil
	}

	var undeclared []error

	for i := range a.Accounts {
		acct := &a.Accounts[i]

		if _, ok := members[acct.OU]; !ok {
			undeclared = append(undeclared, fmt.Errorf("OU not found for account %s: %s", acct.Name, acct.OU))

			continue
		}

		members[acct.OU] = append(members[acct.OU], registry.Account{Name: acct.Name, Email: acct.Email})
	}

	if err := errors.Join(undeclared...); err != nil {
		return fmt.Errorf("deploy accounts: %w", err)
	}

	rootID, err := awsorg.LookupRootID(ctx, provider)
	if err != nil {
		return fmt.Errorf("deploy OUs: %w", err)
	}

	logger.InfoContext(ctx.Context(), "found organization root", slog.String("root_ou_id", rootID))

	for _, ou := range a.OUs {
		unit, err := awsorg.New(ctx, "orgunit-"+ou, &awsorg.Args{
			Unit:           registry.OU{Name: ou},
			ParentID:       pulumi.String(rootID),
			Accounts:       members[ou],
			Provider:       provider,
			Names:          a.Names,
			LegacyTopLevel: true,
		})
		if err != nil {
			return fmt.Errorf("deploy OU %s: %w", ou, err)
		}

		for _, acct := range members[ou] {
			ctx.Export(fmt.Sprintf("account-id-%s", acct.Name), unit.Accounts[acct.Name].ID())
		}
	}

	return nil
}
