package fleet

import (
	"fmt"
	"log/slog"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/engine/iam"
)

// StandaloneAuditorsArgs configures StandaloneAuditors.
type StandaloneAuditorsArgs struct {
	// Accounts are the accounts whose auditor role is deployed on its own,
	// because the AccountIAM that carries their boundaries carries no auditor:
	// the management account (its AccountIAM holds the management boundaries
	// only), or a member that IAM skipped.
	Accounts []string
	// Management is the name of the management account. An entry of Accounts
	// equal to it is reached through the root profile itself, not the access
	// role.
	Management string
	// AccountIDs are the ids of the accounts outside Fleet.Accounts that
	// Accounts may name, by name; the management account's id is required here.
	// A member of the fleet needs no entry.
	AccountIDs map[string]string
	// Auditor builds the role, per account id. Required.
	Auditor func(accountID pulumi.StringInput) (*iam.AuditorRole, error)
	// Names is the naming hook of the components. Nil: the engine's defaults.
	Names iam.NameFunc
}

// StandaloneAuditors deploys the auditor role in each of a.Accounts as an
// AccountIAM named "vanta-<account>", through its own provider
// "vanta-provider-<account>" in the primary region.
//
// A member account the fleet already gives an auditor (it is in Accounts and
// not in Skip) is refused: the role name is fixed, so a second role would
// collide. So is an account that is neither a member nor in a.AccountIDs.
func (f *Fleet) StandaloneAuditors(ctx *pulumi.Context, logger *slog.Logger, a StandaloneAuditorsArgs) error {
	if a.Auditor == nil {
		return fmt.Errorf("standalone auditors: Auditor is unset")
	}

	for _, account := range a.Accounts {
		provider, accountID, err := f.standaloneProvider(ctx, a, account)
		if err != nil {
			return err
		}

		role, err := a.Auditor(accountID)
		if err != nil {
			return fmt.Errorf("auditor role (%s): %w", account, err)
		}

		if _, err := iam.New(ctx, "vanta-"+account, &iam.Args{
			Account:     account,
			AuditorRole: role,
			Provider:    provider,
			Names:       a.Names,
		}); err != nil {
			return fmt.Errorf("deploy auditor role (%s): %w", account, err)
		}

		logger.InfoContext(ctx.Context(), "auditor role deployed", slog.String("account", account))
	}

	return nil
}

func (f *Fleet) standaloneProvider(
	ctx *pulumi.Context, a StandaloneAuditorsArgs, account string,
) (pulumi.ProviderResource, pulumi.StringInput, error) {
	name := "vanta-provider-" + account

	if account == a.Management {
		id, ok := a.AccountIDs[account]
		if !ok {
			return nil, nil, fmt.Errorf("standalone auditor %s: no account id", account)
		}

		p, err := f.rootProvider(ctx, name, f.PrimaryRegion)
		if err != nil {
			return nil, nil, fmt.Errorf("create provider for %s: %w", account, err)
		}

		return p, pulumi.String(id), nil
	}

	var accountID pulumi.StringInput

	if id, member := f.Accounts[account]; member {
		if !f.Skip[account] {
			return nil, nil, fmt.Errorf("standalone auditor %s: the fleet already deploys its auditor role", account)
		}

		accountID = id
	} else {
		id, ok := a.AccountIDs[account]
		if !ok {
			return nil, nil, fmt.Errorf("standalone auditor %s: neither a fleet account nor in AccountIDs", account)
		}

		accountID = pulumi.String(id)
	}

	p, err := f.NewProvider(ctx, name, accountID, f.PrimaryRegion)
	if err != nil {
		return nil, nil, fmt.Errorf("create provider for %s: %w", account, err)
	}

	return p, accountID, nil
}
