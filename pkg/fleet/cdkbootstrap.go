package fleet

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/cdkbootstrap"
	enginecdk "github.com/truvity/aws-structure/pkg/engine/cdkbootstrap"
)

// CDKBootstrapsArgs configures CDKBootstraps.
type CDKBootstrapsArgs struct {
	// Bootstraps are the CDK bootstraps, one per app (qualifier). Each names
	// member accounts of the fleet and the regions to bootstrap them in.
	Bootstraps []cdkbootstrap.Bootstrap
	// Names is the naming hook of every component. Nil: the engine's defaults.
	Names enginecdk.NameFunc
}

// CDKBootstraps deploys the CDK bootstraps: one CDKBootstrap component per
// bootstrap, account and region named "cdkbootstrap-<qualifier>-<account>-<region>",
// through one provider per account and region named "cdkbootstrap-<account>-<region>"
// (shared by the qualifiers that use the place).
//
// IAM must have run on f first: the stack creates its roles under the
// DeployBoundary policy, which the account's AccountIAM creates, so each stack
// depends on that component. An account that is not a member of the fleet, or
// that IAM registered nothing for, is refused.
func (f *Fleet) CDKBootstraps(ctx *pulumi.Context, logger *slog.Logger, a CDKBootstrapsArgs) error {
	if err := f.Validate(); err != nil {
		return err
	}

	if err := cdkbootstrap.Validate(a.Bootstraps); err != nil {
		return fmt.Errorf("cdk bootstraps: %w", err)
	}

	var errs []error

	for _, account := range cdkbootstrap.Accounts(a.Bootstraps) {
		if _, ok := f.Accounts[account]; !ok {
			errs = append(errs, fmt.Errorf("cdk bootstraps: %q is not a member account of the fleet", account))
		} else if f.IAMComponent(account) == nil {
			errs = append(errs, fmt.Errorf("cdk bootstraps: %q has no AccountIAM: run IAM before CDKBootstraps", account))
		}
	}

	if err := errors.Join(errs...); err != nil {
		return err
	}

	providers := map[[2]string]*aws.Provider{}

	for i := range a.Bootstraps {
		b := a.Bootstraps[i]

		for _, account := range b.Accounts {
			for _, region := range b.Regions {
				key := [2]string{account, region}

				p := providers[key]
				if p == nil {
					var err error

					p, err = f.NewProvider(ctx, fmt.Sprintf("cdkbootstrap-%s-%s", account, region), f.Accounts[account], region)
					if err != nil {
						return fmt.Errorf("create provider for %s/%s: %w", account, region, err)
					}

					providers[key] = p
				}

				if _, err := enginecdk.New(ctx, fmt.Sprintf("cdkbootstrap-%s-%s-%s", b.Qualifier, account, region), &enginecdk.Args{
					Account:   account,
					Region:    region,
					Partition: f.Partition,
					Bootstrap: b,
					Provider:  p,
					DependsOn: []pulumi.Resource{f.IAMComponent(account)},
					Names:     a.Names,
				}); err != nil {
					return fmt.Errorf("deploy CDK bootstrap %s to %s/%s: %w", b.Qualifier, account, region, err)
				}

				logger.InfoContext(ctx.Context(), "CDK bootstrap deployed",
					slog.String("qualifier", b.Qualifier), slog.String("account", account), slog.String("region", region))
			}
		}
	}

	return nil
}
