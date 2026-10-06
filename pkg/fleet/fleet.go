package fleet

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// accessRole is the role AWS creates in every account an organization makes,
// which the management account assumes.
const accessRole = "OrganizationAccountAccessRole"

// Fleet is the set of member accounts and how to reach them.
type Fleet struct {
	// Partition is the ARN partition. Required.
	Partition string
	// RootProfile is the AWS profile of the management account, which every
	// member provider assumes the access role from. Required.
	RootProfile string
	// Accounts are the member accounts' ids by name. The management account is
	// not a member. Required.
	Accounts map[string]pulumi.StringInput
	// Expected are the names Accounts must contain, exactly. Required: a set
	// that drifted from the expected one is refused rather than deployed.
	Expected []string
	// PrimaryRegion is where single-region controls live. Required; it must be
	// in Regions.
	PrimaryRegion string
	// Regions are every region multi-region controls are deployed in.
	// Required.
	Regions []string
	// BoundaryName is the name of the permissions boundary policy service roles
	// carry; it is created by the IAM controls. Required.
	BoundaryName string
	// Skip names the accounts that already carry a control through another
	// mechanism: the password policy, the auditor role, the baseline,
	// CloudTrail and GuardDuty are not deployed to them (they still get
	// their boundary policies).
	Skip map[string]bool
}

// Validate reports every problem with f at once, or returns nil.
func (f *Fleet) Validate() error {
	var errs []error

	for name, v := range map[string]string{
		"Partition": f.Partition, "RootProfile": f.RootProfile, "PrimaryRegion": f.PrimaryRegion,
		"BoundaryName": f.BoundaryName,
	} {
		if v == "" {
			errs = append(errs, fmt.Errorf("fleet: %s is empty", name))
		}
	}

	if !slices.Contains(f.Regions, f.PrimaryRegion) {
		errs = append(errs, fmt.Errorf("fleet: Regions %v does not contain PrimaryRegion %q", f.Regions, f.PrimaryRegion))
	}

	expected := make(map[string]bool, len(f.Expected))

	var missing, extra []string

	for _, name := range f.Expected {
		expected[name] = true

		if _, ok := f.Accounts[name]; !ok {
			missing = append(missing, name)
		}
	}

	for name := range f.Accounts {
		if !expected[name] {
			extra = append(extra, name)
		}
	}

	if len(missing) > 0 || len(extra) > 0 {
		sort.Strings(missing)
		sort.Strings(extra)

		errs = append(errs, fmt.Errorf("fleet: accounts map mismatch: missing=%v extra=%v", missing, extra))
	}

	return errors.Join(errs...)
}

// Names returns the member account names in a deterministic order.
func (f *Fleet) Names() []string {
	names := make([]string, 0, len(f.Accounts))
	for name := range f.Accounts {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
}

// BoundaryARN is the ARN of the boundary policy in a member account.
func (f *Fleet) BoundaryARN(accountID pulumi.StringInput) pulumi.StringOutput {
	return pulumi.Sprintf("arn:%s:iam::%s:policy/%s", f.Partition, accountID, f.BoundaryName)
}

// ProviderMap holds cross-account providers keyed by account and region.
// Build one per stack and share it across the deploy functions of that stack,
// so no provider is registered twice.
type ProviderMap struct {
	providers map[string]*aws.Provider
}

func providerKey(account, region string) string { return account + ":" + region }

// Get returns the provider of the account in the region, or nil.
func (pm *ProviderMap) Get(account, region string) *aws.Provider {
	return pm.providers[providerKey(account, region)]
}

// NewProvider creates an AWS provider that assumes the organization access role
// in the account, from the management account's profile.
func (f *Fleet) NewProvider(ctx *pulumi.Context, name string, accountID pulumi.StringInput, region string) (*aws.Provider, error) {
	return aws.NewProvider(ctx, name, &aws.ProviderArgs{
		Region:  pulumi.String(region),
		Profile: pulumi.String(f.RootProfile),
		AssumeRoles: aws.ProviderAssumeRoleArray{
			&aws.ProviderAssumeRoleArgs{
				RoleArn: pulumi.Sprintf("arn:%s:iam::%s:role/%s", f.Partition, accountID, accessRole),
			},
		},
	})
}

// Providers creates one provider per account and region, named
// "<prefix>-<account>-<region>". The prefix namespaces the stack's controls
// ("baseline", "guardduty").
func (f *Fleet) Providers(ctx *pulumi.Context, prefix string, regions []string) (*ProviderMap, error) {
	if err := f.Validate(); err != nil {
		return nil, fmt.Errorf("validate accounts: %w", err)
	}

	pm := &ProviderMap{providers: make(map[string]*aws.Provider, len(f.Accounts)*len(regions))}

	for _, account := range f.Names() {
		for _, region := range regions {
			p, err := f.NewProvider(ctx, fmt.Sprintf("%s-%s-%s", prefix, account, region), f.Accounts[account], region)
			if err != nil {
				return nil, fmt.Errorf("create provider for %s/%s: %w", account, region, err)
			}

			pm.providers[providerKey(account, region)] = p
		}
	}

	return pm, nil
}

func (f *Fleet) logStart(ctx *pulumi.Context, logger *slog.Logger, control string, regions int) {
	logger.InfoContext(ctx.Context(), "deploying compliance control",
		slog.String("control", control),
		slog.Int("accounts", len(f.Accounts)),
		slog.Int("regions", regions),
	)
}

func (f *Fleet) skipped(ctx *pulumi.Context, logger *slog.Logger, account, control string) bool {
	if !f.Skip[account] {
		return false
	}

	logger.InfoContext(ctx.Context(), "skipping "+control+" (already exists elsewhere)", slog.String("account", account))

	return true
}

// RootProvider creates an AWS provider for the management account itself, in a
// region, from its profile.
func (f *Fleet) RootProvider(ctx *pulumi.Context, name, region string) (*aws.Provider, error) {
	return f.rootProvider(ctx, name, region)
}

func (f *Fleet) rootProvider(ctx *pulumi.Context, name, region string) (*aws.Provider, error) {
	return aws.NewProvider(ctx, name, &aws.ProviderArgs{
		Region:  pulumi.String(region),
		Profile: pulumi.String(f.RootProfile),
	})
}
