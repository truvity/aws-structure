package fleet

import (
	"fmt"
	"log/slog"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/engine/baseline"
	"github.com/truvity/aws-structure/pkg/engine/guardduty"
	"github.com/truvity/aws-structure/pkg/engine/iam"
	awstrail "github.com/truvity/aws-structure/pkg/engine/trail"
	"github.com/truvity/aws-structure/pkg/registry"
)

// BaselineArgs configures Baseline.
type BaselineArgs struct {
	// Names is the naming hook of every component. Nil: the engine's defaults.
	Names baseline.NameFunc
}

// Baseline deploys one AccountBaseline per account named "baseline-<account>":
// EBS default encryption in the primary region and an Access Analyzer in every
// region. The providers are built here (one per account and region, prefix
// "baseline") even for skipped accounts, as a stack that already holds them
// expects.
func (f *Fleet) Baseline(ctx *pulumi.Context, logger *slog.Logger, a BaselineArgs) error {
	pm, err := f.Providers(ctx, "baseline", f.Regions)
	if err != nil {
		return fmt.Errorf("build baseline provider map: %w", err)
	}

	f.logStart(ctx, logger, "EBS default encryption + IAM Access Analyzer", len(f.Regions))

	for _, account := range f.Names() {
		if f.skipped(ctx, logger, account, "account baseline") {
			continue
		}

		providers := make(map[string]pulumi.ProviderResource, len(f.Regions))
		for _, region := range f.Regions {
			providers[region] = pm.Get(account, region)
		}

		if _, err := baseline.New(ctx, "baseline-"+account, &baseline.Args{
			Account: account,
			Baseline: registry.Baseline{
				EBSDefaultEncryption: true,
				Regions:              []string{f.PrimaryRegion},
				AccessAnalyzer:       true,
			},
			AnalyzerRegions: f.Regions,
			Providers:       providers,
			Names:           a.Names,
			LegacyTopLevel:  true,
		}); err != nil {
			return fmt.Errorf("deploy account baseline (%s): %w", account, err)
		}
	}

	return nil
}

// TrailArgs configures Trail. Each format takes the account id and then the
// region (the replica bucket takes them in that order too).
type TrailArgs struct {
	// ReplicaRegion is where the trail buckets are replicated to. Required.
	ReplicaRegion string
	// TrailBucket, AccessLogBucket and ReplicaBucket are the bucket names as
	// formats of (account id, region). Required.
	TrailBucket     string
	AccessLogBucket string
	ReplicaBucket   string
	// KeyAlias is the alias of the account's trail key. Required.
	KeyAlias string
	// DataEventResource is the S3 ARN whose object events the trail logs.
	// Required.
	DataEventResource string
	// ReplicationRoleName is a format of (account name). Required.
	ReplicationRoleName string
}

// Trail deploys one AccountTrail per account named "cloudtrail-<account>", from
// the primary region's provider and the replica region's.
func (f *Fleet) Trail(ctx *pulumi.Context, logger *slog.Logger, a TrailArgs) error {
	pm, err := f.Providers(ctx, "cloudtrail", []string{f.PrimaryRegion, a.ReplicaRegion})
	if err != nil {
		return fmt.Errorf("build cloudtrail provider map: %w", err)
	}

	f.logStart(ctx, logger, "CloudTrail", 1)

	region := f.PrimaryRegion

	for _, account := range f.Names() {
		if f.skipped(ctx, logger, account, "CloudTrail") {
			continue
		}

		provider := pm.Get(account, region)
		if provider == nil {
			return fmt.Errorf("missing provider for CloudTrail account=%s region=%s", account, region)
		}

		replica := pm.Get(account, a.ReplicaRegion)
		if replica == nil {
			return fmt.Errorf("missing provider for CloudTrail replica account=%s region=%s", account, a.ReplicaRegion)
		}

		id := f.Accounts[account]

		if _, err := awstrail.New(ctx, "cloudtrail-"+account, &awstrail.Args{
			Account: account,
			Buckets: awstrail.Buckets{
				Trail:     pulumi.Sprintf(a.TrailBucket, id, region),
				AccessLog: pulumi.Sprintf(a.AccessLogBucket, id, region),
				Replica:   pulumi.Sprintf(a.ReplicaBucket, id, region),
			},
			KeyAlias:          a.KeyAlias,
			KeyAdministrator:  pulumi.Sprintf("arn:%s:iam::%s:root", f.Partition, id),
			TrailARN:          pulumi.Sprintf("arn:%s:cloudtrail:%s:%s:trail/*", f.Partition, region, id),
			DataEventResource: a.DataEventResource,
			ReplicationRole: awstrail.ReplicationRole{
				Name:                fmt.Sprintf(a.ReplicationRoleName, account),
				PermissionsBoundary: f.BoundaryARN(id),
			},
			Provider:        provider,
			ReplicaProvider: replica,
			LegacyTopLevel:  true,
		}); err != nil {
			return fmt.Errorf("deploy CloudTrail to %s: %w", account, err)
		}

		logger.InfoContext(ctx.Context(), "CloudTrail deployed", slog.String("account", account))
	}

	return nil
}

// GuardDutyArgs configures GuardDuty.
type GuardDutyArgs struct {
	// TopicARNs are the alerting topics by region, from pkg/alerting. Required
	// for every region.
	TopicARNs map[string]pulumi.StringOutput
	// FindingPublishingFrequency is how often updates of a finding are
	// published (see guardduty.Args). Empty: the provider default.
	FindingPublishingFrequency string
}

// GuardDuty deploys one AccountRegionGuardDuty per account and region named
// "guardduty-<account>-<region>", from providers built with prefix "guardduty",
// publishing to the region's topic in the management account.
func (f *Fleet) GuardDuty(ctx *pulumi.Context, logger *slog.Logger, pm *ProviderMap, a GuardDutyArgs) error {
	f.logStart(ctx, logger, "GuardDuty", len(f.Regions))

	for _, account := range f.Names() {
		if f.skipped(ctx, logger, account, "GuardDuty") {
			continue
		}

		for _, region := range f.Regions {
			provider := pm.Get(account, region)
			if provider == nil {
				return fmt.Errorf("missing provider for GuardDuty account=%s region=%s", account, region)
			}

			if _, err := guardduty.New(ctx, fmt.Sprintf("guardduty-%s-%s", account, region), &guardduty.Args{
				Account:                    account,
				Region:                     region,
				SNSTopicARN:                a.TopicARNs[region],
				PermissionsBoundary:        f.BoundaryARN(f.Accounts[account]),
				Provider:                   provider,
				LegacyTopLevel:             true,
				FindingPublishingFrequency: a.FindingPublishingFrequency,
			}); err != nil {
				return fmt.Errorf("deploy GuardDuty to %s/%s: %w", account, region, err)
			}

			logger.InfoContext(ctx.Context(), "GuardDuty deployed",
				slog.String("account", account), slog.String("region", region))
		}
	}

	return nil
}

// IAMArgs configures IAM.
type IAMArgs struct {
	// RootAccount is the management account's name, which gets "iam-root" with
	// the boundaries in RootBoundaries only. Required.
	RootAccount string
	// Boundaries are the boundary policies every member account carries.
	Boundaries []registry.Boundary
	// RootBoundaries are the boundary policies the management account carries.
	RootBoundaries []registry.Boundary
	// PasswordPolicy and Auditor are deployed to every member account that is
	// not skipped; the auditor is built per account id.
	PasswordPolicy registry.PasswordPolicy
	Auditor        func(accountID pulumi.StringInput) (*iam.AuditorRole, error)
	// Names is the naming hook of every component. Nil: the engine's defaults.
	Names iam.NameFunc
}

// IAM deploys the IAM controls: "iam-root" in the management account (its
// provider "root-iam-provider" in the primary region) and one AccountIAM per
// member account named "iam-<account>".
//
// The boundary policies are created through their own providers
// ("provider-<account>", primary region): a different naming convention from
// the shared ones ("iam-<account>-<region>") used for the password policy and
// the auditor role.
func (f *Fleet) IAM(ctx *pulumi.Context, logger *slog.Logger, a IAMArgs) error {
	if err := f.Validate(); err != nil {
		return err
	}

	boundaryProviders := make(map[string]pulumi.ProviderResource, len(f.Accounts))

	for _, account := range f.Names() {
		p, err := f.NewProvider(ctx, "provider-"+account, f.Accounts[account], f.PrimaryRegion)
		if err != nil {
			return fmt.Errorf("create provider for %s: %w", account, err)
		}

		boundaryProviders[account] = p
	}

	root, err := f.rootProvider(ctx, "root-iam-provider", f.PrimaryRegion)
	if err != nil {
		return fmt.Errorf("create root IAM provider: %w", err)
	}

	if _, err := iam.New(ctx, "iam-root", &iam.Args{
		Account:        a.RootAccount,
		Boundaries:     a.RootBoundaries,
		Provider:       root,
		Names:          a.Names,
		LegacyTopLevel: true,
	}); err != nil {
		return fmt.Errorf("deploy root IAM controls: %w", err)
	}

	pm, err := f.Providers(ctx, "iam", []string{f.PrimaryRegion})
	if err != nil {
		return fmt.Errorf("build iam provider map: %w", err)
	}

	for _, account := range f.Names() {
		args := &iam.Args{
			Account:          account,
			Boundaries:       a.Boundaries,
			Provider:         pm.Get(account, f.PrimaryRegion),
			BoundaryProvider: boundaryProviders[account],
			Names:            a.Names,
			LegacyTopLevel:   true,
		}

		// The accounts that already carry the password policy and the auditor
		// role get the boundaries only.
		if !f.skipped(ctx, logger, account, "password policy and auditor role") {
			policy := a.PasswordPolicy
			args.PasswordPolicy = &policy

			role, err := a.Auditor(f.Accounts[account])
			if err != nil {
				return fmt.Errorf("auditor role (%s): %w", account, err)
			}

			args.AuditorRole = role
		}

		if _, err := iam.New(ctx, "iam-"+account, args); err != nil {
			return fmt.Errorf("deploy account IAM controls (%s): %w", account, err)
		}
	}

	return nil
}
