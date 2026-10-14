package awsprofile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	pulumiaws "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Manager hands out AWS SDK configs, account ids and Pulumi AWS providers by
// profile, each made once and cached. The zero value is not usable; call
// NewManager.
type Manager struct {
	logger *slog.Logger

	mu         sync.Mutex
	configs    map[string]aws.Config          // key: profile, or profile-region
	providers  map[string]*pulumiaws.Provider // key: profile, or profile-region
	accountIDs map[string]string              // key: profile

	// identity returns the account id cfg's credentials belong to. Tests
	// replace it; nil means STS GetCallerIdentity.
	identity func(ctx context.Context, cfg aws.Config) (string, error)
}

// NewManager returns an empty Manager that logs what it creates to logger.
func NewManager(logger *slog.Logger) *Manager {
	return &Manager{
		logger:     logger,
		configs:    make(map[string]aws.Config),
		providers:  make(map[string]*pulumiaws.Provider),
		accountIDs: make(map[string]string),
	}
}

// GetAWSConfig returns the AWS SDK config of profile, its region read from the
// profile in the shared config.
func (m *Manager) GetAWSConfig(ctx context.Context, profile string) (aws.Config, error) {
	return m.config(ctx, profile, profile, awsconfig.WithSharedConfigProfile(profile))
}

// GetAWSConfigWithRegion returns the AWS SDK config of profile in region.
func (m *Manager) GetAWSConfigWithRegion(ctx context.Context, profile, region string) (aws.Config, error) {
	return m.config(ctx, profile+"-"+region, profile,
		awsconfig.WithSharedConfigProfile(profile), awsconfig.WithRegion(region))
}

func (m *Manager) config(
	ctx context.Context, key, profile string, opts ...func(*awsconfig.LoadOptions) error,
) (aws.Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if cfg, ok := m.configs[key]; ok {
		return cfg, nil
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("load AWS config for profile %s: %w", profile, err)
	}

	m.configs[key] = cfg

	m.logger.InfoContext(ctx, "created AWS config", slog.String("profile", profile), slog.String("region", cfg.Region))

	return cfg, nil
}

// GetAccountID returns the id of the account profile's credentials belong to
// (STS GetCallerIdentity).
func (m *Manager) GetAccountID(ctx context.Context, profile string) (string, error) {
	m.mu.Lock()
	id, ok := m.accountIDs[profile]
	m.mu.Unlock()

	if ok {
		return id, nil
	}

	cfg, err := m.GetAWSConfig(ctx, profile)
	if err != nil {
		return "", err
	}

	identity := m.identity
	if identity == nil {
		identity = callerAccount
	}

	id, err = identity(ctx, cfg)
	if err != nil {
		return "", fmt.Errorf("account id of profile %s: %w", profile, err)
	}

	m.mu.Lock()
	m.accountIDs[profile] = id
	m.mu.Unlock()

	m.logger.InfoContext(ctx, "got AWS account id", slog.String("profile", profile), slog.String("account_id", id))

	return id, nil
}

func callerAccount(ctx context.Context, cfg aws.Config) (string, error) {
	out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("get caller identity: %w", err)
	}

	if out.Account == nil {
		return "", errors.New("caller identity has no account")
	}

	return *out.Account, nil
}

// GetAWSProvider returns the Pulumi AWS provider "provider/aws/<profile>", its
// region read from the profile.
func (m *Manager) GetAWSProvider(ctx *pulumi.Context, profile string) (*pulumiaws.Provider, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if p, ok := m.providers[profile]; ok {
		return p, nil
	}

	name := "provider/aws/" + profile

	p, err := pulumiaws.NewProvider(ctx, name, &pulumiaws.ProviderArgs{Profile: pulumi.String(profile)})
	if err != nil {
		return nil, fmt.Errorf("create AWS provider for profile %s: %w", profile, err)
	}

	m.providers[profile] = p

	m.logger.InfoContext(ctx.Context(), "created AWS provider",
		slog.String("profile", profile), slog.String("resource_name", name))

	return p, nil
}

// programProvider names one provider of one Pulumi program run.
type programProvider struct {
	ctx  *pulumi.Context
	name string
}

// programProviders holds every provider GetAWSProviderWithRegion registered,
// per program run, so that several Managers in one program register each
// provider name once.
var programProviders sync.Map

// GetAWSProviderWithRegion returns the Pulumi AWS provider
// "provider/aws/<profile>/<region>". A provider of that name another Manager
// already registered in the same program run is shared, not registered twice.
func (m *Manager) GetAWSProviderWithRegion(ctx *pulumi.Context, profile, region string) (*pulumiaws.Provider, error) {
	key := profile + "-" + region

	m.mu.Lock()
	defer m.mu.Unlock()

	if p, ok := m.providers[key]; ok {
		return p, nil
	}

	name := fmt.Sprintf("provider/aws/%s/%s", profile, region)

	if shared, ok := programProviders.Load(programProvider{ctx: ctx, name: name}); ok {
		p, _ := shared.(*pulumiaws.Provider)
		m.providers[key] = p

		return p, nil
	}

	p, err := pulumiaws.NewProvider(ctx, name, &pulumiaws.ProviderArgs{
		Profile: pulumi.String(profile),
		Region:  pulumi.String(region),
	})
	if err != nil {
		return nil, fmt.Errorf("create AWS provider for profile %s in %s: %w", profile, region, err)
	}

	programProviders.Store(programProvider{ctx: ctx, name: name}, p)
	m.providers[key] = p

	m.logger.InfoContext(ctx.Context(), "created AWS provider",
		slog.String("profile", profile), slog.String("region", region), slog.String("resource_name", name))

	return p, nil
}
