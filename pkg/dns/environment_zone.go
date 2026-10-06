package dns

import (
	"fmt"
	"log/slog"

	pulumiaws "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type (
	// EnvironmentZoneConfig configures a per-environment private DNS zone.
	EnvironmentZoneConfig struct {
		Environment    string              // e.g., "env-a", "env-b"
		Provider       *pulumiaws.Provider // AWS provider for this environment's account (zone creation)
		ParentProvider *pulumiaws.Provider // AWS provider for the parent zone's account (NS delegation). If nil, uses Provider.
		Profile        string              // AWS profile for the parent zone's account (NS delegation lookups)
		Region         string              // AWS region
		RootZoneID     pulumi.StringInput  // Root zone ID (from the root zone stack output)
		BootstrapVPCID pulumi.StringInput  // VPC ID for zone association at creation time
		PrivateDomain  string              // Root private domain (e.g., "example.private")
		EnvDomain      string              // Environment-specific domain (e.g., "env-a.example.private")
	}
)

// DeployEnvironmentZone creates a {env}.{privateDomain} child zone with NS delegation
// to the root zone. This is the shared pattern used by every environment.
func DeployEnvironmentZone(
	c *pulumi.Context,
	logger *slog.Logger,
	cfg EnvironmentZoneConfig,
) (*DeployResult, error) {
	ctx := c.Context()

	logger.InfoContext(ctx, "deploying environment private zone",
		slog.String("environment", cfg.Environment),
		slog.String("domain", cfg.EnvDomain),
	)

	// Resolve parent provider: if ParentProvider is set, use it for NS delegation.
	// Otherwise, use the zone Provider (same-account case).
	parentProvider := cfg.Provider
	if cfg.ParentProvider != nil {
		parentProvider = cfg.ParentProvider
	}

	result, err := Deploy(c, logger, "dns",
		nil,
		[]PrivateZoneConfig{
			{
				ZoneBase: ZoneBase{
					ZoneName: cfg.EnvDomain,
					Provider: cfg.Provider,
					Region:   cfg.Region,
					Import:   false,
				},
				Parent: &ParentRef{
					ZoneName: cfg.PrivateDomain,
					Provider: parentProvider,
					Profile:  cfg.Profile,
					ZoneID:   cfg.RootZoneID,
				},
				BootstrapVPCID: cfg.BootstrapVPCID,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("deploy environment zone %s: %w", cfg.EnvDomain, err)
	}

	// Export standard outputs for the environment zone.
	if envPrivate, ok := result.PrivateZones[cfg.EnvDomain]; ok {
		c.Export("private-zone-id", envPrivate.ZoneID)
		c.Export("private-zone-name", pulumi.String(cfg.EnvDomain))
		c.Export("private-zone-name-servers", envPrivate.NameServers)
	}

	return result, nil
}
