package dns

import (
	"fmt"
	"log/slog"

	pulumiaws "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type (
	// RootZoneConfig configures a root private DNS zone (no parent delegation).
	RootZoneConfig struct {
		ZoneName       string              // e.g., "example.private"
		Provider       *pulumiaws.Provider // AWS provider for the zone's account
		Region         string              // AWS region
		BootstrapVPCID pulumi.StringInput  // VPC to associate at zone creation time
	}
)

// DeployRootZone creates a root private zone with no parent delegation.
// It exports root-private-zone-id, root-private-zone-name, and root-private-zone-name-servers.
func DeployRootZone(
	c *pulumi.Context,
	logger *slog.Logger,
	cfg RootZoneConfig,
) (*DeployResult, error) {
	ctx := c.Context()

	logger.InfoContext(ctx, "deploying root private zone",
		slog.String("zone", cfg.ZoneName),
	)

	result, err := Deploy(c, logger, "dns",
		nil,
		[]PrivateZoneConfig{
			{
				ZoneBase: ZoneBase{
					ZoneName: cfg.ZoneName,
					Provider: cfg.Provider,
					Region:   cfg.Region,
					Import:   false,
				},
				BootstrapVPCID: cfg.BootstrapVPCID,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("deploy root zone %s: %w", cfg.ZoneName, err)
	}

	// Export standard outputs for the root zone.
	if rootPrivate, ok := result.PrivateZones[cfg.ZoneName]; ok {
		c.Export("root-private-zone-id", rootPrivate.ZoneID)
		c.Export("root-private-zone-name", pulumi.String(cfg.ZoneName))
		c.Export("root-private-zone-name-servers", rootPrivate.NameServers)
	}

	return result, nil
}
