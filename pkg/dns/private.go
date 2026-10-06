package dns

import (
	"log/slog"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// NewPrivateZone creates or imports a private hosted zone with optional NS delegation.
// BootstrapVPCID is required — Route53 needs at least one VPC to create a private zone.
func NewPrivateZone(
	c *pulumi.Context,
	logger *slog.Logger,
	resourceName string,
	config PrivateZoneConfig,
) (*ZoneResult, error) {
	return newZone(c, logger, resourceName, config.ZoneBase, config.Parent, true, config.BootstrapVPCID)
}
