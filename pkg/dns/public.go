package dns

import (
	"log/slog"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// NewPublicZone creates or imports a public hosted zone with optional NS delegation.
func NewPublicZone(
	c *pulumi.Context,
	logger *slog.Logger,
	resourceName string,
	config PublicZoneConfig,
) (*ZoneResult, error) {
	return newZone(c, logger, resourceName, config.ZoneBase, config.Parent, false, nil)
}
