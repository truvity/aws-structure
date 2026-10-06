package dns

import (
	"fmt"
	"log/slog"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/route53"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// AssociateZone creates a Route53 VPC association for a private hosted zone.
//
// Same-account: set ZoneProvider == VPCProvider, CrossAccount = false.
// Cross-account: set ZoneProvider to zone owner, VPCProvider to VPC owner, CrossAccount = true.
func AssociateZone(
	c *pulumi.Context,
	logger *slog.Logger,
	resourceName string,
	config ZoneAssociationConfig,
) error {
	ctx := c.Context()

	logger.InfoContext(ctx, "associating VPC with private zone",
		slog.String("resource", resourceName),
		slog.Bool("cross_account", config.CrossAccount),
	)

	if config.CrossAccount {
		// Cross-account: zone owner must authorize the VPC first.
		auth, err := route53.NewVpcAssociationAuthorization(c, fmt.Sprintf("%s/auth", resourceName), &route53.VpcAssociationAuthorizationArgs{
			ZoneId:    config.ZoneID,
			VpcId:     config.VPCID,
			VpcRegion: pulumi.String(config.Region),
		}, pulumi.Provider(config.ZoneProvider))
		if err != nil {
			return fmt.Errorf("create VPC association authorization: %w", err)
		}

		// VPC owner's provider creates the actual association.
		// DependsOn auth — AWS requires authorization to exist before association.
		_, err = route53.NewZoneAssociation(c, fmt.Sprintf("%s/assoc", resourceName), &route53.ZoneAssociationArgs{
			ZoneId:    config.ZoneID,
			VpcId:     config.VPCID,
			VpcRegion: pulumi.String(config.Region),
		}, pulumi.Provider(config.VPCProvider), pulumi.DependsOn([]pulumi.Resource{auth}))
		if err != nil {
			return fmt.Errorf("create cross-account zone association: %w", err)
		}
	} else {
		// Same-account: single ZoneAssociation resource.
		_, err := route53.NewZoneAssociation(c, fmt.Sprintf("%s/assoc", resourceName), &route53.ZoneAssociationArgs{
			ZoneId:    config.ZoneID,
			VpcId:     config.VPCID,
			VpcRegion: pulumi.String(config.Region),
		}, pulumi.Provider(config.ZoneProvider))
		if err != nil {
			return fmt.Errorf("create zone association: %w", err)
		}
	}

	logger.InfoContext(ctx, "associated VPC with private zone",
		slog.String("resource", resourceName),
	)

	return nil
}
