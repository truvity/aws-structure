package dns

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsroute53 "github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	pulumiaws "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/route53"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// newZone creates or imports a hosted zone with optional NS delegation.
// isPrivate controls the Route53 zone type.
// bootstrapVPCID is required for private zones — Route53 needs at least one VPC at creation time.
func newZone(
	c *pulumi.Context,
	logger *slog.Logger,
	resourceName string,
	base ZoneBase,
	parent *ParentRef,
	isPrivate bool,
	bootstrapVPCID pulumi.StringInput,
) (*ZoneResult, error) {
	ctx := c.Context()

	kindLabel := "public"
	if isPrivate {
		kindLabel = "private"
	}

	awsProvider := base.Provider

	var zone *route53.Zone

	zoneNameWithDot := base.ZoneName
	if !strings.HasSuffix(zoneNameWithDot, ".") {
		zoneNameWithDot += "."
	}

	if base.Import {
		logger.InfoContext(ctx, "looking up existing zone",
			slog.String("zone_name", base.ZoneName),
			slog.String("kind", kindLabel),
		)

		lookedUpZone, err := route53.LookupZone(c, &route53.LookupZoneArgs{
			Name:        &zoneNameWithDot,
			PrivateZone: pulumi.BoolRef(isPrivate),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return nil, fmt.Errorf("lookup zone: %w", err)
		}

		logger.InfoContext(ctx, "found existing zone",
			slog.String("zone_name", base.ZoneName),
			slog.String("kind", kindLabel),
			slog.String("zone_id", lookedUpZone.ZoneId),
		)

		zoneID := lookedUpZone.ZoneId
		zone, err = route53.NewZone(c, fmt.Sprintf("%s/zone", resourceName), &route53.ZoneArgs{
			Name:    pulumi.String(zoneNameWithDot),
			Comment: pulumi.String(fmt.Sprintf("%s hosted zone %s (imported)", kindLabel, base.ZoneName)),
			Tags: pulumi.StringMap{
				"Name":      pulumi.String(base.ZoneName),
				"ManagedBy": pulumi.String("pulumi"),
			},
		}, pulumi.Provider(awsProvider), pulumi.Import(pulumi.ID(zoneID)))
		if err != nil {
			return nil, fmt.Errorf("import existing zone %s (ID: %s): %w", base.ZoneName, zoneID, err)
		}

		logger.InfoContext(ctx, "imported existing zone",
			slog.String("zone_name", base.ZoneName),
			slog.String("kind", kindLabel),
			slog.String("zone_id", zoneID),
		)
	} else {
		logger.InfoContext(ctx, "creating new zone",
			slog.String("zone_name", base.ZoneName),
			slog.String("kind", kindLabel),
		)

		zone, err := route53.NewZone(c, fmt.Sprintf("%s/zone", resourceName), &route53.ZoneArgs{
			Name:    pulumi.String(zoneNameWithDot),
			Comment: pulumi.String(fmt.Sprintf("%s hosted zone %s", kindLabel, base.ZoneName)),
			Vpcs:    buildZoneVPCs(isPrivate, bootstrapVPCID, base.Region),
			Tags: pulumi.StringMap{
				"Name":      pulumi.String(base.ZoneName),
				"ManagedBy": pulumi.String("pulumi"),
			},
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return nil, fmt.Errorf("create zone: %w", err)
		}

		logger.InfoContext(ctx, "created zone",
			slog.String("zone_name", base.ZoneName),
			slog.String("kind", kindLabel),
		)

		if parent != nil {
			if err := createNSDelegation(c, logger, resourceName, base, parent, zone, isPrivate); err != nil {
				return nil, err
			}

			// For child private zones in a different account: associate the parent zone
			// with this zone's primary VPC so DNS resolution works end-to-end.
			// Same-account: parent zone already has this VPC from its own bootstrap — skip.
			if isPrivate && bootstrapVPCID != nil && parent.Provider != base.Provider {
				parentZoneID, err := resolveParentZoneID(c, logger, parent, base.Region, isPrivate)
				if err != nil {
					return nil, fmt.Errorf("resolve parent zone %s for association: %w", parent.ZoneName, err)
				}

				if err := AssociateZone(c, logger, fmt.Sprintf("%s/parent-assoc", resourceName), ZoneAssociationConfig{
					ZoneID:       parentZoneID,
					VPCID:        bootstrapVPCID,
					ZoneProvider: parent.Provider,
					VPCProvider:  base.Provider,
					Region:       base.Region,
					CrossAccount: true,
				}); err != nil {
					return nil, fmt.Errorf("associate parent zone %s with child VPC: %w", parent.ZoneName, err)
				}
			}
		}

		return &ZoneResult{
			Zone:        zone,
			ZoneID:      zone.ZoneId.ToStringOutput(),
			NameServers: zone.NameServers,
		}, nil
	}

	if parent != nil {
		if err := createNSDelegation(c, logger, resourceName, base, parent, zone, isPrivate); err != nil {
			return nil, err
		}
	}

	return &ZoneResult{
		Zone:        zone,
		ZoneID:      zone.ZoneId.ToStringOutput(),
		NameServers: zone.NameServers,
	}, nil
}

// resolveParentZoneID returns the parent zone ID as a StringInput.
// Uses ZoneID output if set, otherwise falls back to AWS SDK lookup by name.
func resolveParentZoneID(
	c *pulumi.Context,
	logger *slog.Logger,
	parent *ParentRef,
	region string,
	isPrivate bool,
) (pulumi.StringInput, error) {
	if parent.ZoneID != nil {
		return parent.ZoneID, nil
	}
	zoneID, err := LookupZoneIDByName(c, logger, parent.ZoneName, parent.Profile, region, isPrivate)
	if err != nil {
		return nil, err
	}
	return pulumi.String(zoneID), nil
}

// createNSDelegation creates or imports an NS delegation record in the parent zone.
func createNSDelegation(
	c *pulumi.Context,
	logger *slog.Logger,
	resourceName string,
	base ZoneBase,
	parent *ParentRef,
	zone *route53.Zone,
	isPrivate bool,
) error {
	ctx := c.Context()

	parentProvider := parent.Provider

	childZoneNameWithDot := base.ZoneName
	if !strings.HasSuffix(childZoneNameWithDot, ".") {
		childZoneNameWithDot += "."
	}

	if base.Import {
		if parent.ZoneIDForImport == "" {
			return fmt.Errorf("parent.ZoneIDForImport must be set when base.Import=true (zone %s)", base.ZoneName)
		}
		return importOrCreateNSDelegation(c, logger, resourceName, base, parent, zone, parentProvider, childZoneNameWithDot)
	}

	// Create flow: resolve parent zone ID from output, or by AWS SDK lookup.
	var parentZoneID pulumi.StringInput
	if parent.ZoneID != nil {
		parentZoneID = parent.ZoneID
	} else {
		zoneID, err := LookupZoneIDByName(c, logger, parent.ZoneName, parent.Profile, base.Region, isPrivate)
		if err != nil {
			return fmt.Errorf("lookup parent zone %s: %w", parent.ZoneName, err)
		}
		parentZoneID = pulumi.String(zoneID)
	}

	logger.InfoContext(ctx, "creating NS delegation",
		slog.String("child_zone", base.ZoneName),
		slog.String("parent_zone", parent.ZoneName),
	)

	_, err := route53.NewRecord(c, fmt.Sprintf("%s/delegation", resourceName), &route53.RecordArgs{
		ZoneId:  parentZoneID,
		Name:    pulumi.String(childZoneNameWithDot),
		Type:    pulumi.String("NS"),
		Ttl:     pulumi.Int(300),
		Records: zone.NameServers,
	}, pulumi.Provider(parentProvider))
	if err != nil {
		return fmt.Errorf("create NS delegation: %w", err)
	}

	logger.InfoContext(ctx, "created NS delegation",
		slog.String("child_zone", base.ZoneName),
		slog.String("parent_zone", parent.ZoneName),
	)

	return nil
}

// importOrCreateNSDelegation checks if an NS record already exists and imports or creates it.
func importOrCreateNSDelegation(
	c *pulumi.Context,
	logger *slog.Logger,
	resourceName string,
	base ZoneBase,
	parent *ParentRef,
	zone *route53.Zone,
	parentProvider *pulumiaws.Provider,
	childZoneNameWithDot string,
) error {
	ctx := c.Context()

	logger.InfoContext(ctx, "looking up existing NS delegation",
		slog.String("child_zone", base.ZoneName),
		slog.String("parent_zone", parent.ZoneName),
	)

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(base.Region),
		awsconfig.WithSharedConfigProfile(parent.Profile),
	)
	if err != nil {
		return fmt.Errorf("load AWS config for parent zone: %w", err)
	}

	route53Client := awsroute53.NewFromConfig(awsCfg)
	recordExists := false

	paginator := awsroute53.NewListResourceRecordSetsPaginator(route53Client, &awsroute53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(parent.ZoneIDForImport),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list records in parent zone: %w", err)
		}
		for i := range page.ResourceRecordSets {
			rs := &page.ResourceRecordSets[i]
			if rs.Type == route53types.RRTypeNs && aws.ToString(rs.Name) == childZoneNameWithDot {
				recordExists = true
				break
			}
		}
		if recordExists {
			break
		}
	}

	recordArgs := &route53.RecordArgs{
		ZoneId:  pulumi.String(parent.ZoneIDForImport),
		Name:    pulumi.String(childZoneNameWithDot),
		Type:    pulumi.String("NS"),
		Ttl:     pulumi.Int(300),
		Records: zone.NameServers,
	}

	if recordExists {
		recordID := fmt.Sprintf("%s_%s_NS", parent.ZoneIDForImport, childZoneNameWithDot)
		logger.InfoContext(ctx, "found existing NS delegation, importing",
			slog.String("child_zone", base.ZoneName),
			slog.String("parent_zone", parent.ZoneName),
			slog.String("record_id", recordID),
		)
		_, err = route53.NewRecord(c, fmt.Sprintf("%s/delegation", resourceName), recordArgs,
			pulumi.Provider(parentProvider), pulumi.Import(pulumi.ID(recordID)))
		if err != nil {
			return fmt.Errorf("import NS delegation record: %w", err)
		}
		logger.InfoContext(ctx, "imported existing NS delegation",
			slog.String("child_zone", base.ZoneName),
			slog.String("parent_zone", parent.ZoneName),
		)
	} else {
		logger.InfoContext(ctx, "NS delegation record not found, creating new one",
			slog.String("child_zone", base.ZoneName),
			slog.String("parent_zone", parent.ZoneName),
		)
		_, err = route53.NewRecord(c, fmt.Sprintf("%s/delegation", resourceName), recordArgs,
			pulumi.Provider(parentProvider))
		if err != nil {
			return fmt.Errorf("create NS delegation: %w", err)
		}
		logger.InfoContext(ctx, "created NS delegation",
			slog.String("child_zone", base.ZoneName),
			slog.String("parent_zone", parent.ZoneName),
		)
	}

	return nil
}

// buildZoneVPCs returns a VPC array for zone creation.
// Route53 requires at least one VPC at creation time to make a zone private.
func buildZoneVPCs(isPrivate bool, bootstrapVPCID pulumi.StringInput, region string) route53.ZoneVpcArray {
	if !isPrivate || bootstrapVPCID == nil {
		return nil
	}
	return route53.ZoneVpcArray{
		route53.ZoneVpcArgs{
			VpcId:     bootstrapVPCID,
			VpcRegion: pulumi.String(region),
		},
	}
}

// LookupZoneIDByName finds a hosted zone ID using the AWS SDK's ListHostedZonesByName.
//
// Unlike Pulumi's route53.LookupZone, the AWS SDK returns all zones including private
// zones without VPC associations — critical for cross-backend scenarios.
func LookupZoneIDByName(
	c *pulumi.Context,
	logger *slog.Logger,
	zoneName string,
	profile string,
	region string,
	isPrivate bool,
) (string, error) {
	ctx := c.Context()

	zoneNameWithDot := zoneName
	if !strings.HasSuffix(zoneNameWithDot, ".") {
		zoneNameWithDot += "."
	}

	logger.InfoContext(ctx, "looking up zone ID via AWS SDK",
		slog.String("zone_name", zoneName),
		slog.String("profile", profile),
		slog.Bool("private", isPrivate),
	)

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(region),
		awsconfig.WithSharedConfigProfile(profile),
	)
	if err != nil {
		return "", fmt.Errorf("load AWS config: %w", err)
	}

	client := awsroute53.NewFromConfig(awsCfg)

	resp, err := client.ListHostedZonesByName(ctx, &awsroute53.ListHostedZonesByNameInput{
		DNSName: aws.String(zoneNameWithDot),
	})
	if err != nil {
		return "", fmt.Errorf("list hosted zones by name: %w", err)
	}

	for i := range resp.HostedZones {
		hz := &resp.HostedZones[i]
		hzIsPrivate := hz.Config != nil && hz.Config.PrivateZone

		if aws.ToString(hz.Name) != zoneNameWithDot {
			continue
		}
		if hzIsPrivate != isPrivate {
			continue
		}
		zoneID := aws.ToString(hz.Id)
		zoneID = strings.TrimPrefix(zoneID, "/hostedzone/")

		logger.InfoContext(ctx, "found zone via AWS SDK",
			slog.String("zone_name", zoneName),
			slog.String("zone_id", zoneID),
		)

		return zoneID, nil
	}

	return "", fmt.Errorf("zone %s (private=%t) not found", zoneName, isPrivate)
}

// zoneNameToResourceName converts zone name to resource name (dots → dashes).
func zoneNameToResourceName(zoneName string) string {
	return strings.ReplaceAll(zoneName, ".", "-")
}

// Deploy creates multiple zones in correct order (roots first, then children).
func Deploy(
	c *pulumi.Context,
	logger *slog.Logger,
	resourcePrefix string,
	publicZones []PublicZoneConfig,
	privateZones []PrivateZoneConfig,
) (*DeployResult, error) {
	ctx := c.Context()

	logger.InfoContext(ctx, "deploying DNS zones",
		slog.Int("public_zones", len(publicZones)),
		slog.Int("private_zones", len(privateZones)),
	)

	result := &DeployResult{
		PublicZones:  make(map[string]*ZoneResult),
		PrivateZones: make(map[string]*ZoneResult),
	}

	// Separate roots from children
	var rootPublic, childPublic []PublicZoneConfig
	for _, zone := range publicZones {
		if zone.Parent == nil {
			rootPublic = append(rootPublic, zone)
		} else {
			childPublic = append(childPublic, zone)
		}
	}

	var rootPrivate, childPrivate []PrivateZoneConfig
	for _, zone := range privateZones {
		if zone.Parent == nil {
			rootPrivate = append(rootPrivate, zone)
		} else {
			childPrivate = append(childPrivate, zone)
		}
	}

	logger.InfoContext(ctx, "separated zones",
		slog.Int("root_public", len(rootPublic)),
		slog.Int("child_public", len(childPublic)),
		slog.Int("root_private", len(rootPrivate)),
		slog.Int("child_private", len(childPrivate)),
	)

	// Deploy root zones first
	for _, config := range rootPublic {
		resourceName := fmt.Sprintf("%s/%s", resourcePrefix, zoneNameToResourceName(config.ZoneName))
		zoneResult, err := NewPublicZone(c, logger, resourceName, config)
		if err != nil {
			return nil, fmt.Errorf("deploy root public zone %s: %w", config.ZoneName, err)
		}
		result.PublicZones[config.ZoneName] = zoneResult
	}

	for _, config := range rootPrivate {
		resourceName := fmt.Sprintf("%s/%s", resourcePrefix, zoneNameToResourceName(config.ZoneName))
		zoneResult, err := NewPrivateZone(c, logger, resourceName, config)
		if err != nil {
			return nil, fmt.Errorf("deploy root private zone %s: %w", config.ZoneName, err)
		}
		result.PrivateZones[config.ZoneName] = zoneResult
	}

	// Deploy child zones (with delegation)
	for _, config := range childPublic {
		resourceName := fmt.Sprintf("%s/%s", resourcePrefix, zoneNameToResourceName(config.ZoneName))
		zoneResult, err := NewPublicZone(c, logger, resourceName, config)
		if err != nil {
			return nil, fmt.Errorf("deploy child public zone %s: %w", config.ZoneName, err)
		}
		result.PublicZones[config.ZoneName] = zoneResult
	}

	for _, config := range childPrivate {
		resourceName := fmt.Sprintf("%s/%s", resourcePrefix, zoneNameToResourceName(config.ZoneName))
		zoneResult, err := NewPrivateZone(c, logger, resourceName, config)
		if err != nil {
			return nil, fmt.Errorf("deploy child private zone %s: %w", config.ZoneName, err)
		}
		result.PrivateZones[config.ZoneName] = zoneResult
	}

	logger.InfoContext(ctx, "deployed all DNS zones",
		slog.Int("total_public", len(result.PublicZones)),
		slog.Int("total_private", len(result.PrivateZones)),
	)

	return result, nil
}
