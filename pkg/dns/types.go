package dns

import (
	pulumiaws "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/route53"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type (
	// ZoneBase contains common configuration for all zones.
	ZoneBase struct {
		ZoneName string              // e.g., "example.test", "env.example.private"
		Provider *pulumiaws.Provider // AWS provider for the zone's account
		Region   string              // AWS region (used for VPC association args)
		Import   bool                // true = lookup & adopt existing zone; false = create new
	}

	// ParentRef references a parent zone for NS delegation.
	//
	// For new zones (Import=false): set ZoneID to a stack reference output to avoid
	// LookupZone calls (required for private zones with no VPC associations yet).
	// If ZoneID is nil, LookupZone is used as fallback (public zones only).
	//
	// For import flows (Import=true): set ZoneIDForImport to the plain zone ID string
	// so the AWS SDK can list existing records without blocking on Pulumi outputs.
	ParentRef struct {
		ZoneName        string              // Parent zone name (used for NS record name)
		Provider        *pulumiaws.Provider // AWS provider for parent's account
		Profile         string              // AWS profile for parent's account (used for SDK lookups)
		ZoneID          pulumi.StringInput  // Zone ID as Pulumi output (for create flows)
		ZoneIDForImport string              // Zone ID as plain string (for import flows only)
	}

	// PublicZoneConfig configures a public hosted zone.
	PublicZoneConfig struct {
		ZoneBase
		Parent *ParentRef // nil = root zone (no delegation)
	}

	// PrivateZoneConfig configures a private hosted zone.
	PrivateZoneConfig struct {
		ZoneBase
		Parent *ParentRef // nil = root zone (no delegation)

		// BootstrapVPCID is the VPC to associate at zone creation time.
		// Route53 requires at least one VPC association to create a private zone.
		BootstrapVPCID pulumi.StringInput
	}

	// ZoneResult contains deployed zone information.
	ZoneResult struct {
		Zone        *route53.Zone
		ZoneID      pulumi.StringOutput
		NameServers pulumi.StringArrayOutput
	}

	// DeployResult contains all deployed zones.
	DeployResult struct {
		PublicZones  map[string]*ZoneResult // keyed by ZoneName
		PrivateZones map[string]*ZoneResult // keyed by ZoneName
	}

	// ZoneAssociationConfig configures a VPC association with a private hosted zone.
	ZoneAssociationConfig struct {
		ZoneID       pulumi.StringInput  // Route53 zone ID
		VPCID        pulumi.StringInput  // VPC to associate
		ZoneProvider *pulumiaws.Provider // Provider for the zone owner's account
		VPCProvider  *pulumiaws.Provider // Provider for the VPC owner's account
		Region       string              // AWS region
		CrossAccount bool                // true = different accounts (requires authorization resource)
	}
)
