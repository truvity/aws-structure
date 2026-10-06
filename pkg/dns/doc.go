// Package dns deploys Route 53 hosted zones, their delegation and the records
// an estate keeps in them, as plain Pulumi resources.
//
// Zones. NewPublicZone and NewPrivateZone create a zone, or adopt an existing
// one (ZoneBase.Import), and, when a parent is named, the NS record that
// delegates the zone from the parent. Deploy creates several zones, roots
// first. A private zone needs one VPC at creation (BootstrapVPCID); a child
// private zone in another account than its parent also gets the parent zone
// associated with its VPC, so names resolve end to end (AssociateZone).
// DeployRootZone and DeployEnvironmentZone are the two shapes an estate uses:
// a root private zone, and one child per environment delegated from it.
//
// Records. DeployPrivateEntryRecords writes one A record per name at an
// address the caller pins, and one CNAME per cross-cluster name at a load
// balancer it finds by tag; it refuses wildcards and names outside the zone.
// StatusBoxRecord writes one A record at the address of the live device among
// the candidates the caller looked up (PickDevice).
//
// Logical names are "<prefix>/<zone with dots as dashes>/{zone,delegation,
// parent-assoc}" and the record names the caller's slug function and these
// functions build; they are API. The package never writes a zone name, an
// account id, a profile or a hostname of its own: all of them are inputs.
package dns
