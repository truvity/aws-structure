package dns

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/route53"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// privateEntryRecordTTL is short on purpose: the first thing anybody does
// when a private name is wrong is change it and try again, and an hour of
// cache turns that into a morning.
const privateEntryRecordTTL = 60

// LoadBalancerFinder finds the DNS name of the internal load balancer that
// carries a Service, by the Service's stack tag. It returns "" with a nil
// error when there is none yet.
type LoadBalancerFinder interface {
	FindLoadBalancerDNS(ctx context.Context, cluster, stackTag string) (string, error)
}

// PrivateEntry configures DeployPrivateEntryRecords.
type PrivateEntry struct {
	// Cluster names the cluster, for messages and for the load balancer lookup.
	Cluster string
	// ZoneID and ZoneName are the zone the records go in. ZoneName is also the
	// zone every name must be inside.
	ZoneID   pulumi.StringInput
	ZoneName string
	// Address is the pinned address of the shared private entry; every name of
	// Hosts is an A record to it.
	Address string
	// Hosts are the names written as A records. Exact names only.
	Hosts []string
	// CrossClusterHosts are the names written as CNAMEs to the load balancer
	// in front of the private entry, when it exists.
	CrossClusterHosts []string
	// LoadBalancerTag is the stack tag of the Service the load balancer
	// carries. Required when CrossClusterHosts is not empty.
	LoadBalancerTag string
	// LoadBalancers finds the load balancer. Required when CrossClusterHosts
	// is not empty.
	LoadBalancers LoadBalancerFinder
	// Slug turns a name into the suffix of a record's logical name. Required.
	// Records are "private-entry-<slug>" and "cross-cluster-<slug>".
	Slug func(host string) string
}

// DeployPrivateEntryRecords writes one A record per name of Hosts, all
// pointing at Address, and one CNAME per name of CrossClusterHosts, pointing
// at the load balancer found by tag.
//
// EXACT NAMES ONLY. Every record is one name, never a wildcard: a typo in a
// private name should fail to resolve rather than land on the gateway and come
// back as a certificate error or a 404. A name outside the zone is refused for
// the same reason.
//
// A MISSING LOAD BALANCER IS NOT AN ERROR. The Service is created by a release
// this stack does not order, so on a cluster whose gateways have not synced
// yet there is nothing to point at. The cross-cluster records are skipped with
// a warning and the next run writes them.
//
// It exports privateEntryAddress, privateEntryRecords and crossClusterRecords.
func DeployPrivateEntryRecords(
	c *pulumi.Context,
	logger *slog.Logger,
	e PrivateEntry,
	opts ...pulumi.ResourceOption,
) error {
	goCtx := c.Context()

	if len(e.Hosts) == 0 && len(e.CrossClusterHosts) == 0 {
		logger.InfoContext(goCtx, "no private-clusterip exposure on this cluster; no private entry records",
			slog.String("cluster", e.Cluster))

		return nil
	}

	if e.Slug == nil {
		return fmt.Errorf("cluster %s: private entry records need a slug function", e.Cluster)
	}

	for _, host := range e.Hosts {
		if err := ValidatePrivateEntryHost(e.Cluster, e.ZoneName, host); err != nil {
			return err
		}

		if _, err := route53.NewRecord(c, "private-entry-"+e.Slug(host), &route53.RecordArgs{
			ZoneId:  e.ZoneID,
			Name:    pulumi.String(host),
			Type:    pulumi.String("A"),
			Ttl:     pulumi.Int(privateEntryRecordTTL),
			Records: pulumi.StringArray{pulumi.String(e.Address)},
		}, opts...); err != nil {
			return fmt.Errorf("private entry record %s: %w", host, err)
		}

		logger.InfoContext(goCtx, "private entry record",
			slog.String("cluster", e.Cluster),
			slog.String("host", host),
			slog.String("address", e.Address),
		)
	}

	if err := deployCrossClusterRecords(c, logger, e, opts...); err != nil {
		return err
	}

	c.Export("privateEntryAddress", pulumi.String(e.Address))
	c.Export("privateEntryRecords", pulumi.ToStringArray(e.Hosts))
	c.Export("crossClusterRecords", pulumi.ToStringArray(e.CrossClusterHosts))

	return nil
}

// deployCrossClusterRecords points each cross-cluster name at the load balancer
// in front of the cluster's private entry. A CNAME and not an A record: the
// address is the load balancer controller's, it changes when the Service is
// recreated, and nothing in the caller's data can know it, which is why it is
// FOUND.
func deployCrossClusterRecords(
	c *pulumi.Context,
	logger *slog.Logger,
	e PrivateEntry,
	opts ...pulumi.ResourceOption,
) error {
	if len(e.CrossClusterHosts) == 0 {
		return nil
	}

	if e.LoadBalancers == nil || e.LoadBalancerTag == "" {
		return fmt.Errorf("cluster %s: cross-cluster records need a load balancer finder and its tag", e.Cluster)
	}

	goCtx := c.Context()

	lbDNS, err := e.LoadBalancers.FindLoadBalancerDNS(goCtx, e.Cluster, e.LoadBalancerTag)
	if err != nil {
		return fmt.Errorf("find the private entry load balancer: %w", err)
	}

	if lbDNS == "" {
		logger.WarnContext(goCtx, "no private entry load balancer yet; skipping the cross-cluster records",
			slog.String("cluster", e.Cluster),
			slog.String("load_balancer_tag", e.LoadBalancerTag),
			slog.String("rerun_after", "the gateways Application has synced"),
			slog.Any("records", e.CrossClusterHosts),
		)

		return nil
	}

	for _, host := range e.CrossClusterHosts {
		if err := ValidatePrivateEntryHost(e.Cluster, e.ZoneName, host); err != nil {
			return err
		}

		if _, err := route53.NewRecord(c, "cross-cluster-"+e.Slug(host), &route53.RecordArgs{
			ZoneId:  e.ZoneID,
			Name:    pulumi.String(host),
			Type:    pulumi.String("CNAME"),
			Ttl:     pulumi.Int(privateEntryRecordTTL),
			Records: pulumi.StringArray{pulumi.String(lbDNS)},
		}, opts...); err != nil {
			return fmt.Errorf("cross-cluster record %s: %w", host, err)
		}

		logger.InfoContext(goCtx, "cross-cluster record",
			slog.String("cluster", e.Cluster),
			slog.String("host", host),
			slog.String("load_balancer", lbDNS),
		)
	}

	return nil
}

// ValidatePrivateEntryHost refuses the two shapes that would write a record
// somewhere other than where the caller's catalog says: a wildcard (which would
// capture names nobody cataloged) and a name outside the cluster's own private
// zone.
func ValidatePrivateEntryHost(cluster, zone, host string) error {
	if strings.HasPrefix(host, "*.") {
		return fmt.Errorf(
			"cluster %s: private entry domain %q is a wildcard — private names are written one at a time, "+
				"so an uncataloged name fails to resolve instead of landing here", cluster, host)
	}

	if host != zone && !strings.HasSuffix(host, "."+zone) {
		return fmt.Errorf(
			"cluster %s: private entry domain %q is not inside this cluster's private zone %q", cluster, host, zone)
	}

	return nil
}
