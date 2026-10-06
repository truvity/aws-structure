package dns_test

import (
	"context"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"testing"

	pulumiaws "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/dns"
)

type recorded struct {
	typ, name string
	inputs    resource.PropertyMap
}

type recorder struct {
	mu   sync.Mutex
	regs []recorded
}

func (r *recorder) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	r.mu.Lock()
	r.regs = append(r.regs, recorded{args.TypeToken, args.Name, args.Inputs})
	r.mu.Unlock()

	out := args.Inputs.Copy()
	out["zoneId"] = resource.NewProperty("zone-of-" + args.Name)
	out["nameServers"] = resource.NewProperty([]resource.PropertyValue{resource.NewProperty("ns-1")})

	return args.Name + "-id", out, nil
}

func (*recorder) Call(_ pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return resource.PropertyMap{}, nil
}

func (r *recorder) names(typ string) []string {
	var out []string

	for _, g := range r.regs {
		if g.typ == typ {
			out = append(out, g.name)
		}
	}

	sort.Strings(out)

	return out
}

func (r *recorder) input(typ, name, key string) resource.PropertyValue {
	for _, g := range r.regs {
		if g.typ == typ && g.name == name {
			return g.inputs[resource.PropertyKey(key)]
		}
	}

	return resource.NewNullProperty()
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func provider(ctx *pulumi.Context, name string) (*pulumiaws.Provider, error) {
	return pulumiaws.NewProvider(ctx, name, &pulumiaws.ProviderArgs{Region: pulumi.String("region-a")})
}

const (
	zoneType   = "aws:route53/zone:Zone"
	recordType = "aws:route53/record:Record"
	assocType  = "aws:route53/zoneAssociation:ZoneAssociation"
	authType   = "aws:route53/vpcAssociationAuthorization:VpcAssociationAuthorization"
)

func TestEnvironmentZoneNames(t *testing.T) {
	rec := &recorder{}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		env, err := provider(ctx, "env")
		if err != nil {
			return err
		}

		parent, err := provider(ctx, "parent")
		if err != nil {
			return err
		}

		_, err = dns.DeployEnvironmentZone(ctx, quiet(), dns.EnvironmentZoneConfig{
			Environment:    "env-a",
			Provider:       env,
			ParentProvider: parent,
			Profile:        "parent-profile",
			Region:         "region-a",
			RootZoneID:     pulumi.String("root-zone"),
			BootstrapVPCID: pulumi.String("vpc-ref"),
			PrivateDomain:  "example.private",
			EnvDomain:      "env-a.example.private",
		})

		return err
	}, pulumi.WithMocks("proj", "stack", rec))
	if err != nil {
		t.Fatal(err)
	}

	if got := rec.names(zoneType); strings.Join(got, ",") != "dns/env-a-example-private/zone" {
		t.Errorf("zones = %v", got)
	}

	if got := rec.names(recordType); strings.Join(got, ",") != "dns/env-a-example-private/delegation" {
		t.Errorf("records = %v", got)
	}

	// The parent is in another account: its zone is associated with the
	// child's VPC, authorization first.
	if got := rec.names(authType); strings.Join(got, ",") != "dns/env-a-example-private/parent-assoc/auth" {
		t.Errorf("authorizations = %v", got)
	}

	if got := rec.names(assocType); strings.Join(got, ",") != "dns/env-a-example-private/parent-assoc/assoc" {
		t.Errorf("associations = %v", got)
	}

	if rec.input(zoneType, "dns/env-a-example-private/zone", "name").StringValue() != "env-a.example.private." {
		t.Error("zone name must carry the trailing dot")
	}
}

func TestRootZoneHasNoDelegation(t *testing.T) {
	rec := &recorder{}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		p, err := provider(ctx, "p")
		if err != nil {
			return err
		}

		_, err = dns.DeployRootZone(ctx, quiet(), dns.RootZoneConfig{
			ZoneName: "example.private", Provider: p, Region: "region-a", BootstrapVPCID: pulumi.String("vpc-ref"),
		})

		return err
	}, pulumi.WithMocks("proj", "stack", rec))
	if err != nil {
		t.Fatal(err)
	}

	if got := rec.names(zoneType); strings.Join(got, ",") != "dns/example-private/zone" {
		t.Errorf("zones = %v", got)
	}

	if len(rec.names(recordType)) != 0 {
		t.Errorf("a root zone is not delegated: %v", rec.names(recordType))
	}
}

type fakeLB struct{ dns string }

func (f fakeLB) FindLoadBalancerDNS(context.Context, string, string) (string, error) {
	return f.dns, nil
}

func entry(lb dns.LoadBalancerFinder) dns.PrivateEntry {
	return dns.PrivateEntry{
		Cluster:           "env-a",
		ZoneID:            pulumi.String("zone-ref"),
		ZoneName:          "env-a.example.private",
		Address:           "192.0.2.20",
		Hosts:             []string{"gw.env-a.example.private"},
		CrossClusterHosts: []string{"vault.env-a.example.private"},
		LoadBalancerTag:   "ns/svc",
		LoadBalancers:     lb,
		Slug:              func(h string) string { return strings.ReplaceAll(h, ".", "-") },
	}
}

func runEntry(t *testing.T, e dns.PrivateEntry) (*recorder, error) {
	t.Helper()

	rec := &recorder{}
	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		return dns.DeployPrivateEntryRecords(ctx, quiet(), e)
	}, pulumi.WithMocks("proj", "stack", rec))

	return rec, err
}

func TestPrivateEntryRecords(t *testing.T) {
	rec, err := runEntry(t, entry(fakeLB{dns: "lb.example.test"}))
	if err != nil {
		t.Fatal(err)
	}

	want := "cross-cluster-vault-env-a-example-private,private-entry-gw-env-a-example-private"
	if got := strings.Join(rec.names(recordType), ","); got != want {
		t.Errorf("records = %s, want %s", got, want)
	}

	if rec.input(recordType, "cross-cluster-vault-env-a-example-private", "type").StringValue() != "CNAME" {
		t.Error("cross-cluster names are CNAMEs")
	}
}

func TestPrivateEntryMissingLoadBalancerSkipsCrossCluster(t *testing.T) {
	rec, err := runEntry(t, entry(fakeLB{}))
	if err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(rec.names(recordType), ","); got != "private-entry-gw-env-a-example-private" {
		t.Errorf("records = %s", got)
	}
}

func TestPrivateEntryRefusals(t *testing.T) {
	if err := dns.ValidatePrivateEntryHost("c", "z.example.private", "*.z.example.private"); err == nil ||
		!strings.Contains(err.Error(), "wildcard") {
		t.Errorf("wildcard not refused: %v", err)
	}

	if err := dns.ValidatePrivateEntryHost("c", "z.example.private", "x.other.private"); err == nil ||
		!strings.Contains(err.Error(), "not inside") {
		t.Errorf("foreign name not refused: %v", err)
	}

	if err := dns.ValidatePrivateEntryHost("c", "z.example.private", "z.example.private"); err != nil {
		t.Errorf("the zone's own name is inside it: %v", err)
	}

	e := entry(nil)
	if _, err := runEntry(t, e); err == nil || !strings.Contains(err.Error(), "load balancer finder") {
		t.Errorf("missing finder not refused: %v", err)
	}
}

func device(id, name, seen string, addrs ...string) dns.Device {
	return dns.Device{ID: id, Name: name, LastSeen: seen, Addresses: addrs}
}

func TestDeviceIPv4(t *testing.T) {
	got, err := dns.DeviceIPv4("d", []string{"fd00::1", "198.51.100.7"})
	if err != nil || got != "198.51.100.7" {
		t.Fatalf("got %q, %v", got, err)
	}

	if _, err := dns.DeviceIPv4("d", []string{"fd00::1"}); err == nil || !strings.Contains(err.Error(), "no IPv4") {
		t.Fatalf("v6-only not refused: %v", err)
	}
}

func TestPickDevice(t *testing.T) {
	if d, err := dns.PickDevice(nil); d != nil || err != nil {
		t.Fatalf("no devices: %v, %v", d, err)
	}

	older := device("old", "n1", "2026-01-01T09:00:00Z", "198.51.100.1")
	newer := device("new", "n2", "2026-01-01T10:00:00Z", "198.51.100.2")

	for _, order := range [][]dns.Device{{older, newer}, {newer, older}} {
		d, err := dns.PickDevice(order)
		if err != nil || d.ID != "new" {
			t.Fatalf("newest must win: %v, %v", d, err)
		}
	}

	tied := []dns.Device{older, device("b", "n3", older.LastSeen, "198.51.100.3")}
	if _, err := dns.PickDevice(tied); err == nil || !strings.Contains(err.Error(), "cannot tell which") {
		t.Fatalf("tie not refused: %v", err)
	}

	bad := []dns.Device{older, device("b", "n3", "not-a-time", "198.51.100.3")}
	if _, err := dns.PickDevice(bad); err == nil || !strings.Contains(err.Error(), "unparseable lastSeen") {
		t.Fatalf("bad timestamp not refused: %v", err)
	}
}

func TestDeviceRecord(t *testing.T) {
	run := func(devs []dns.Device) (*recorder, error) {
		rec := &recorder{}
		err := pulumi.RunErr(func(ctx *pulumi.Context) error {
			p, err := provider(ctx, "p")
			if err != nil {
				return err
			}

			return dns.NewDeviceRecord(ctx, quiet(), dns.DeviceRecord{
				ResourceName: "box-endpoint", Name: "box.example.private", ZoneID: pulumi.String("zone-ref"),
				Provider: p, Candidates: devs, Label: "box",
			})
		}, pulumi.WithMocks("proj", "stack", rec))

		return rec, err
	}

	rec, err := run([]dns.Device{device("a", "n1", "2026-01-01T10:00:00Z", "198.51.100.9", "fd00::1")})
	if err != nil {
		t.Fatal(err)
	}

	if got := rec.names(recordType); len(got) != 1 || got[0] != "box-endpoint" {
		t.Fatalf("records = %v", got)
	}

	if rec.input(recordType, "box-endpoint", "type").StringValue() != "A" {
		t.Error("device record is an A record")
	}

	rec, err = run(nil)
	if err != nil || len(rec.names(recordType)) != 0 {
		t.Fatalf("no device means no record and no error: %v %v", rec.names(recordType), err)
	}
}
