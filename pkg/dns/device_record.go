package dns

import (
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"time"

	pulumiaws "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/route53"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// deviceRecordTTL matches privateEntryRecordTTL's reasoning: short, because
// the first thing anybody does when a private name is wrong is change it and
// try again.
const deviceRecordTTL = 60

// Device is one candidate for a DeviceRecord: what a network's device list
// says about a machine, reduced to what choosing among them needs.
type Device struct {
	ID   string
	Name string
	// LastSeen is an RFC 3339 timestamp.
	LastSeen string
	// Addresses are the device's addresses, IPv4 and IPv6 alike.
	Addresses []string
}

// DeviceRecord configures NewDeviceRecord.
type DeviceRecord struct {
	// ResourceName is the record's logical name. Required.
	ResourceName string
	// Name is the record's DNS name. Required.
	Name string
	// ZoneID is the zone the record goes in. Required.
	ZoneID pulumi.StringInput
	// Provider is the AWS provider of the zone's account. Required.
	Provider *pulumiaws.Provider
	// Candidates are every device that may carry the name. PickDevice chooses
	// the live one among them.
	Candidates []Device
	// Label names the machine in messages ("status box").
	Label string
}

// NewDeviceRecord writes Name as an A record to the IPv4 address of the live
// device among Candidates.
//
// The device may not exist yet (it has not been deployed for the first time,
// or is mid-replacement): then nothing is written, with a warning, and the
// record appears on the next run. This must not fail the whole apply. A
// replacement instance joins under the same hostname with a fresh address, so
// the record goes stale until the stack runs again; that is the price of an A
// record, which the zone's VPC resolver can follow where it could not follow a
// CNAME to a name only the device's own network resolves.
func NewDeviceRecord(c *pulumi.Context, logger *slog.Logger, r DeviceRecord) error {
	goCtx := c.Context()

	device, err := PickDevice(r.Candidates)
	if err != nil {
		return fmt.Errorf("%s record: %w", r.Label, err)
	}

	if device == nil {
		logger.WarnContext(goCtx, r.Label+" device not found yet; skipping its DNS record",
			slog.String("record", r.Name),
			slog.String("rerun_after", "the device has been deployed (or finished replacing itself)"))

		return nil
	}

	address, err := DeviceIPv4(device.Name, device.Addresses)
	if err != nil {
		return fmt.Errorf("%s record: %w", r.Label, err)
	}

	if _, err := route53.NewRecord(c, r.ResourceName, &route53.RecordArgs{
		ZoneId:  r.ZoneID,
		Name:    pulumi.String(r.Name),
		Type:    pulumi.String("A"),
		Ttl:     pulumi.Int(deviceRecordTTL),
		Records: pulumi.StringArray{pulumi.String(address)},
	}, pulumi.Provider(r.Provider)); err != nil {
		return fmt.Errorf("%s record: %w", r.Label, err)
	}

	logger.InfoContext(goCtx, r.Label+" record written",
		slog.String("name", r.Name),
		slog.String("address", address),
	)

	return nil
}

// PickDevice chooses the live device among the candidates. Zero candidates
// returns nil, nil. One is unambiguous.
//
// Two or more means a replacement is in flight: the old, now-offline device has
// not expired yet and the new one has already joined. The only signal a device
// list gives is LastSeen, so the most recently seen device wins. If the top
// LastSeen is tied, this REFUSES rather than guess which device is live: re-run
// once the older, offline device expires and the tie resolves itself.
func PickDevice(devices []Device) (*Device, error) {
	if len(devices) == 0 {
		return nil, nil
	}

	if len(devices) == 1 {
		return &devices[0], nil
	}

	type candidate struct {
		device   *Device
		lastSeen time.Time
	}

	candidates := make([]candidate, 0, len(devices))

	for i := range devices {
		d := &devices[i]

		lastSeen, err := time.Parse(time.RFC3339, d.LastSeen)
		if err != nil {
			return nil, fmt.Errorf("device %s (%s): unparseable lastSeen %q: %w", d.Name, d.ID, d.LastSeen, err)
		}

		candidates = append(candidates, candidate{device: d, lastSeen: lastSeen})
	}

	sort.Slice(candidates, func(i, j int) bool { return candidates[i].lastSeen.After(candidates[j].lastSeen) })

	if candidates[0].lastSeen.Equal(candidates[1].lastSeen) {
		return nil, fmt.Errorf(
			"%d candidate devices (including %s and %s) share the same lastSeen (%s): "+
				"cannot tell which is the live device — re-run after the older, offline device expires",
			len(devices), candidates[0].device.Name, candidates[1].device.Name, candidates[0].lastSeen.Format(time.RFC3339))
	}

	return candidates[0].device, nil
}

// DeviceIPv4 picks the device's IPv4 address out of addresses, which also
// carries its IPv6 one: an A record needs the former specifically, never
// whichever comes first.
func DeviceIPv4(device string, addresses []string) (string, error) {
	for _, raw := range addresses {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}

		if addr.Is4() {
			return addr.String(), nil
		}
	}

	return "", fmt.Errorf("device %q has no IPv4 address (addresses: %v)", device, addresses)
}
