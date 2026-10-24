package desired

import (
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// zone returns the zone of overlay DNS of the VRF vrf as its members get it in the Vrf object
// (SDN-11 #187, ADR-0028 decisions 6 and 7, intent/dns.go): its suffix and its DnsRecord resources
// ordered by name, each with the bytes of the addresses it answers; nil while overlay DNS is off in
// the VRF. The name of each node of the VRF is no record of the zone: a node answers it from the
// addresses of its peers and its own, which its state holds.
func zone(in intent.Intent, vrf string) *controlpb.DnsZone {
	suffix, records, ok := in.Zone(vrf)
	if !ok {
		return nil
	}
	z := &controlpb.DnsZone{Suffix: suffix}
	for _, r := range records {
		rec := &controlpb.DnsRecord{Name: r.Name}
		for _, a := range r.Addresses {
			rec.Addresses = append(rec.Addresses, a.AsSlice())
		}
		z.Records = append(z.Records, rec)
	}
	return z
}
