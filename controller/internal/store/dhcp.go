package store

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/rqlite/gorqlite"
)

// The leases of the DHCP responders of the L2 Networks (SDN-43, #236): one row per lease, as the
// node that answers DHCP for its Network reported it last (Leases of the control protocol). Each
// report replaces the leases of its node and Network as a whole. They are not part of the intent,
// so a revision, a rollback or an import never changes them; a store backup holds them.
func init() {
	RegisterSchema("dhcp_leases", `CREATE TABLE IF NOT EXISTS dhcp_leases (network TEXT NOT NULL, node TEXT NOT NULL, mac TEXT NOT NULL, `+
		`address TEXT NOT NULL, expires INTEGER NOT NULL, host_name TEXT NOT NULL, PRIMARY KEY (network, node, mac))`)
}

// DHCPLease is one lease of the DHCP responder of an L2 Network: the address that a client of the
// Network holds until Expires, as the node that answers DHCP for the Network reported it.
type DHCPLease struct {
	Network  string     `json:"network"`
	Node     string     `json:"node"`
	MAC      string     `json:"mac"` // the client's MAC address, as 02:00:5e:10:00:01
	Address  netip.Addr `json:"address"`
	Expires  time.Time  `json:"expires"`
	HostName string     `json:"hostName,omitempty"` // the host name that the client sent, DHCP option 12
}

// DHCPLeases returns every stored lease, ordered by Network, then address.
func (s *Store) DHCPLeases(ctx context.Context) ([]DHCPLease, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT network, node, mac, address, expires, host_name FROM dhcp_leases`)
	if err != nil {
		return nil, fmt.Errorf("store: reading the DHCP leases: %w", err)
	}
	out := []DHCPLease{}
	for qr.Next() {
		var l DHCPLease
		var address string
		var expires int64
		if err := qr.Scan(&l.Network, &l.Node, &l.MAC, &address, &expires, &l.HostName); err != nil {
			return nil, fmt.Errorf("store: reading the DHCP leases: %w", err)
		}
		if l.Address, err = netip.ParseAddr(address); err != nil {
			return nil, fmt.Errorf("store: the DHCP lease of %s in Network %q: %w", l.MAC, l.Network, err)
		}
		l.Expires = time.UnixMilli(expires).UTC()
		out = append(out, l)
	}
	slices.SortFunc(out, func(a, b DHCPLease) int {
		return cmp.Or(cmp.Compare(a.Network, b.Network), a.Address.Compare(b.Address), cmp.Compare(a.Node, b.Node), cmp.Compare(a.MAC, b.MAC))
	})
	return out, nil
}

// SetDHCPLeases replaces the leases that the node node reported for the Network network with
// leases, which hold no MAC address twice, in one transaction.
func (s *Store) SetDHCPLeases(ctx context.Context, node, network string, leases []DHCPLease) error {
	stmts := []gorqlite.ParameterizedStatement{statement(`DELETE FROM dhcp_leases WHERE node = ? AND network = ?`, node, network)}
	for _, l := range leases {
		stmts = append(stmts, statement(`INSERT OR REPLACE INTO dhcp_leases (network, node, mac, address, expires, host_name) VALUES (?, ?, ?, ?, ?, ?)`,
			network, node, l.MAC, l.Address.String(), l.Expires.UnixMilli(), l.HostName))
	}
	if err := s.write(ctx, stmts); err != nil {
		return fmt.Errorf("store: writing the DHCP leases of node %q in Network %q: %w", node, network, err)
	}
	return nil
}
