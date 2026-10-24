// NodeDhcp.c
// The DHCP responder of an L2 Network (SDN-43, #236; ADR-0028). When the LAN that an L2 Network is bridged to has no
// DHCP server, the node that the controller names answers the DHCP clients of the Network from the Network's IPv4
// pool, which stays the controller's: the desired state of that node carries the responder in the Network object
// (CONTROL_DHCP of Core/Control.h) with the pool, the responder's own address, the gateway and the DNS servers that the
// clients get, the lease time and the reservations of the Network. The responder gives no client the first or the last
// address of the pool, a reservation, the gateway, a DNS server or its own address.
//
// A responder (NODE_DHCP) is a member of the switch of its Network (Core/Switch.h) with a MAC address of its own: it
// takes the frames that the switch delivers to its port (NodeDhcpInput) and gives the frames that it sends
// (NodeDhcpOutput). Time is the caller's, in ms, as for the switch. Before it answers a client it looks for a DHCP
// server of the LAN: it sends a DHCPDISCOVER of its own, a probe, waits NODE_DHCP_PROBE_WAIT for the answers, and
// probes again every NODE_DHCP_PROBE_TIME. While a DHCP server of the LAN answered within NODE_DHCP_LAN_HOLD, to its
// probe or to a client, the responder answers nobody, so a Network bridged to a LAN with DHCP keeps the LAN's server.
// Otherwise it answers DHCPDISCOVER with DHCPOFFER and DHCPREQUEST with DHCPACK or DHCPNAK (RFC 2131 4.3), takes
// DHCPDECLINE and DHCPRELEASE, answers DHCPINFORM, and answers the ARP requests for its own address, so a client can
// renew by unicast. Its lease table holds NODE_DHCP_MAX_LEASES entries at most: its offers, its leases and the
// addresses that clients declined. A responder whose mode is not pool answers nothing and sends nothing.
//
// The node keeps one responder for each Network whose object in its desired state carries one (NodeDhcpApplied), puts
// it on the switch of the Network once the L2 data path attached that switch (NodeDhcpAttach), sends its frames into
// the switch on a thread of its own, and reports its leases on the control stream whenever they change
// (ControlSetLeases), so the controller lists them with IPAM. A Network that the state no longer gives a responder has
// none on the node.

#include "Node.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"

#include "Core/Control.h"
#include "Core/Switch.h"

#include "NodeInternal.h"

#define NODE_DHCP_SERVER_PORT 67     // The UDP port of a DHCP server ...
#define NODE_DHCP_CLIENT_PORT 68     // ... and of a client
#define NODE_DHCP_BOOTREQUEST 1      // The op of the message of a client ...
#define NODE_DHCP_BOOTREPLY   2      // ... and of a server
#define NODE_DHCP_BROADCAST   0x8000 // The flag of a client that takes the answers by broadcast only (RFC 2131 4.1)
#define NODE_DHCP_TTL         64     // The TTL of the packets of the responder
#define NODE_DHCP_COOKIE_AT   236    // The magic cookie of a message: after the fixed header, sname and file
#define NODE_DHCP_FIXED       240    // ... and the options after it

// The kinds of an entry of the lease table
#define NODE_DHCP_OFFERED  1 // An address that the responder offered a client
#define NODE_DHCP_BOUND    2 // A lease
#define NODE_DHCP_DECLINED 3 // An address that a client declined, as another host uses it

// One entry of the lease table
typedef struct NODE_DHCP_ENTRY {
	UINT Kind;         // NODE_DHCP_OFFERED, NODE_DHCP_BOUND or NODE_DHCP_DECLINED
	UCHAR Mac[6];      // The client's MAC address; zero for a declined address
	UINT Address;      // The address, in host byte order
	UINT64 Expires;    // When the entry ends, in the ms of the caller
	char HostName[64]; // The host name that the client sent (option 12), printable ASCII
} NODE_DHCP_ENTRY;

// A frame that waits to be sent
typedef struct NODE_DHCP_FRAME {
	UINT Size;                       // Its bytes
	UCHAR Data[NODE_DHCP_MAX_FRAME]; // ...
} NODE_DHCP_FRAME;

// The DHCP responder of one L2 Network
struct NODE_DHCP {
	LOCK *Lock;                // Everything below
	NODE_DHCP_CONFIG Config;   // How it runs
	bool Valid;                // The configuration serves: the mode is pool, the pool a /16 to a /30, its own address a host address of it
	UINT First;                // The first address of the pool, in host byte order ...
	UINT Last;                 // ... and its last
	UINT NumEntries;           // The lease table
	NODE_DHCP_ENTRY *Entries;  // ... room for NODE_DHCP_MAX_LEASES entries
	UINT QueueHead;            // The frames that wait to be sent: the oldest ...
	UINT QueueSize;            // ... and their number
	NODE_DHCP_FRAME *Queue;    // ... in a ring of NODE_DHCP_MAX_QUEUE
	bool Probed;               // It sent its first probe since it serves ...
	UINT64 FirstProbe;         // ... at this time
	UINT64 NextProbe;          // When it sends its next probe
	UINT ProbeXid;             // The transaction id of its probes
	bool LanSeen;              // A DHCP server of the LAN answered ...
	UINT64 LanAnswer;          // ... last at this time
	USHORT IpId;               // The identification of its next IPv4 packet
	NODE_DHCP_STATUS Counters; // Its counters: Probes to LanAnswers, and Changes
};

// The broadcast address of Ethernet
static const UCHAR node_dhcp_broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

//
// The configuration and the lease table
//

// The mask of the prefix length length, 0 to 32
static UINT NodeDhcpMask(UINT length) {
	return (length == 0 ? 0 : 0xFFFFFFFFU << (32 - MIN(length, 32)));
}

// Whether a configuration serves: the mode is pool, the pool a /16 to a /30, the lease time not 0, the MAC address of
// the responder a unicast one and its own address a host address of the pool
static bool NodeDhcpConfigOk(const NODE_DHCP_CONFIG *c) {
	if (c->Serve == false || c->PoolLength < NODE_DHCP_MIN_POOL || c->PoolLength > NODE_DHCP_MAX_POOL || c->LeaseTime == 0)
		return false;
	if ((c->Mac[0] & 0x01) != 0 || IsZero(c->Mac, 6))
		return false;

	UINT mask = NodeDhcpMask(c->PoolLength);
	UINT first = c->Pool & mask;
	UINT last = first | ~mask;

	return c->Address > first && c->Address < last;
}

// Whether the responder may give a client the address a: a host address of the pool that is not its own address, the
// gateway, a DNS server or in a reservation of the Network
static bool NodeDhcpUsable(const NODE_DHCP *d, UINT a) {
	const NODE_DHCP_CONFIG *c = &d->Config;

	if (a <= d->First || a >= d->Last || a == c->Address || a == c->Gateway)
		return false;
	for (UINT i = 0; i < c->NumDns; i++) {
		if (a == c->Dns[i])
			return false;
	}
	for (UINT i = 0; i < c->NumReserved; i++) {
		UINT mask = NodeDhcpMask(c->ReservedLength[i]);

		if ((a & mask) == (c->ReservedAddress[i] & mask))
			return false;
	}

	return true;
}

// The last address of the reservation that holds the address a, 0 when none does
static UINT NodeDhcpReservedEnd(const NODE_DHCP *d, UINT a) {
	UINT end = 0;

	for (UINT i = 0; i < d->Config.NumReserved; i++) {
		UINT mask = NodeDhcpMask(d->Config.ReservedLength[i]);

		if ((a & mask) == (d->Config.ReservedAddress[i] & mask))
			end = MAX(end, (a & mask) | ~mask);
	}

	return end;
}

// The entry of the client mac, NULL for none
static NODE_DHCP_ENTRY *NodeDhcpByMac(NODE_DHCP *d, const UCHAR *mac) {
	for (UINT i = 0; i < d->NumEntries; i++) {
		NODE_DHCP_ENTRY *e = &d->Entries[i];

		if (e->Kind != NODE_DHCP_DECLINED && Cmp(e->Mac, mac, 6) == 0)
			return e;
	}

	return NULL;
}

// The entry that holds the address a, NULL for none
static NODE_DHCP_ENTRY *NodeDhcpByAddress(NODE_DHCP *d, UINT a) {
	for (UINT i = 0; i < d->NumEntries; i++) {
		if (d->Entries[i].Address == a)
			return &d->Entries[i];
	}

	return NULL;
}

// Whether the client mac may hold the address a: the responder may give it, and no entry of another client and no
// declined address holds it
static bool NodeDhcpAvailable(NODE_DHCP *d, UINT a, const UCHAR *mac) {
	if (NodeDhcpUsable(d, a) == false)
		return false;

	NODE_DHCP_ENTRY *e = NodeDhcpByAddress(d, a);
	return e == NULL || (e->Kind != NODE_DHCP_DECLINED && Cmp(e->Mac, mac, 6) == 0);
}

// Take the entry e out of the lease table
static void NodeDhcpRemove(NODE_DHCP *d, NODE_DHCP_ENTRY *e) {
	UINT i = (UINT)(e - d->Entries);

	if (i + 1 < d->NumEntries)
		Copy(e, &d->Entries[d->NumEntries - 1], sizeof(NODE_DHCP_ENTRY));
	d->NumEntries--;
}

// Take out the entries that ended at now: each lease among them is a change
static void NodeDhcpExpire(NODE_DHCP *d, UINT64 now) {
	UINT i = 0;

	while (i < d->NumEntries) {
		NODE_DHCP_ENTRY *e = &d->Entries[i];

		if (now < e->Expires) {
			i++;
			continue;
		}
		if (e->Kind == NODE_DHCP_BOUND)
			d->Counters.Changes++;
		NodeDhcpRemove(d, e);
	}
}

// The host name of the options o into the entry e: option 12, its printable ASCII characters but the space; the one
// before when the client sent none
static void NodeDhcpHostName(NODE_DHCP_ENTRY *e, LIST *o) {
	DHCP_OPTION *opt = GetDhcpOption(o, DHCP_ID_HOST_NAME);
	UINT k = 0;

	if (opt == NULL)
		return;

	for (UINT i = 0; i < opt->Size && k < sizeof(e->HostName) - 1; i++) {
		UCHAR c = ((UCHAR *)opt->Data)[i];

		if (c > 0x20 && c < 0x7F)
			e->HostName[k++] = (char)c;
	}
	e->HostName[k] = 0;
}

// An IPv4 address option of the options o in host byte order, 0 when there is none of 4 bytes
static UINT NodeDhcpOptionAddress(LIST *o, UINT id) {
	DHCP_OPTION *opt = GetDhcpOption(o, id);

	return (opt != NULL && opt->Size == 4 ? READ_UINT(opt->Data) : 0);
}

// The responder answers clients at now: its configuration serves, its first probe went NODE_DHCP_PROBE_WAIT ago, and no
// DHCP server of the LAN answered within NODE_DHCP_LAN_HOLD
static bool NodeDhcpServing(const NODE_DHCP *d, UINT64 now) {
	if (d->Valid == false || d->Probed == false || now < d->FirstProbe + NODE_DHCP_PROBE_WAIT)
		return false;

	return d->LanSeen == false || now >= d->LanAnswer + NODE_DHCP_LAN_HOLD;
}

// The responder starts anew: it sends none of the frames that wait and probes before it answers a client
static void NodeDhcpReset(NODE_DHCP *d) {
	d->QueueHead = 0;
	d->QueueSize = 0;
	d->Probed = false;
}

//
// The frames
//

// Queue a frame: false when the queue is full
static bool NodeDhcpQueue(NODE_DHCP *d, const UCHAR *frame, UINT size) {
	if (d->QueueSize >= NODE_DHCP_MAX_QUEUE || size > NODE_DHCP_MAX_FRAME)
		return false;

	NODE_DHCP_FRAME *f = &d->Queue[(d->QueueHead + d->QueueSize) % NODE_DHCP_MAX_QUEUE];
	Copy(f->Data, frame, size);
	f->Size = size;
	d->QueueSize++;

	return true;
}

// Queue the UDP datagram of size bytes from src_ip:src_port to dst_ip:dst_port, in a frame to dst_mac; the addresses
// in host byte order
static bool NodeDhcpSendUdp(NODE_DHCP *d, const UCHAR *dst_mac, UINT src_ip, USHORT src_port, UINT dst_ip, USHORT dst_port, const UCHAR *data, UINT size) {
	UCHAR frame[NODE_DHCP_MAX_FRAME];
	UINT total = sizeof(MAC_HEADER) + sizeof(IPV4_HEADER) + sizeof(UDP_HEADER) + size;

	if (total > sizeof(frame))
		return false;

	MAC_HEADER *mac = (MAC_HEADER *)frame;
	IPV4_HEADER *ip = (IPV4_HEADER *)(frame + sizeof(MAC_HEADER));
	UDP_HEADER *udp = (UDP_HEADER *)(frame + sizeof(MAC_HEADER) + sizeof(IPV4_HEADER));

	Zero(frame, total);
	Copy(mac->DestAddress, dst_mac, 6);
	Copy(mac->SrcAddress, d->Config.Mac, 6);
	mac->Protocol = Endian16(MAC_PROTO_IPV4);

	IPV4_SET_VERSION(ip, 4);
	IPV4_SET_HEADER_LEN(ip, 5);
	ip->TotalLength = Endian16((USHORT)(sizeof(IPV4_HEADER) + sizeof(UDP_HEADER) + size));
	ip->Identification = Endian16(d->IpId++);
	ip->TimeToLive = NODE_DHCP_TTL;
	ip->Protocol = IP_PROTO_UDP;
	ip->SrcIP = Endian32(src_ip);
	ip->DstIP = Endian32(dst_ip);
	ip->Checksum = IpChecksum(ip, sizeof(IPV4_HEADER));

	udp->SrcPort = Endian16(src_port);
	udp->DstPort = Endian16(dst_port);
	udp->PacketLength = Endian16((USHORT)(sizeof(UDP_HEADER) + size));
	Copy(((UCHAR *)udp) + sizeof(UDP_HEADER), data, size);
	USHORT sum = CalcChecksumForIPv4(ip->SrcIP, ip->DstIP, IP_PROTO_UDP, udp, sizeof(UDP_HEADER) + size, 0);
	// A checksum of 0 says that there is none (RFC 768)
	udp->Checksum = (sum == 0 ? 0xFFFF : sum);

	return NodeDhcpQueue(d, frame, total);
}

// A DHCP message: the fixed header of op, xid, flags, ciaddr, yiaddr and chaddr, the magic cookie and the options o,
// padded to DHCP_MIN_SIZE; its size in buf, 0 when it does not fit
static UINT NodeDhcpBuild(UCHAR *buf, UINT size, UCHAR op, UINT xid, USHORT flags, UINT ciaddr, UINT yiaddr, const UCHAR *chaddr, LIST *o) {
	BUF *b = BuildDhcpOptionsBuf(o);
	UINT ret = 0;

	if (b != NULL && NODE_DHCP_FIXED + b->Size <= size) {
		DHCPV4_HEADER *h = (DHCPV4_HEADER *)buf;

		ret = MAX(NODE_DHCP_FIXED + b->Size, DHCP_MIN_SIZE);
		ret = MIN(ret, size);
		Zero(buf, ret);
		h->OpCode = op;
		h->HardwareType = ARP_HARDWARE_TYPE_ETHERNET;
		h->HardwareAddressSize = 6;
		h->TransactionId = xid;
		h->Flags = flags;
		h->ClientIP = Endian32(ciaddr);
		h->YourIP = Endian32(yiaddr);
		Copy(h->ClientMacAddress, chaddr, 6);
		WRITE_UINT(buf + NODE_DHCP_COOKIE_AT, DHCP_MAGIC_COOKIE);
		Copy(buf + NODE_DHCP_FIXED, b->Buf, b->Size);
	}

	FreeBuf(b);
	return ret;
}

// Add the option id with an IPv4 address of host byte order
static void NodeDhcpAddAddress(LIST *o, UINT id, UINT a) {
	UCHAR be[4];

	WRITE_UINT(be, a);
	Add(o, NewDhcpOption(id, be, 4));
}

// Queue the answer of the message type type to the request req of a client: yiaddr the address it gives, 0 for none;
// with lease, the lease time and the renewal and rebinding times. A DHCPNAK, and an answer to a client without an
// address that asked for broadcast, goes to the broadcast address; an answer to a client with an address to that
// address, and any other to the address it gives, at the client's MAC address (RFC 2131 4.1).
static bool NodeDhcpReply(NODE_DHCP *d, const DHCPV4_HEADER *req, UCHAR type, UINT yiaddr, bool lease) {
	const NODE_DHCP_CONFIG *c = &d->Config;
	UCHAR msg[NODE_DHCP_MAX_FRAME - sizeof(MAC_HEADER) - sizeof(IPV4_HEADER) - sizeof(UDP_HEADER)];
	UINT ciaddr = Endian32(req->ClientIP);
	LIST *o = NewListFast(NULL);

	Add(o, NewDhcpOption(DHCP_ID_MESSAGE_TYPE, &type, 1));
	NodeDhcpAddAddress(o, DHCP_ID_SERVER_ID, c->Address);
	if (type != DHCP_NAK) {
		if (lease) {
			NodeDhcpAddAddress(o, DHCP_ID_LEASE_TIME, c->LeaseTime);
			NodeDhcpAddAddress(o, DHCP_ID_RENEWAL_TIME, c->LeaseTime / 2);
			NodeDhcpAddAddress(o, DHCP_ID_REBINDING_TIME, (UINT)((UINT64)c->LeaseTime * 7 / 8));
		}
		NodeDhcpAddAddress(o, DHCP_ID_SUBNET_MASK, NodeDhcpMask(c->PoolLength));
		if (c->Gateway != 0)
			NodeDhcpAddAddress(o, DHCP_ID_GATEWAY_ADDR, c->Gateway);
		if (c->NumDns != 0) {
			UCHAR dns[NODE_DHCP_MAX_DNS * 4];

			for (UINT i = 0; i < c->NumDns; i++)
				WRITE_UINT(dns + i * 4, c->Dns[i]);
			Add(o, NewDhcpOption(DHCP_ID_DNS_ADDR, dns, c->NumDns * 4));
		}
	}

	// ciaddr goes back in a DHCPACK only (RFC 2131 table 3)
	UINT size = NodeDhcpBuild(msg, (UINT)sizeof(msg), NODE_DHCP_BOOTREPLY, req->TransactionId, req->Flags, (type == DHCP_ACK ? ciaddr : 0), yiaddr, req->ClientMacAddress, o);
	FreeDhcpOptions(o);
	if (size == 0)
		return false;

	if (type == DHCP_NAK || (ciaddr == 0 && (Endian16(req->Flags) & NODE_DHCP_BROADCAST) != 0))
		return NodeDhcpSendUdp(d, node_dhcp_broadcast, c->Address, NODE_DHCP_SERVER_PORT, 0xFFFFFFFF, NODE_DHCP_CLIENT_PORT, msg, size);

	return NodeDhcpSendUdp(d, req->ClientMacAddress, c->Address, NODE_DHCP_SERVER_PORT, (ciaddr != 0 ? ciaddr : yiaddr), NODE_DHCP_CLIENT_PORT, msg, size);
}

// Queue a probe: a DHCPDISCOVER from the responder's own MAC address that asks for answers by broadcast, which a DHCP
// server of the LAN answers
static void NodeDhcpProbe(NODE_DHCP *d) {
	UCHAR msg[NODE_DHCP_MAX_FRAME - sizeof(MAC_HEADER) - sizeof(IPV4_HEADER) - sizeof(UDP_HEADER)];
	UCHAR type = DHCP_DISCOVER;
	LIST *o = NewListFast(NULL);

	Add(o, NewDhcpOption(DHCP_ID_MESSAGE_TYPE, &type, 1));
	UINT size = NodeDhcpBuild(msg, (UINT)sizeof(msg), NODE_DHCP_BOOTREQUEST, Endian32(d->ProbeXid + (UINT)d->Counters.Probes), Endian16(NODE_DHCP_BROADCAST), 0, 0, d->Config.Mac, o);
	FreeDhcpOptions(o);

	if (size != 0 && NodeDhcpSendUdp(d, node_dhcp_broadcast, 0, NODE_DHCP_CLIENT_PORT, 0xFFFFFFFF, NODE_DHCP_SERVER_PORT, msg, size))
		d->Counters.Probes++;
}

// Answer an ARP request for the responder's own address
static void NodeDhcpArp(NODE_DHCP *d, const ARPV4_HEADER *a) {
	UCHAR frame[sizeof(MAC_HEADER) + sizeof(ARPV4_HEADER)];
	MAC_HEADER *mac = (MAC_HEADER *)frame;
	ARPV4_HEADER *r = (ARPV4_HEADER *)(frame + sizeof(MAC_HEADER));

	if (Endian16(a->HardwareType) != ARP_HARDWARE_TYPE_ETHERNET || Endian16(a->ProtocolType) != MAC_PROTO_IPV4 || a->HardwareSize != 6 || a->ProtocolSize != 4 || Endian16(a->Operation) != ARP_OPERATION_REQUEST || Endian32(a->TargetIP) != d->Config.Address)
		return;

	Copy(mac->DestAddress, a->SrcAddress, 6);
	Copy(mac->SrcAddress, d->Config.Mac, 6);
	mac->Protocol = Endian16(MAC_PROTO_ARPV4);
	r->HardwareType = Endian16(ARP_HARDWARE_TYPE_ETHERNET);
	r->ProtocolType = Endian16(MAC_PROTO_IPV4);
	r->HardwareSize = 6;
	r->ProtocolSize = 4;
	r->Operation = Endian16(ARP_OPERATION_RESPONSE);
	Copy(r->SrcAddress, d->Config.Mac, 6);
	r->SrcIP = Endian32(d->Config.Address);
	Copy(r->TargetAddress, a->SrcAddress, 6);
	r->TargetIP = a->SrcIP;

	if (NodeDhcpQueue(d, frame, sizeof(frame)))
		d->Counters.Arps++;
}

//
// The messages of the clients
//

// The address that the responder offers the client mac: the one its entry holds, the one it asked for when that is free,
// else the lowest free address of the pool; 0 when none is free or the lease table has no room for the client
static UINT NodeDhcpPick(NODE_DHCP *d, const UCHAR *mac, UINT requested) {
	NODE_DHCP_ENTRY *e = NodeDhcpByMac(d, mac);

	if (e != NULL && NodeDhcpUsable(d, e->Address))
		return e->Address;
	if (e == NULL && d->NumEntries >= NODE_DHCP_MAX_LEASES)
		return 0;
	if (requested != 0 && NodeDhcpAvailable(d, requested, mac))
		return requested;

	for (UINT a = d->First + 1; a < d->Last; a++) {
		UINT end = NodeDhcpReservedEnd(d, a);

		if (end != 0) {
			// The reservation as a whole
			if (end >= d->Last)
				break;
			a = end;
			continue;
		}
		if (NodeDhcpAvailable(d, a, mac))
			return a;
	}

	return 0;
}

// Give the client mac the lease of the address a from now: one more change
static void NodeDhcpBind(NODE_DHCP *d, UINT64 now, NODE_DHCP_ENTRY *e, const UCHAR *mac, UINT a, LIST *o) {
	if (e == NULL) {
		e = &d->Entries[d->NumEntries++];
		Zero(e, sizeof(NODE_DHCP_ENTRY));
		Copy(e->Mac, mac, 6);
	}

	e->Kind = NODE_DHCP_BOUND;
	e->Address = a;
	e->Expires = now + (UINT64)d->Config.LeaseTime * 1000;
	NodeDhcpHostName(e, o);
	d->Counters.Changes++;
}

// DHCPDISCOVER: a DHCPOFFER of a free address, which stays the client's for NODE_DHCP_OFFER_TIME
static void NodeDhcpDiscover(NODE_DHCP *d, UINT64 now, const DHCPV4_HEADER *h, LIST *o) {
	const UCHAR *mac = h->ClientMacAddress;
	UINT a = NodeDhcpPick(d, mac, NodeDhcpOptionAddress(o, DHCP_ID_REQUEST_IP_ADDRESS));

	if (a == 0) {
		d->Counters.Ignored++;
		return;
	}

	NODE_DHCP_ENTRY *e = NodeDhcpByMac(d, mac);
	if (e == NULL) {
		e = &d->Entries[d->NumEntries++];
		Zero(e, sizeof(NODE_DHCP_ENTRY));
		Copy(e->Mac, mac, 6);
		e->Kind = NODE_DHCP_OFFERED;
	}
	// A client that holds a lease keeps it until it asks for the address again
	if (e->Kind != NODE_DHCP_BOUND || e->Address != a) {
		if (e->Kind == NODE_DHCP_BOUND)
			d->Counters.Changes++;
		e->Kind = NODE_DHCP_OFFERED;
		e->Address = a;
		e->Expires = now + NODE_DHCP_OFFER_TIME;
	}
	NodeDhcpHostName(e, o);

	if (NodeDhcpReply(d, h, DHCP_OFFER, a, true))
		d->Counters.Offers++;
}

// DHCPREQUEST (RFC 2131 4.3.2): the answer to an offer when it names a server, else the check of an address that the
// client knows (INIT-REBOOT) or the renewal of its lease (RENEWING, REBINDING). A DHCPACK gives the lease; a DHCPNAK
// tells the client that the address is not its own.
static void NodeDhcpRequest(NODE_DHCP *d, UINT64 now, const DHCPV4_HEADER *h, LIST *o) {
	const UCHAR *mac = h->ClientMacAddress;
	DHCP_OPTION *server = GetDhcpOption(o, DHCP_ID_SERVER_ID);
	UINT requested = NodeDhcpOptionAddress(o, DHCP_ID_REQUEST_IP_ADDRESS);
	UINT ciaddr = Endian32(h->ClientIP);
	NODE_DHCP_ENTRY *e = NodeDhcpByMac(d, mac);
	UINT a = 0;
	bool ok = false;

	if (server != NULL) {
		// SELECTING: an offer of another server took the client, and the responder's offer goes
		if (server->Size != 4 || READ_UINT(server->Data) != d->Config.Address) {
			if (e != NULL && e->Kind == NODE_DHCP_OFFERED)
				NodeDhcpRemove(d, e);
			d->Counters.Ignored++;
			return;
		}
		a = (requested != 0 ? requested : ciaddr);
		ok = (e != NULL && e->Address == a && NodeDhcpUsable(d, a));
	} else if (requested != 0 || ciaddr != 0) {
		// INIT-REBOOT with the address it asks for, RENEWING and REBINDING with the address it holds
		a = (requested != 0 ? requested : ciaddr);
		ok = NodeDhcpAvailable(d, a, mac);
		if (ok && e == NULL && d->NumEntries >= NODE_DHCP_MAX_LEASES) {
			d->Counters.Ignored++;
			return;
		}
	} else {
		d->Counters.Ignored++;
		return;
	}

	if (ok == false) {
		if (NodeDhcpReply(d, h, DHCP_NAK, 0, false))
			d->Counters.Naks++;
		return;
	}

	NodeDhcpBind(d, now, e, mac, a, o);
	if (NodeDhcpReply(d, h, DHCP_ACK, a, true))
		d->Counters.Acks++;
}

// DHCPDECLINE: another host uses the address that the client got, which stays out of use for NODE_DHCP_DECLINE_TIME
static void NodeDhcpDecline(NODE_DHCP *d, UINT64 now, const DHCPV4_HEADER *h, LIST *o) {
	NODE_DHCP_ENTRY *e = NodeDhcpByMac(d, h->ClientMacAddress);

	if (NodeDhcpOptionAddress(o, DHCP_ID_SERVER_ID) != d->Config.Address || e == NULL || e->Address != NodeDhcpOptionAddress(o, DHCP_ID_REQUEST_IP_ADDRESS)) {
		d->Counters.Ignored++;
		return;
	}

	if (e->Kind == NODE_DHCP_BOUND)
		d->Counters.Changes++;
	e->Kind = NODE_DHCP_DECLINED;
	Zero(e->Mac, sizeof(e->Mac));
	Zero(e->HostName, sizeof(e->HostName));
	e->Expires = now + NODE_DHCP_DECLINE_TIME;
}

// DHCPRELEASE: the client gives its lease back
static void NodeDhcpRelease(NODE_DHCP *d, const DHCPV4_HEADER *h, LIST *o) {
	NODE_DHCP_ENTRY *e = NodeDhcpByMac(d, h->ClientMacAddress);

	if (NodeDhcpOptionAddress(o, DHCP_ID_SERVER_ID) != d->Config.Address || e == NULL || e->Kind != NODE_DHCP_BOUND || e->Address != Endian32(h->ClientIP)) {
		d->Counters.Ignored++;
		return;
	}

	NodeDhcpRemove(d, e);
	d->Counters.Changes++;
}

// DHCPINFORM: a client with an address of the pool that it set itself asks for the other settings, which a DHCPACK
// without a lease gives (RFC 2131 3.4)
static void NodeDhcpInform(NODE_DHCP *d, const DHCPV4_HEADER *h) {
	UINT ciaddr = Endian32(h->ClientIP);

	if (ciaddr <= d->First || ciaddr >= d->Last) {
		d->Counters.Ignored++;
		return;
	}

	if (NodeDhcpReply(d, h, DHCP_ACK, 0, false))
		d->Counters.Acks++;
}

// A DHCP message that the switch delivered. An answer of a server tells of a DHCP server of the LAN; the message of a
// client is answered while the responder serves.
static void NodeDhcpMessage(NODE_DHCP *d, UINT64 now, PKT *p) {
	DHCPV4_HEADER *h = p->L7.DHCPv4Header;
	UDP_HEADER *udp = p->L4.UDPHeader;
	UINT size = p->PayloadSize;
	UINT udp_size = Endian16(udp->PacketLength);
	UINT options_size = 0;

	// The message ends with its datagram
	if (udp_size >= sizeof(UDP_HEADER) && udp_size - sizeof(UDP_HEADER) < size)
		size = udp_size - (UINT)sizeof(UDP_HEADER);

	UCHAR *options = DhcpOptionsOf(h, size, &options_size);
	if (options == NULL)
		return;

	LIST *o = ParseDhcpOptions(options, options_size);
	DHCP_OPTION *t = GetDhcpOption(o, DHCP_ID_MESSAGE_TYPE);
	UINT type = (t != NULL && t->Size == 1 ? *((UCHAR *)t->Data) : 0);

	if (h->OpCode == NODE_DHCP_BOOTREPLY && Endian16(udp->SrcPort) == NODE_DHCP_SERVER_PORT) {
		// An answer of another server, not one of the responder's own that a loop brought back
		if ((type == DHCP_OFFER || type == DHCP_ACK || type == DHCP_NAK) && Cmp(p->MacAddressSrc, d->Config.Mac, 6) != 0) {
			d->LanSeen = true;
			d->LanAnswer = now;
			d->Counters.LanAnswers++;
		}
	} else if (h->OpCode == NODE_DHCP_BOOTREQUEST && Endian16(udp->DstPort) == NODE_DHCP_SERVER_PORT) {
		// A client of Ethernet on this segment, not one behind a relay
		bool client = (h->HardwareType == ARP_HARDWARE_TYPE_ETHERNET && h->HardwareAddressSize == 6 && h->RelayIP == 0 && (h->ClientMacAddress[0] & 0x01) == 0 && IsZero(h->ClientMacAddress, 6) == false);

		if (NodeDhcpServing(d, now) == false || client == false) {
			d->Counters.Ignored++;
		} else {
			switch (type) {
			case DHCP_DISCOVER:
				NodeDhcpDiscover(d, now, h, o);
				break;
			case DHCP_REQUEST:
				NodeDhcpRequest(d, now, h, o);
				break;
			case DHCP_DECLINE:
				NodeDhcpDecline(d, now, h, o);
				break;
			case DHCP_RELEASE:
				NodeDhcpRelease(d, h, o);
				break;
			case DHCP_INFORM:
				NodeDhcpInform(d, h);
				break;
			default:
				d->Counters.Ignored++;
				break;
			}
		}
	}

	FreeDhcpOptions(o);
}

//
// The responder
//

// A responder with the configuration cfg at now
NODE_DHCP *NodeDhcpNew(const NODE_DHCP_CONFIG *cfg, UINT64 now) {
	if (cfg == NULL)
		return NULL;

	NODE_DHCP *d = ZeroMalloc(sizeof(NODE_DHCP));
	d->Lock = NewLock();
	d->Entries = ZeroMalloc(sizeof(NODE_DHCP_ENTRY) * NODE_DHCP_MAX_LEASES);
	d->Queue = ZeroMalloc(sizeof(NODE_DHCP_FRAME) * NODE_DHCP_MAX_QUEUE);
	NodeDhcpSetConfig(d, cfg, now);

	return d;
}

void NodeDhcpFree(NODE_DHCP *d) {
	if (d == NULL)
		return;

	DeleteLock(d->Lock);
	Free(d->Entries);
	Free(d->Queue);
	Free(d);
}

// The configuration cfg from now. The entries whose address the responder may give no more go, and a lease among them
// is a change. A responder that starts to serve, or whose MAC address or pool changed, probes before it answers a
// client; one that no longer serves sends nothing more.
void NodeDhcpSetConfig(NODE_DHCP *d, const NODE_DHCP_CONFIG *cfg, UINT64 now) {
	if (d == NULL || cfg == NULL)
		return;

	Lock(d->Lock);
	{
		bool was = d->Valid;
		bool moved = (Cmp(d->Config.Mac, cfg->Mac, 6) != 0 || d->Config.Pool != cfg->Pool || d->Config.PoolLength != cfg->PoolLength);
		UINT i = 0;

		Copy(&d->Config, cfg, sizeof(NODE_DHCP_CONFIG));
		d->Config.NumDns = MIN(d->Config.NumDns, NODE_DHCP_MAX_DNS);
		d->Config.NumReserved = MIN(d->Config.NumReserved, NODE_DHCP_MAX_RESERVED);
		d->Valid = NodeDhcpConfigOk(&d->Config);
		d->First = d->Config.Pool & NodeDhcpMask(d->Config.PoolLength);
		d->Last = d->First | ~NodeDhcpMask(d->Config.PoolLength);
		d->ProbeXid = READ_UINT(d->Config.Mac + 2) ^ 0x52414E5A;

		NodeDhcpExpire(d, now);
		while (i < d->NumEntries) {
			NODE_DHCP_ENTRY *e = &d->Entries[i];

			if (NodeDhcpUsable(d, e->Address)) {
				i++;
				continue;
			}
			if (e->Kind == NODE_DHCP_BOUND)
				d->Counters.Changes++;
			NodeDhcpRemove(d, e);
		}

		if (d->Valid == false || was == false || moved)
			NodeDhcpReset(d);
	}
	Unlock(d->Lock);
}

// A frame that the switch delivered to the port of the responder at now: a DHCP message or an ARP request. A tagged
// frame of another VLAN than the port's, and a frame larger than NODE_DHCP_MAX_FRAME, are left alone.
void NodeDhcpInput(NODE_DHCP *d, UINT64 now, const UCHAR *frame, UINT size) {
	UCHAR buf[NODE_DHCP_MAX_FRAME];

	if (d == NULL || frame == NULL || size < sizeof(MAC_HEADER) || size > sizeof(buf))
		return;

	// The parser takes a frame that it may change: a copy of the switch's
	Copy(buf, frame, size);
	PKT *p = ParsePacketEx5(buf, size, false, 0, false, true, false, true);
	if (p == NULL)
		return;

	Lock(d->Lock);
	{
		NodeDhcpExpire(d, now);
		if (p->VlanId == 0 && p->TypeL3 == L3_ARPV4 && p->L3.ARPv4Header != NULL) {
			if (NodeDhcpServing(d, now))
				NodeDhcpArp(d, p->L3.ARPv4Header);
		} else if (p->VlanId == 0 && p->TypeL3 == L3_IPV4 && p->TypeL4 == L4_UDP && p->TypeL7 == L7_DHCPV4 && p->L7.DHCPv4Header != NULL) {
			NodeDhcpMessage(d, now, p);
		}
	}
	Unlock(d->Lock);

	FreePacket(p);
}

// The next frame that the responder sends at now, into buf of size bytes: its size, 0 for none. A probe goes first
// when the responder serves and it has not probed yet or for NODE_DHCP_PROBE_TIME. A frame larger than size is dropped.
UINT NodeDhcpOutput(NODE_DHCP *d, UINT64 now, UCHAR *buf, UINT size) {
	UINT ret = 0;

	if (d == NULL || buf == NULL)
		return 0;

	Lock(d->Lock);
	{
		NodeDhcpExpire(d, now);
		if (d->Valid && (d->Probed == false || now >= d->NextProbe)) {
			if (d->Probed == false) {
				d->Probed = true;
				d->FirstProbe = now;
			}
			d->NextProbe = now + NODE_DHCP_PROBE_TIME;
			NodeDhcpProbe(d);
		}

		while (d->QueueSize != 0 && ret == 0) {
			NODE_DHCP_FRAME *f = &d->Queue[d->QueueHead];

			d->QueueHead = (d->QueueHead + 1) % NODE_DHCP_MAX_QUEUE;
			d->QueueSize--;
			if (f->Size <= size) {
				Copy(buf, f->Data, f->Size);
				ret = f->Size;
			}
		}
	}
	Unlock(d->Lock);

	return ret;
}

// The leases of the responder at now, max at most: their number
UINT NodeDhcpGetLeases(NODE_DHCP *d, UINT64 now, NODE_DHCP_LEASE *leases, UINT max) {
	UINT num = 0;

	if (d == NULL || leases == NULL)
		return 0;

	Lock(d->Lock);
	{
		NodeDhcpExpire(d, now);
		for (UINT i = 0; i < d->NumEntries && num < max; i++) {
			const NODE_DHCP_ENTRY *e = &d->Entries[i];
			NODE_DHCP_LEASE *l = &leases[num];

			if (e->Kind != NODE_DHCP_BOUND)
				continue;

			Zero(l, sizeof(NODE_DHCP_LEASE));
			Copy(l->Mac, e->Mac, 6);
			l->Address = e->Address;
			l->Expires = e->Expires;
			StrCpy(l->HostName, sizeof(l->HostName), e->HostName);
			num++;
		}
	}
	Unlock(d->Lock);

	return num;
}

void NodeDhcpGetStatus(NODE_DHCP *d, UINT64 now, NODE_DHCP_STATUS *st) {
	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_DHCP_STATUS));
	if (d == NULL)
		return;

	Lock(d->Lock);
	{
		NodeDhcpExpire(d, now);
		Copy(st, &d->Counters, sizeof(NODE_DHCP_STATUS));
		st->Serving = NodeDhcpServing(d, now);
		st->LanServer = (d->LanSeen && now < d->LanAnswer + NODE_DHCP_LAN_HOLD);
		st->NumLeases = 0;
		for (UINT i = 0; i < d->NumEntries; i++) {
			if (d->Entries[i].Kind == NODE_DHCP_BOUND)
				st->NumLeases++;
		}
	}
	Unlock(d->Lock);
}

// The configuration of the responder of the CONTROL_DHCP c of a desired state, with the MAC address mac
void NodeDhcpConfigOf(NODE_DHCP_CONFIG *cfg, const CONTROL_DHCP *c, const UCHAR *mac) {
	if (cfg == NULL)
		return;

	Zero(cfg, sizeof(NODE_DHCP_CONFIG));
	if (c == NULL || mac == NULL)
		return;

	cfg->Serve = true;
	Copy(cfg->Mac, mac, 6);
	cfg->Pool = READ_UINT(c->Pool);
	cfg->PoolLength = c->PoolLength;
	cfg->Address = READ_UINT(c->Address);
	cfg->Gateway = READ_UINT(c->Gateway);
	cfg->NumDns = MIN(c->NumDns, NODE_DHCP_MAX_DNS);
	for (UINT i = 0; i < cfg->NumDns; i++)
		cfg->Dns[i] = READ_UINT(c->Dns[i]);
	cfg->LeaseTime = c->LeaseTime;
	cfg->NumReserved = MIN(c->NumReserved, NODE_DHCP_MAX_RESERVED);
	for (UINT i = 0; i < cfg->NumReserved; i++) {
		cfg->ReservedAddress[i] = READ_UINT(c->Reserved[i].Address);
		cfg->ReservedLength[i] = c->Reserved[i].Length;
	}
}

//
// The responders of a node
//

// The responder of one L2 Network on the node
typedef struct NODE_DHCP_NETWORK {
	NODE_DHCPS *Owner;            // The responders of the node
	char Name[CONTROL_NAME_SIZE]; // The L2 Network
	NODE_DHCP *Dhcp;              // Its responder, NULL while the desired state gives it none
	SWITCH *Switch;               // The switch of the Network that the L2 data path attached, NULL for none ...
	UINT Vlan;                    // ... the VLAN of the Network on it ...
	UINT Port;                    // ... and the port of the responder there, SWITCH_PORT_NONE while it has none
	UINT64 Reported;              // The changes of its leases that the control stream got
	bool Report;                  // Its leases go to the control stream at the next run of the thread
} NODE_DHCP_NETWORK;

// The DHCP responders of a node, while its overlay runs
struct NODE_DHCPS {
	NODE *Node;             // The node
	LOCK *Lock;             // Networks and their fields
	LIST *Networks;         // The L2 Networks with a responder or a switch (NODE_DHCP_NETWORK)
	CONTROL_LEASES *Leases; // The leases that the control stream reports (CONTROL_CONFIG.Leases)
	NODE_DHCP_LEASE *Buf;   // The leases of one responder, NODE_DHCP_MAX_LEASES
	CONTROL_LEASE *Report;  // ... as the control stream takes them
	HANDLE Halt;            // Ends the thread
	HANDLE Wake;            // A responder has a frame to send, or a responder came or went (auto-reset)
	HANDLE Thread;          // Sends the frames of the responders into their switches and reports their leases
};

// The MAC address of the responder of the Network network on the node node: a locally administered unicast address from
// the FNV-1a hash of the two names, the same at every start, so the clients keep the ARP entry of their server
static void NodeDhcpMacOf(UCHAR *mac, const char *node, const char *network) {
	UINT64 h = 0xCBF29CE484222325ULL;

	for (const char *s = node; *s != 0; s++)
		h = (h ^ (UCHAR)*s) * 0x100000001B3ULL;
	h = (h ^ 0xFF) * 0x100000001B3ULL;
	for (const char *s = network; *s != 0; s++)
		h = (h ^ (UCHAR)*s) * 0x100000001B3ULL;

	mac[0] = 0x02;
	for (UINT i = 1; i < 6; i++)
		mac[i] = (UCHAR)(h >> (8 * (i - 1)));
}

// The Unix time in ms
static UINT64 NodeDhcpUnixTime() {
	FILETIME ft;

	GetSystemTimeAsFileTime(&ft);
	UINT64 t = ((UINT64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
	// 100 ns since 1601 to ms since 1970
	return (t - 116444736000000000ULL) / 10000;
}

// The entry of the Network name, which is made when make is true; NULL for none. The caller holds the lock.
static NODE_DHCP_NETWORK *NodeDhcpNetwork(NODE_DHCPS *ds, const char *name, bool make) {
	for (UINT i = 0; i < LIST_NUM(ds->Networks); i++) {
		NODE_DHCP_NETWORK *net = LIST_DATA(ds->Networks, i);

		if (StrCmp(net->Name, name) == 0)
			return net;
	}
	if (make == false)
		return NULL;

	NODE_DHCP_NETWORK *net = ZeroMalloc(sizeof(NODE_DHCP_NETWORK));
	net->Owner = ds;
	StrCpy(net->Name, sizeof(net->Name), name);
	net->Port = SWITCH_PORT_NONE;
	Add(ds->Networks, net);

	return net;
}

// Takes a frame that the switch delivers to the port of a responder (SWITCH_SEND_PROC), on the thread of SwitchInput:
// the responder queues its answer, which the thread of the responders sends
static void NodeDhcpSwitchSend(void *param, UINT port, const UCHAR *frame, UINT size) {
	NODE_DHCP_NETWORK *net = (NODE_DHCP_NETWORK *)param;

	UNREFERENCED_PARAMETER(port);
	NodeDhcpInput(net->Dhcp, GetTickCount64(), frame, size);
	SetEvent(net->Owner->Wake);
}

// Put the responder of the Network on its switch: an access port of its VLAN that takes the broadcast group, which also
// takes the frames to an address that the VLAN has not learnt. The caller holds the lock.
static bool NodeDhcpPlug(NODE_DHCP_NETWORK *net) {
	SWITCH_PORT_CONFIG pc;

	if (net->Dhcp == NULL || net->Switch == NULL || net->Port != SWITCH_PORT_NONE)
		return true;

	Zero(&pc, sizeof(pc));
	pc.Mode = SWITCH_ACCESS;
	pc.Vlan = net->Vlan;
	pc.Send = NodeDhcpSwitchSend;
	pc.Param = net;

	// A new member of the Network probes before it answers
	Lock(net->Dhcp->Lock);
	NodeDhcpReset(net->Dhcp);
	Unlock(net->Dhcp->Lock);

	net->Port = SwitchAddPort(net->Switch, &pc);
	if (net->Port == SWITCH_PORT_NONE)
		return false;
	if (SwitchSubscribe(net->Switch, net->Port, net->Vlan, node_dhcp_broadcast) == false) {
		SwitchDelPort(net->Switch, net->Port);
		net->Port = SWITCH_PORT_NONE;
		return false;
	}

	return true;
}

// Take the responder of the Network off its switch: once this returns, the switch delivers it no more frames. The caller
// holds the lock.
static void NodeDhcpUnplug(NODE_DHCP_NETWORK *net) {
	if (net->Port == SWITCH_PORT_NONE)
		return;

	SwitchDelPort(net->Switch, net->Port);
	net->Port = SWITCH_PORT_NONE;
}

// Report the leases of the responder of the Network on the control stream at now. The caller holds the lock.
static void NodeDhcpReport(NODE_DHCPS *ds, NODE_DHCP_NETWORK *net, UINT64 now, UINT64 changes) {
	UINT64 unix_now = NodeDhcpUnixTime();
	UINT num = NodeDhcpGetLeases(net->Dhcp, now, ds->Buf, NODE_DHCP_MAX_LEASES);

	for (UINT i = 0; i < num; i++) {
		const NODE_DHCP_LEASE *l = &ds->Buf[i];
		CONTROL_LEASE *r = &ds->Report[i];

		Zero(r, sizeof(CONTROL_LEASE));
		Copy(r->Mac, l->Mac, 6);
		WRITE_UINT(r->Address, l->Address);
		r->Expires = unix_now + (l->Expires > now ? l->Expires - now : 0);
		StrCpy(r->HostName, sizeof(r->HostName), l->HostName);
	}

	if (ControlSetLeases(ds->Leases, net->Name, ds->Report, num)) {
		net->Reported = changes;
		net->Report = false;
	}
}

static DWORD WINAPI NodeDhcpThread(LPVOID param) {
	NODE_DHCPS *ds = (NODE_DHCPS *)param;
	HANDLE events[2] = {ds->Halt, ds->Wake};
	UCHAR *frame = Malloc(NODE_DHCP_MAX_FRAME);

	while (WaitForMultipleObjects(2, events, FALSE, NODE_DHCP_TICK) != WAIT_OBJECT_0) {
		UINT64 now = GetTickCount64();

		Lock(ds->Lock);
		for (UINT i = 0; i < LIST_NUM(ds->Networks); i++) {
			NODE_DHCP_NETWORK *net = LIST_DATA(ds->Networks, i);
			NODE_DHCP_STATUS st;
			UINT size;

			if (net->Dhcp == NULL)
				continue;

			// Its frames into its switch: a responder that has none sends nothing, and probes once it has one
			while (net->Port != SWITCH_PORT_NONE && (size = NodeDhcpOutput(net->Dhcp, now, frame, NODE_DHCP_MAX_FRAME)) != 0)
				SwitchInput(net->Switch, now, net->Port, frame, size);

			NodeDhcpGetStatus(net->Dhcp, now, &st);
			if (net->Report || st.Changes != net->Reported)
				NodeDhcpReport(ds, net, now, st.Changes);
		}
		Unlock(ds->Lock);
	}

	Free(frame);
	return 0;
}

// Start the DHCP responders of a node with its overlay: the leases that its control stream reports, NULL when they
// could not start
CONTROL_LEASES *NodeDhcpStart(NODE *n) {
	DWORD thread_id = 0;

	if (n == NULL || n->Dhcp != NULL)
		return NULL;

	NODE_DHCPS *ds = ZeroMalloc(sizeof(NODE_DHCPS));
	ds->Node = n;
	ds->Lock = NewLock();
	ds->Networks = NewListFast(NULL);
	ds->Leases = ControlNewLeases();
	ds->Buf = ZeroMalloc(sizeof(NODE_DHCP_LEASE) * NODE_DHCP_MAX_LEASES);
	ds->Report = ZeroMalloc(sizeof(CONTROL_LEASE) * NODE_DHCP_MAX_LEASES);
	ds->Halt = CreateEventW(NULL, TRUE, FALSE, NULL);
	ds->Wake = CreateEventW(NULL, FALSE, FALSE, NULL);
	if (ds->Leases != NULL && ds->Halt != NULL && ds->Wake != NULL)
		ds->Thread = CreateThread(NULL, 0, NodeDhcpThread, ds, 0, &thread_id);

	n->Dhcp = ds;
	if (ds->Thread == NULL) {
		NodeLog(n, "DHCP: the responders of the L2 Networks could not start");
		NodeDhcpStop(n);
		return NULL;
	}

	return ds->Leases;
}

// Stop the DHCP responders of a node, once its control stream stopped: each leaves its switch
void NodeDhcpStop(NODE *n) {
	NODE_DHCPS *ds = (n != NULL ? n->Dhcp : NULL);

	if (ds == NULL)
		return;

	if (ds->Thread != NULL) {
		SetEvent(ds->Halt);
		WaitForSingleObject(ds->Thread, INFINITE);
		CloseHandle(ds->Thread);
	}

	n->Dhcp = NULL;
	for (UINT i = 0; i < LIST_NUM(ds->Networks); i++) {
		NODE_DHCP_NETWORK *net = LIST_DATA(ds->Networks, i);

		NodeDhcpUnplug(net);
		NodeDhcpFree(net->Dhcp);
		Free(net);
	}
	ReleaseList(ds->Networks);
	ControlFreeLeases(ds->Leases);
	if (ds->Halt != NULL)
		CloseHandle(ds->Halt);
	if (ds->Wake != NULL)
		CloseHandle(ds->Wake);
	DeleteLock(ds->Lock);
	Free(ds->Buf);
	Free(ds->Report);
	Free(ds);
}

// Whether the state st gives the Network name a responder
static bool NodeDhcpInState(const CONTROL_STATE *st, const char *name) {
	for (UINT i = 0; i < st->NumDhcps; i++) {
		if (StrCmp(st->Dhcps[i].Network, name) == 0)
			return true;
	}

	return false;
}

// The responders of a desired state that the overlay applied: one starts for each Network that the state gives one, or
// takes its new configuration, and the responder of a Network that the state gives none stops, with its report
void NodeDhcpApplied(NODE *n, const CONTROL_STATE *st) {
	NODE_DHCPS *ds = (n != NULL ? n->Dhcp : NULL);
	UINT64 now = GetTickCount64();

	if (ds == NULL || st == NULL)
		return;

	Lock(ds->Lock);
	{
		for (UINT i = 0; i < st->NumDhcps; i++) {
			const CONTROL_DHCP *c = &st->Dhcps[i];
			NODE_DHCP_NETWORK *net = NodeDhcpNetwork(ds, c->Network, true);
			NODE_DHCP_CONFIG cfg;
			UCHAR mac[6];

			NodeDhcpMacOf(mac, st->Name, c->Network);
			NodeDhcpConfigOf(&cfg, c, mac);
			if (net->Dhcp != NULL) {
				NodeDhcpSetConfig(net->Dhcp, &cfg, now);
				continue;
			}

			net->Dhcp = NodeDhcpNew(&cfg, now);
			net->Report = true;
			if (NodeDhcpPlug(net) == false)
				NodeLog(n, "DHCP: the responder of the L2 Network %s could not join the switch of the Network", net->Name);
			NodeLog(n, "DHCP: the responder of the L2 Network %s starts: pool %u.%u.%u.%u/%u, its address %u.%u.%u.%u, lease time %u s, %s", net->Name,
			        (UINT)c->Pool[0], (UINT)c->Pool[1], (UINT)c->Pool[2], (UINT)c->Pool[3], c->PoolLength, (UINT)c->Address[0], (UINT)c->Address[1], (UINT)c->Address[2], (UINT)c->Address[3], c->LeaseTime,
			        (net->Switch != NULL ? "on the switch of the Network" : "until the switch of the Network is attached"));
		}

		UINT i = 0;
		while (i < LIST_NUM(ds->Networks)) {
			NODE_DHCP_NETWORK *net = LIST_DATA(ds->Networks, i);

			if (net->Dhcp == NULL || NodeDhcpInState(st, net->Name)) {
				i++;
				continue;
			}

			// The mode is off, or the controller named another node: the node answers no DHCP for the Network
			NodeDhcpUnplug(net);
			NodeDhcpFree(net->Dhcp);
			net->Dhcp = NULL;
			ControlSetLeases(ds->Leases, net->Name, NULL, 0);
			NodeLog(n, "DHCP: the responder of the L2 Network %s stops: the desired state gives it none", net->Name);
			if (net->Switch == NULL) {
				Delete(ds->Networks, net);
				Free(net);
				continue;
			}
			i++;
		}
	}
	Unlock(ds->Lock);

	SetEvent(ds->Wake);
}

// The L2 data path attaches the switch sw of the L2 Network network, whose VLAN on it is vlan: the responder of the
// Network, while the desired state gives it one, becomes a member of the switch. False when the overlay does not run
// or the responder could not join the switch.
bool NodeDhcpAttach(NODE *n, const char *network, SWITCH *sw, UINT vlan) {
	NODE_DHCPS *ds = (n != NULL ? n->Dhcp : NULL);
	bool ok;

	if (ds == NULL || IsEmptyStr(network) || StrLen(network) >= CONTROL_NAME_SIZE || sw == NULL)
		return false;

	Lock(ds->Lock);
	{
		NODE_DHCP_NETWORK *net = NodeDhcpNetwork(ds, network, true);

		NodeDhcpUnplug(net);
		net->Switch = sw;
		net->Vlan = vlan;
		ok = NodeDhcpPlug(net);
	}
	Unlock(ds->Lock);

	SetEvent(ds->Wake);
	return ok;
}

// The L2 data path detaches the switch of the L2 Network network before it frees it: the responder leaves it
void NodeDhcpDetach(NODE *n, const char *network) {
	NODE_DHCPS *ds = (n != NULL ? n->Dhcp : NULL);

	if (ds == NULL || network == NULL)
		return;

	Lock(ds->Lock);
	{
		NODE_DHCP_NETWORK *net = NodeDhcpNetwork(ds, network, false);

		if (net != NULL) {
			NodeDhcpUnplug(net);
			net->Switch = NULL;
			if (net->Dhcp == NULL) {
				Delete(ds->Networks, net);
				Free(net);
			}
		}
	}
	Unlock(ds->Lock);
}

// How the responder of the L2 Network network on the node stands: false when the node runs none for it
bool NodeDhcpGetNetwork(NODE *n, const char *network, NODE_DHCP_STATUS *st) {
	NODE_DHCPS *ds = (n != NULL ? n->Dhcp : NULL);
	bool ok = false;

	if (st != NULL)
		Zero(st, sizeof(NODE_DHCP_STATUS));
	if (ds == NULL || network == NULL || st == NULL)
		return false;

	Lock(ds->Lock);
	{
		NODE_DHCP_NETWORK *net = NodeDhcpNetwork(ds, network, false);

		if (net != NULL && net->Dhcp != NULL) {
			NodeDhcpGetStatus(net->Dhcp, GetTickCount64(), st);
			ok = true;
		}
	}
	Unlock(ds->Lock);

	return ok;
}
