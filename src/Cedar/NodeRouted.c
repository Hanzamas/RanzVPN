// NodeRouted.c
// The routed networks of the server role of a node (NodeRouted.h; CORE-S6-1, #80; ADR-0010 decision 1). Each L3 Network
// of the configuration store that the Routed setting gives gateway addresses is a routed network: a KM-TEST adapter of its
// own (NodeKmTest.c) is the access port of the network and carries its gateway addresses, its IPv4 and IPv6 interfaces
// forward, and the Windows IP stack routes between the routed networks. The node routes nothing itself: it holds no route
// of a routed network, and a packet of one network reaches another only through the kernel.
// - The port: the L2 adapter of the KM-TEST adapter (NodeL2.c), with the backend that the host gives (XDP, else SeLow),
//   carries the frames between the host and the member side of the port, which has a MAC address of its own. An IP
//   packet of a member goes into the host as a frame from the member side (NodeRoutedSend), and only from an address of
//   the network; a packet that the host routes to an address of the network goes to the owner of the member side
//   (NodeRoutedSetProc). The port answers the ARP requests and the Neighbor Solicitations of the host for the addresses of
//   the network with the MAC address of the member side, so the members of the network are all behind it. It never answers
//   for a gateway address, nor a solicitation of the duplicate address detection of the host, and the interfaces of the
//   port make none (DadTransmits 0): no one but the node is on the segment.
// - The NAT: the routed networks whose setting asks for it reach the internet through the NAT network of WinNAT of the
//   node (NODE_EGRESS_NETNAT_NAME; ADR-0025 decision 6), over the supernet of their IPv4 prefixes. WinNAT holds one NAT
//   network per host: the routed networks make it only where none exists, never touch one of another program, and leave
//   alone the one of the node that the Egress of the overlay holds over its VRFs (NodeEgressNat.c), whose prefix differs;
//   those routed networks then have no NAT, and the node log says so. They take out what they made when the role stops.
// - The setting: Routed in the configuration store, one JSON object: {"networks": [{"name": "lab", "gateways":
//   ["198.18.81.1/24", "fd81:a::1/64"], "nat": true}]}. An L3 Network that it does not name, or names with a gateway that
//   is not valid, stays down, and the node log says why. The KM-TEST adapter of a routed network has the MAC address of the
//   node's static key and the name of the Network (NodeRoutedMac), so the node finds it again at its next start; the
//   gateway addresses go when the role stops, the adapter stays.
// arm64 has no backend for the port (NodeL2Offered), so no routed network comes up there.

#include "Node.h"

#include "ConfigStore.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"

#include "NodeEgress.h"
#include "NodeInternal.h"
#include "NodeL2.h"
#include "NodeRouted.h"

#include <WinDNS.h>
#include <iphlpapi.h>

#include <cjson/cJSON.h>

// The EtherTypes of the port, and the ICMPv6 types of neighbor discovery
#define NODE_ROUTED_TYPE_IPV4 0x0800
#define NODE_ROUTED_TYPE_ARP  0x0806
#define NODE_ROUTED_TYPE_IPV6 0x86DD
#define NODE_ROUTED_ICMPV6    58
#define NODE_ROUTED_NS        135
#define NODE_ROUTED_NA        136
// Bytes of the shortest frame that the port hands the host: the shortest Ethernet frame without its FCS
#define NODE_ROUTED_MIN_FRAME 60
// Routed networks whose IPv4 prefixes the NAT network of WinNAT of the node takes at most
#define NODE_ROUTED_MAX_NAT 64

// A routed network
struct NODE_ROUTED {
	NODE *Node;                                             // The node
	char Name[MAX_HUBNAME_LEN + 1];                         // The name of its L3 Network
	UINT NumGateways;                                       // Its gateway addresses ...
	NODE_ROUTED_GATEWAY Gateways[NODE_ROUTED_MAX_GATEWAYS]; // ...
	bool Made[NODE_ROUTED_MAX_GATEWAYS];                    // ... and the ones that its interface holds, which go when it stops
	bool Nat;                                               // It goes through the NAT network of WinNAT of the node
	UCHAR Mac[6];                                           // The MAC address of its KM-TEST adapter ...
	UCHAR MemberMac[6];                                     // ... and of the member side of the port
	NODE_KMTEST *KmTest;                                    // The KM-TEST adapter ...
	UINT IfIndex;                                           // ... its interface ...
	UINT64 Luid;                                            // ...
	NODE_L2 *L2;                                            // ... and the L2 adapter on it, the port
	SRWLOCK Lock;                                           // Proc and Param
	NODE_ROUTED_PROC *Proc;                                 // The owner of the member side, NULL for none
	void *Param;                                            // ... and its parameter
	volatile LONG64 FromMembers;                            // The counters (NODE_ROUTED_STATUS)
	volatile LONG64 ToMembers;
	volatile LONG64 Answers;
	volatile LONG64 Refused;
	volatile LONG64 Ignored;
	volatile LONG64 Unowned;
};

// The routed networks of the server role, and the NAT network of WinNAT that they made
struct NODE_ROUTED_SET {
	LIST *Networks;                     // The routed networks (NODE_ROUTED)
	bool NetNat;                        // The routed networks made the NAT network of WinNAT of the node ...
	wchar_t Prefix[NODE_ROUTED_PREFIX]; // ... over this internal prefix
};

//
// The setting
//

// Whether an address of size bytes can be the gateway of a network: no unspecified, loopback, multicast, broadcast or
// link-local address
static bool NodeRoutedUnicast(const UCHAR *a, UINT size) {
	static const UCHAR none[16] = {0};

	if (size == 4)
		return (a[0] != 0 && a[0] != 127 && a[0] < 224 && (a[0] != 169 || a[1] != 254));

	if (Cmp(a, none, 15) == 0 && (a[15] == 0 || a[15] == 1))
		return false;

	return (a[0] != 0xFF && (a[0] != 0xFE || (a[1] & 0xC0) != 0x80));
}

// A gateway address of the Routed setting, "198.18.81.1/24" or "fd81:a::1/64", into gw: false when it is no IPv4 or IPv6
// unicast address with a prefix length that leaves room for members (8 to 30 for IPv4, 16 to 126 for IPv6)
static bool NodeRoutedParseGateway(const char *str, NODE_ROUTED_GATEWAY *gw) {
	char addr[MAX_SIZE];
	wchar_t tmp[MAX_SIZE];
	NET_ADDRESS_INFO info;
	UINT slash = INFINITE;
	UINT length = 0;

	Zero(gw, sizeof(NODE_ROUTED_GATEWAY));
	if (str == NULL || StrLen(str) >= sizeof(addr))
		return false;

	StrCpy(addr, sizeof(addr), str);
	for (UINT i = 0; addr[i] != 0 && slash == INFINITE; i++)
		if (addr[i] == '/')
			slash = i;
	if (slash == INFINITE || addr[slash + 1] == 0)
		return false;

	// The length: three digits at most
	for (UINT i = slash + 1; addr[i] != 0; i++) {
		if (addr[i] < '0' || addr[i] > '9' || i > slash + 3)
			return false;
		length = length * 10 + (UINT)(addr[i] - '0');
	}
	addr[slash] = 0;

	StrToUni(tmp, sizeof(tmp), addr);
	Zero(&info, sizeof(info));
	if (ParseNetworkString(tmp, NET_STRING_IP_ADDRESS_NO_SCOPE, &info, NULL, NULL) != ERROR_SUCCESS)
		return false;

	if (info.Format == NET_ADDRESS_IPV4) {
		gw->Size = 4;
		Copy(gw->Address, &info.Ipv4Address.sin_addr, 4);
	} else if (info.Format == NET_ADDRESS_IPV6) {
		gw->Size = 16;
		Copy(gw->Address, &info.Ipv6Address.sin6_addr, 16);
	} else {
		return false;
	}
	gw->Length = length;

	if (gw->Size == 4 && (length < 8 || length > 30))
		return false;
	if (gw->Size == 16 && (length < 16 || length > 126))
		return false;

	return NodeRoutedUnicast(gw->Address, gw->Size);
}

// The gateway addresses and the NAT of the routed network name in the Routed setting json: its gateways into gw
// (NODE_ROUTED_MAX_GATEWAYS) and *num, and whether it goes through NAT into *nat. False when the setting is no JSON object
// with an array networks that names the network (without case), or when it gives the network no gateway, more than
// NODE_ROUTED_MAX_GATEWAYS, or one that is not valid.
bool NodeRoutedParseSetting(const char *json, const char *name, NODE_ROUTED_GATEWAY *gw, UINT *num, bool *nat) {
	bool ok = false;

	if (num != NULL)
		*num = 0;
	if (nat != NULL)
		*nat = false;
	if (json == NULL || name == NULL || gw == NULL || num == NULL || nat == NULL)
		return false;

	cJSON *root = cJSON_Parse(json);
	cJSON *networks = cJSON_GetObjectItemCaseSensitive(root, "networks");
	cJSON *net = NULL;

	if (cJSON_IsObject(root) == false || cJSON_IsArray(networks) == false) {
		cJSON_Delete(root);
		return false;
	}

	cJSON_ArrayForEach(net, networks) {
		cJSON *gateways = cJSON_GetObjectItemCaseSensitive(net, "gateways");
		cJSON *item = NULL;
		const char *n = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(net, "name"));

		if (n == NULL || StrCmpi(n, name) != 0)
			continue;

		ok = (cJSON_IsArray(gateways) && cJSON_GetArraySize(gateways) > 0 && cJSON_GetArraySize(gateways) <= NODE_ROUTED_MAX_GATEWAYS);
		cJSON_ArrayForEach(item, gateways) {
			if (ok == false || *num >= NODE_ROUTED_MAX_GATEWAYS)
				break;
			ok = NodeRoutedParseGateway(cJSON_GetStringValue(item), &gw[*num]);
			if (ok)
				(*num)++;
		}

		*nat = (cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(net, "nat")) != 0);
		break;
	}

	cJSON_Delete(root);

	if (ok == false) {
		*num = 0;
		*nat = false;
	}

	return ok;
}

//
// The port
//

// Whether the address of size bytes is inside the prefix of the gateway gw
static bool NodeRoutedInPrefix(const NODE_ROUTED_GATEWAY *gw, const UCHAR *addr, UINT size) {
	UINT full = gw->Length / 8;
	UINT rest = gw->Length % 8;

	if (gw->Size != size || full > size || (full == size && rest != 0))
		return false;
	if (full != 0 && Cmp(gw->Address, addr, full) != 0)
		return false;
	if (rest != 0) {
		UCHAR mask = (UCHAR)(0xFF << (8 - rest));

		if ((gw->Address[full] & mask) != (addr[full] & mask))
			return false;
	}

	return true;
}

// Whether the address of size bytes is one of the member side of the network of the gateways gw: inside the prefix of one
// of them and none of them
static bool NodeRoutedMember(const NODE_ROUTED_GATEWAY *gw, UINT num, const UCHAR *addr, UINT size) {
	bool inside = false;

	for (UINT i = 0; i < num; i++) {
		if (gw[i].Size == size && Cmp(gw[i].Address, addr, size) == 0)
			return false;
		if (NodeRoutedInPrefix(&gw[i], addr, size))
			inside = true;
	}

	return inside;
}

// What a frame of size bytes that the host sent out of the adapter of a routed network is, the network of the gateways gw
// (num of them) whose member side has the MAC address member_mac: NODE_ROUTED_FRAME_*, which f takes with what the port
// needs of it.
// - An ARP request of IPv4 over Ethernet, broadcast or not, for an address of the member side: ARP.
// - A Neighbor Solicitation, multicast or not, for an address of the member side, from an address of the host (the
//   unspecified one is its duplicate address detection): NS. Its answer goes to the MAC address of its source link-layer
//   address option, or to the source of the frame without one.
// - Any other IPv4 or IPv6 packet to the MAC address of the member side, whose header holds: IP, its bytes the total length
//   of IPv4 or the header and payload of IPv6, without the padding of the frame.
// Anything else is OTHER.
UINT NodeRoutedParseFrame(const UCHAR *frame, UINT size, const UCHAR *member_mac, const NODE_ROUTED_GATEWAY *gw, UINT num, NODE_ROUTED_FRAME *f) {
	if (f == NULL)
		return NODE_ROUTED_FRAME_OTHER;

	Zero(f, sizeof(NODE_ROUTED_FRAME));
	if (frame == NULL || member_mac == NULL || (gw == NULL && num != 0) || size < NODE_ROUTED_ETHER)
		return NODE_ROUTED_FRAME_OTHER;

	UINT type = READ_USHORT(frame + 12);
	const UCHAR *l3 = frame + NODE_ROUTED_ETHER;
	UINT l3_size = size - NODE_ROUTED_ETHER;
	bool to_member = (Cmp(frame, member_mac, 6) == 0);

	if (type == NODE_ROUTED_TYPE_ARP) {
		// Hardware type 1 and protocol IPv4, addresses of 6 and 4 bytes, a request
		if (l3_size < 28 || READ_USHORT(l3) != 1 || READ_USHORT(l3 + 2) != NODE_ROUTED_TYPE_IPV4 || l3[4] != 6 || l3[5] != 4 || READ_USHORT(l3 + 6) != 1)
			return NODE_ROUTED_FRAME_OTHER;
		if (NodeRoutedMember(gw, num, l3 + 24, 4) == false)
			return NODE_ROUTED_FRAME_OTHER;

		f->Kind = NODE_ROUTED_FRAME_ARP;
		f->TargetSize = 4;
		Copy(f->Target, l3 + 24, 4);
		Copy(f->Asker, l3 + 14, 4);
		Copy(f->AskerMac, l3 + 8, 6);
		return f->Kind;
	}

	if (type == NODE_ROUTED_TYPE_IPV4) {
		UINT header = (UINT)(l3_size != 0 ? (l3[0] & 0x0F) * 4 : 0);

		if (to_member == false || l3_size < 20 || (l3[0] >> 4) != 4 || header < 20)
			return NODE_ROUTED_FRAME_OTHER;

		UINT total = READ_USHORT(l3 + 2);
		if (total < header || total > l3_size)
			return NODE_ROUTED_FRAME_OTHER;

		f->Kind = NODE_ROUTED_FRAME_IP;
		f->Offset = NODE_ROUTED_ETHER;
		f->Size = total;
		return f->Kind;
	}

	if (type != NODE_ROUTED_TYPE_IPV6 || l3_size < 40 || (l3[0] >> 4) != 6)
		return NODE_ROUTED_FRAME_OTHER;

	UINT total = 40 + (UINT)READ_USHORT(l3 + 4);
	if (total > l3_size)
		return NODE_ROUTED_FRAME_OTHER;

	// A Neighbor Solicitation: ICMPv6 right after the header, hop limit 255, type 135 and code 0, the target after 8 bytes
	if (l3[6] == NODE_ROUTED_ICMPV6 && total >= 40 + 24 && l3[40] == NODE_ROUTED_NS) {
		static const UCHAR unspecified[16] = {0};
		const UCHAR *ns = l3 + 40;

		if (l3[7] != 255 || ns[1] != 0 || Cmp(l3 + 8, unspecified, 16) == 0 || NodeRoutedMember(gw, num, ns + 8, 16) == false)
			return NODE_ROUTED_FRAME_OTHER;

		f->Kind = NODE_ROUTED_FRAME_NS;
		f->TargetSize = 16;
		Copy(f->Target, ns + 8, 16);
		Copy(f->Asker, l3 + 8, 16);
		Copy(f->AskerMac, frame + 6, 6);

		// The options after the target: the source link-layer address (type 1) names where the answer goes
		for (UINT o = 40 + 24; o + 8 <= total;) {
			UINT len = (UINT)l3[o + 1] * 8;

			if (len == 0 || o + len > total)
				break;
			if (l3[o] == 1 && len == 8)
				Copy(f->AskerMac, l3 + o + 2, 6);
			o += len;
		}

		return f->Kind;
	}

	if (to_member == false)
		return NODE_ROUTED_FRAME_OTHER;

	f->Kind = NODE_ROUTED_FRAME_IP;
	f->Offset = NODE_ROUTED_ETHER;
	f->Size = total;
	return f->Kind;
}

// The answer of the member side to the ARP request or the Neighbor Solicitation f into buf (size bytes): an ARP reply,
// padded to the shortest Ethernet frame, or a Neighbor Advertisement (solicited, override) with the MAC address of the
// member side member_mac as its target link-layer address. Its bytes; 0 when f asks nothing or buf is too small.
UINT NodeRoutedAnswer(UCHAR *buf, UINT size, const NODE_ROUTED_FRAME *f, const UCHAR *member_mac) {
	if (buf == NULL || f == NULL || member_mac == NULL)
		return 0;

	if (f->Kind == NODE_ROUTED_FRAME_ARP) {
		UCHAR *arp = buf + NODE_ROUTED_ETHER;

		if (size < NODE_ROUTED_MIN_FRAME)
			return 0;

		Zero(buf, NODE_ROUTED_MIN_FRAME);
		Copy(buf, f->AskerMac, 6);
		Copy(buf + 6, member_mac, 6);
		WRITE_USHORT(buf + 12, NODE_ROUTED_TYPE_ARP);
		WRITE_USHORT(arp, 1);
		WRITE_USHORT(arp + 2, NODE_ROUTED_TYPE_IPV4);
		arp[4] = 6;
		arp[5] = 4;
		WRITE_USHORT(arp + 6, 2);
		Copy(arp + 8, member_mac, 6);
		Copy(arp + 14, f->Target, 4);
		Copy(arp + 18, f->AskerMac, 6);
		Copy(arp + 24, f->Asker, 4);

		return NODE_ROUTED_MIN_FRAME;
	}

	if (f->Kind == NODE_ROUTED_FRAME_NS) {
		UCHAR *ip = buf + NODE_ROUTED_ETHER;
		UCHAR *na = ip + 40;

		if (size < NODE_ROUTED_NA_SIZE)
			return 0;

		Zero(buf, NODE_ROUTED_NA_SIZE);
		Copy(buf, f->AskerMac, 6);
		Copy(buf + 6, member_mac, 6);
		WRITE_USHORT(buf + 12, NODE_ROUTED_TYPE_IPV6);

		// IPv6 from the address asked for to the asker, 32 bytes of ICMPv6, hop limit 255
		ip[0] = 0x60;
		WRITE_USHORT(ip + 4, 32);
		ip[6] = NODE_ROUTED_ICMPV6;
		ip[7] = 255;
		Copy(ip + 8, f->Target, 16);
		Copy(ip + 24, f->Asker, 16);

		// The advertisement: solicited and override, the target, and its link-layer address in option 2
		na[0] = NODE_ROUTED_NA;
		na[4] = 0x60;
		Copy(na + 8, f->Target, 16);
		na[24] = 2;
		na[25] = 1;
		Copy(na + 26, member_mac, 6);

		USHORT sum = CalcChecksumForIPv6((IPV6_ADDR *)(ip + 8), (IPV6_ADDR *)(ip + 24), NODE_ROUTED_ICMPV6, na, 32, 0);
		Copy(na + 2, &sum, sizeof(sum));

		return NODE_ROUTED_NA_SIZE;
	}

	return 0;
}

// The frame of the IP packet of packet_size bytes of a member of the network of the gateways gw (num of them) into buf (size
// bytes): from the MAC address of the member side member_mac to the adapter adapter_mac, padded to the shortest Ethernet
// frame. Its bytes; 0 when the packet is no IPv4 or IPv6 packet whose header holds, comes from no address of the member
// side, or does not fit.
UINT NodeRoutedFrame(UCHAR *buf, UINT size, const UCHAR *packet, UINT packet_size, const UCHAR *adapter_mac, const UCHAR *member_mac, const NODE_ROUTED_GATEWAY *gw, UINT num) {
	UINT total = 0;
	UINT type = 0;
	const UCHAR *src = NULL;
	UINT src_size = 0;

	if (packet == NULL || adapter_mac == NULL || member_mac == NULL || (gw == NULL && num != 0) || packet_size < 20)
		return 0;

	if ((packet[0] >> 4) == 4) {
		UINT header = (UINT)(packet[0] & 0x0F) * 4;

		total = READ_USHORT(packet + 2);
		if (header < 20 || total < header || total > packet_size)
			return 0;
		type = NODE_ROUTED_TYPE_IPV4;
		src = packet + 12;
		src_size = 4;
	} else if ((packet[0] >> 4) == 6) {
		if (packet_size < 40)
			return 0;
		total = 40 + (UINT)READ_USHORT(packet + 4);
		if (total > packet_size)
			return 0;
		type = NODE_ROUTED_TYPE_IPV6;
		src = packet + 8;
		src_size = 16;
	} else {
		return 0;
	}

	if (NodeRoutedMember(gw, num, src, src_size) == false)
		return 0;

	UINT frame_size = MAX(NODE_ROUTED_ETHER + total, NODE_ROUTED_MIN_FRAME);
	if (buf == NULL || frame_size > size || frame_size > NODE_L2_MAX_FRAME)
		return 0;

	Zero(buf, frame_size);
	Copy(buf, adapter_mac, 6);
	Copy(buf + 6, member_mac, 6);
	WRITE_USHORT(buf + 12, type);
	Copy(buf + NODE_ROUTED_ETHER, packet, total);

	return frame_size;
}

// The supernet of the IPv4 gateways of gw (num of them) into address (4 bytes, network byte order): the longest IPv4 prefix
// that holds the prefix of each, as WinNAT takes one prefix per host. Its length; 0 for none, or for one of length 0.
UINT NodeRoutedSupernet(const NODE_ROUTED_GATEWAY *gw, UINT num, UCHAR *address) {
	UINT super = 0;
	UINT length = 0;
	bool any = false;

	if (address != NULL)
		Zero(address, 4);
	if (gw == NULL || address == NULL)
		return 0;

	for (UINT i = 0; i < num; i++) {
		if (gw[i].Size != 4 || gw[i].Length > 32)
			continue;

		UINT len = gw[i].Length;
		UINT a = READ_UINT(gw[i].Address) & (len == 0 ? 0 : 0xFFFFFFFF << (32 - len));

		if (any == false) {
			super = a;
			length = len;
			any = true;
			continue;
		}

		length = MIN(length, len);
		while (length != 0 && ((super ^ a) >> (32 - length)) != 0)
			length--;
		super &= (length == 0 ? 0 : 0xFFFFFFFF << (32 - length));
	}

	WRITE_UINT(address, super);

	return length;
}

// The MAC address of the KM-TEST adapter of the routed network name on the node of the static key key (PEER_KEY_SIZE bytes):
// the first six bytes of the SHA-256 of NODE_ROUTED_MAC_LABEL, the key and the name in lower case, made a unicast and
// locally administered address, as NodeL2Mac makes the one of an L2 adapter. The same node and Network give the same
// address on every start, so the node finds its adapter again; the member side of the port has the address with the last
// bit flipped.
void NodeRoutedMac(UCHAR *mac, const UCHAR *key, const char *name) {
	UCHAR buf[sizeof(NODE_ROUTED_MAC_LABEL) - 1 + PEER_KEY_SIZE + MAX_HUBNAME_LEN];
	UCHAR hash[SHA256_SIZE];
	char lower[MAX_HUBNAME_LEN + 1];
	UINT label = (UINT)sizeof(NODE_ROUTED_MAC_LABEL) - 1;

	if (mac == NULL || key == NULL || name == NULL)
		return;

	StrCpy(lower, sizeof(lower), name);
	StrLower(lower);
	UINT len = StrLen(lower);

	Copy(buf, NODE_ROUTED_MAC_LABEL, label);
	Copy(buf + label, key, PEER_KEY_SIZE);
	Copy(buf + label + PEER_KEY_SIZE, lower, len);
	Sha2_256(hash, buf, label + PEER_KEY_SIZE + len);

	Copy(mac, hash, 6);
	mac[0] = (UCHAR)((mac[0] & 0xFC) | 0x02);
}

// A frame that the host sent out of the adapter of the routed network param, on the I/O thread of its adapter queue: an
// IP packet to the member side goes to the owner of the member side, an ARP request or a Neighbor Solicitation for an
// address of the network gets the answer of the member side, and anything else is counted and goes no further
static void NodeRoutedFromHost(NODE_L2 *a, void *param, const UCHAR *frame, UINT size) {
	NODE_ROUTED *r = (NODE_ROUTED *)param;
	NODE_ROUTED_FRAME f;
	UCHAR answer[NODE_ROUTED_NA_SIZE];
	UINT len = 0;

	switch (NodeRoutedParseFrame(frame, size, r->MemberMac, r->Gateways, r->NumGateways, &f)) {
	case NODE_ROUTED_FRAME_IP:
		AcquireSRWLockShared(&r->Lock);
		if (r->Proc != NULL) {
			r->Proc(r, r->Param, frame + f.Offset, f.Size);
			InterlockedIncrement64(&r->ToMembers);
		} else {
			InterlockedIncrement64(&r->Unowned);
		}
		ReleaseSRWLockShared(&r->Lock);
		break;
	case NODE_ROUTED_FRAME_ARP:
	case NODE_ROUTED_FRAME_NS:
		len = NodeRoutedAnswer(answer, sizeof(answer), &f, r->MemberMac);
		if (len != 0 && NodeL2Send(a, answer, len))
			InterlockedIncrement64(&r->Answers);
		break;
	default:
		InterlockedIncrement64(&r->Ignored);
		break;
	}
}

// Set the IPv4 or IPv6 interface of a routed network: forwarding (with weak host send and receive, as the gateways of the
// overlay have them) on or off, and no duplicate address detection. ERROR_NOT_FOUND while the stack of the host has no
// interface of that family yet.
static DWORD NodeRoutedSetInterface(NODE_ROUTED *r, ADDRESS_FAMILY family, bool forwarding) {
	MIB_IPINTERFACE_ROW row;

	InitializeIpInterfaceEntry(&row);
	row.Family = family;
	row.InterfaceLuid.Value = r->Luid;
	DWORD err = GetIpInterfaceEntry(&row);
	if (err != NO_ERROR)
		return err;

	if ((row.ForwardingEnabled != FALSE) == forwarding && (row.WeakHostSend != FALSE) == forwarding && (row.WeakHostReceive != FALSE) == forwarding && row.DadTransmits == 0)
		return NO_ERROR;

	row.ForwardingEnabled = (forwarding ? TRUE : FALSE);
	row.WeakHostSend = (forwarding ? TRUE : FALSE);
	row.WeakHostReceive = (forwarding ? TRUE : FALSE);
	row.DadTransmits = 0;
	// SetIpInterfaceEntry refuses the site prefix length that GetIpInterfaceEntry gives (NodeWintunSetForwarding)
	row.SitePrefixLength = 0;

	return SetIpInterfaceEntry(&row);
}

// Whether the routed network has a gateway of size bytes
static bool NodeRoutedHasFamily(NODE_ROUTED *r, UINT size) {
	for (UINT i = 0; i < r->NumGateways; i++)
		if (r->Gateways[i].Size == size)
			return true;

	return false;
}

// Let the kernel forward what the interfaces of the routed network receive, or not, as SetIpInterfaceEntry sets it: the
// IPv4 interface and the IPv6 one, which the stack of the host may take a moment to have after the KM-TEST adapter came
// up. An interface of a family that the network has no gateway of may be missing. False when one could not be set; the
// node log says which.
bool NodeRoutedSetForwarding(NODE_ROUTED *r, bool on) {
	bool ok = true;

	if (r == NULL)
		return false;

	for (UINT i = 0; i < 2; i++) {
		ADDRESS_FAMILY family = (ADDRESS_FAMILY)(i == 0 ? AF_INET : AF_INET6);
		bool needed = NodeRoutedHasFamily(r, i == 0 ? 4 : 16);
		DWORD err = NodeRoutedSetInterface(r, family, on);

		for (UINT64 end = GetTickCount64() + NODE_ROUTED_WAIT; err == ERROR_NOT_FOUND && needed && GetTickCount64() < end;) {
			Sleep(NODE_ROUTED_POLL);
			err = NodeRoutedSetInterface(r, family, on);
		}

		if (err == ERROR_NOT_FOUND && needed == false)
			continue;
		if (err != NO_ERROR) {
			NodeLog(r->Node, "Routed network %s: the forwarding of its %s interface could not be set %s (error %u)", r->Name, i == 0 ? "IPv4" : "IPv6", on ? "on" : "off", (UINT)err);
			ok = false;
		}
	}

	return ok;
}

// The unicast address row of the gateway i of a routed network
static void NodeRoutedAddressRow(NODE_ROUTED *r, UINT i, MIB_UNICASTIPADDRESS_ROW *row) {
	const NODE_ROUTED_GATEWAY *gw = &r->Gateways[i];

	InitializeUnicastIpAddressEntry(row);
	row->InterfaceLuid.Value = r->Luid;
	if (gw->Size == 4) {
		row->Address.Ipv4.sin_family = AF_INET;
		Copy(&row->Address.Ipv4.sin_addr, gw->Address, 4);
	} else {
		row->Address.Ipv6.sin6_family = AF_INET6;
		Copy(&row->Address.Ipv6.sin6_addr, gw->Address, 16);
	}
	row->OnLinkPrefixLength = (UINT8)gw->Length;
	row->DadState = IpDadStatePreferred;
}

// Give the interfaces of a routed network its gateway addresses, and wait up to NODE_ROUTED_WAIT for each to be preferred.
// An address that the interface holds from an earlier run is the node's as well. False when one cannot be added or does
// not become preferred; the node log says which.
static bool NodeRoutedAddresses(NODE_ROUTED *r) {
	MIB_UNICASTIPADDRESS_ROW row;

	for (UINT i = 0; i < r->NumGateways; i++) {
		NodeRoutedAddressRow(r, i, &row);
		DWORD err = CreateUnicastIpAddressEntry(&row);
		if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS) {
			NodeLog(r->Node, "Routed network %s: its gateway address %u could not be added (error %u)", r->Name, i, (UINT)err);
			return false;
		}
		r->Made[i] = true;
	}

	for (UINT i = 0; i < r->NumGateways; i++) {
		DWORD err = NO_ERROR;
		bool preferred = false;

		for (UINT64 end = GetTickCount64() + NODE_ROUTED_WAIT; preferred == false;) {
			NodeRoutedAddressRow(r, i, &row);
			err = GetUnicastIpAddressEntry(&row);
			preferred = (err == NO_ERROR && row.DadState == IpDadStatePreferred);
			if (preferred || GetTickCount64() >= end)
				break;
			Sleep(NODE_ROUTED_POLL);
		}

		if (preferred == false) {
			NodeLog(r->Node, "Routed network %s: its gateway address %u is not preferred within %u ms (error %u, DAD state %u)", r->Name, i, (UINT)NODE_ROUTED_WAIT, (UINT)err, (UINT)row.DadState);
			return false;
		}
	}

	return true;
}

// Bring up a routed network on the node n: its KM-TEST adapter, found again by its MAC address or created, whose
// interfaces forward and hold its gateway addresses, and the L2 adapter on it, the port. NULL when one of them does not
// come up; the node log says which.
NODE_ROUTED *NodeRoutedNew(NODE *n, const NODE_ROUTED_CONFIG *cfg) {
	NET_LUID luid;
	NODE_L2_CONFIG l2;

	if (n == NULL || cfg == NULL || cfg->NumGateways == 0 || cfg->NumGateways > NODE_ROUTED_MAX_GATEWAYS)
		return NULL;

	NODE_ROUTED *r = ZeroMalloc(sizeof(NODE_ROUTED));
	r->Node = n;
	StrCpy(r->Name, sizeof(r->Name), cfg->Name);
	r->NumGateways = cfg->NumGateways;
	Copy(r->Gateways, cfg->Gateways, sizeof(NODE_ROUTED_GATEWAY) * cfg->NumGateways);
	r->Nat = cfg->Nat;
	InitializeSRWLock(&r->Lock);
	NodeRoutedMac(r->Mac, cfg->Key, cfg->Name);
	Copy(r->MemberMac, r->Mac, 6);
	r->MemberMac[5] ^= 0x01;

	r->KmTest = NodeKmTestNew(n, r->Mac);
	r->IfIndex = NodeKmTestIndex(r->KmTest);
	if (r->KmTest == NULL || ConvertInterfaceIndexToLuid(r->IfIndex, &luid) != NO_ERROR) {
		NodeLog(n, "Routed network %s: no KM-TEST adapter for its port", r->Name);
		NodeRoutedFree(r);
		return NULL;
	}
	r->Luid = luid.Value;

	if (NodeRoutedSetForwarding(r, true) == false || NodeRoutedAddresses(r) == false) {
		NodeRoutedFree(r);
		return NULL;
	}

	Zero(&l2, sizeof(l2));
	l2.IfIndex = r->IfIndex;
	l2.Proc = NodeRoutedFromHost;
	l2.Param = r;
	l2.Reset = NodeKmTestReset;
	l2.ResetParam = r->KmTest;
	l2.Backends = cfg->Backends;
	l2.NumBackends = cfg->NumBackends;
	r->L2 = NodeL2New(n, &l2);
	if (r->L2 == NULL) {
		NodeLog(n, "Routed network %s: no backend carries the frames of its port", r->Name);
		NodeRoutedFree(r);
		return NULL;
	}

	NodeLog(n, "Routed network %s up: KM-TEST adapter of interface %u, %u gateway addresses, forwarding on, %s", r->Name, r->IfIndex, r->NumGateways, r->Nat ? "NAT to the internet" : "no NAT");

	return r;
}

// Take a routed network down: its port first, so that nothing calls its owner any more, then its gateway addresses. Its
// KM-TEST adapter stays, for the next start.
void NodeRoutedFree(NODE_ROUTED *r) {
	MIB_UNICASTIPADDRESS_ROW row;

	if (r == NULL)
		return;

	if (NodeL2Free(r->L2) == false) {
		// The port may still call it: the routed network stays, as a leak rather than a freed owner
		NodeLog(r->Node, "Routed network %s: its port did not stop in time, so it stays", r->Name);
		return;
	}
	r->L2 = NULL;

	for (UINT i = 0; i < r->NumGateways; i++) {
		if (r->Made[i] == false)
			continue;

		NodeRoutedAddressRow(r, i, &row);
		DWORD err = DeleteUnicastIpAddressEntry(&row);
		if (err != NO_ERROR && err != ERROR_NOT_FOUND)
			NodeLog(r->Node, "Routed network %s: its gateway address %u could not be taken out (error %u)", r->Name, i, (UINT)err);
	}

	NodeKmTestFree(r->KmTest, false);
	Free(r);
}

// An IP packet of a member of the routed network into the host, as a frame from the member side of its port. False when
// the port refuses it: no IPv4 or IPv6 packet, from no address of the network, or too long; or when its send ring is full.
bool NodeRoutedSend(NODE_ROUTED *r, const UCHAR *packet, UINT size) {
	UCHAR frame[NODE_L2_MAX_FRAME];

	if (r == NULL)
		return false;

	UINT len = NodeRoutedFrame(frame, sizeof(frame), packet, size, r->Mac, r->MemberMac, r->Gateways, r->NumGateways);
	if (len == 0) {
		InterlockedIncrement64(&r->Refused);
		return false;
	}

	if (NodeL2Send(r->L2, frame, len) == false)
		return false;

	InterlockedIncrement64(&r->FromMembers);
	return true;
}

// Set the owner of the member side of a routed network, which takes the IP packets that the kernel routes to its members:
// NULL for none. Once it returns, the owner of before is called no more.
void NodeRoutedSetProc(NODE_ROUTED *r, NODE_ROUTED_PROC *proc, void *param) {
	if (r == NULL)
		return;

	AcquireSRWLockExclusive(&r->Lock);
	r->Proc = proc;
	r->Param = param;
	ReleaseSRWLockExclusive(&r->Lock);
}

// Whether the kernel forwards what the interface of family of a routed network receives, as GetIpInterfaceEntry reads it
static bool NodeRoutedForwards(NODE_ROUTED *r, ADDRESS_FAMILY family) {
	MIB_IPINTERFACE_ROW row;

	InitializeIpInterfaceEntry(&row);
	row.Family = family;
	row.InterfaceLuid.Value = r->Luid;

	return (GetIpInterfaceEntry(&row) == NO_ERROR && row.ForwardingEnabled != FALSE);
}

// The state of a routed network
void NodeRoutedGetStatus(NODE_ROUTED *r, NODE_ROUTED_STATUS *st) {
	NODE_L2_STATUS l2;

	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_ROUTED_STATUS));
	if (r == NULL)
		return;

	st->IfIndex = r->IfIndex;
	Copy(st->Mac, r->Mac, 6);
	Copy(st->MemberMac, r->MemberMac, 6);
	st->Forwarding4 = NodeRoutedForwards(r, AF_INET);
	st->Forwarding6 = NodeRoutedForwards(r, AF_INET6);
	st->Nat = r->Nat;

	NodeL2GetStatus(r->L2, &l2);
	StrCpy(st->Backend, sizeof(st->Backend), l2.Backend);

	st->FromMembers = (UINT64)ReadAcquire64(&r->FromMembers);
	st->ToMembers = (UINT64)ReadAcquire64(&r->ToMembers);
	st->Answers = (UINT64)ReadAcquire64(&r->Answers);
	st->Refused = (UINT64)ReadAcquire64(&r->Refused);
	st->Ignored = (UINT64)ReadAcquire64(&r->Ignored);
	st->Unowned = (UINT64)ReadAcquire64(&r->Unowned);
}

//
// The routed networks of the server role
//

// Put the IPv4 prefixes of the routed networks that go through NAT into the NAT network of WinNAT of the node, over their
// supernet, where no NAT network of WinNAT exists (NodeEgressNat.c). One of another program is never touched, and one of the
// node over another prefix, which the Egress of the overlay holds, stays as it is: those routed networks then have no NAT,
// and the node log says why.
static void NodeRoutedNatUp(NODE *n, NODE_ROUTED_SET *set) {
	NODE_ROUTED_GATEWAY gw[NODE_ROUTED_MAX_NAT];
	UCHAR super[4];
	char prefix[NODE_ROUTED_PREFIX];
	wchar_t want[NODE_ROUTED_PREFIX];
	wchar_t have[NODE_ROUTED_PREFIX];
	UINT num = 0;

	for (UINT i = 0; i < LIST_NUM(set->Networks); i++) {
		NODE_ROUTED *r = LIST_DATA(set->Networks, i);

		for (UINT j = 0; r->Nat && j < r->NumGateways && num < NODE_ROUTED_MAX_NAT; j++)
			if (r->Gateways[j].Size == 4)
				gw[num++] = r->Gateways[j];
	}
	if (num == 0)
		return;

	UINT length = NodeRoutedSupernet(gw, num, super);
	if (length < NODE_EGRESS_SUPERNET) {
		NodeLog(n, "Routed networks: no NAT, as their IPv4 prefixes span more than a supernet that WinNAT takes (/%u)", (UINT)NODE_EGRESS_SUPERNET);
		return;
	}

	Format(prefix, sizeof(prefix), "%u.%u.%u.%u/%u", (UINT)super[0], (UINT)super[1], (UINT)super[2], (UINT)super[3], length);
	StrToUni(want, sizeof(want), prefix);

	bool found = NodeEgressNetNatPrefix(NODE_EGRESS_NETNAT_NAME, have, sizeof(have));
	if (NodeEgressForeignNetNat()) {
		NodeLog(n, "Routed networks: no NAT, as a NAT network of WinNAT of another program exists, which the node leaves alone");
		return;
	}
	if (found && UniStrCmpi(have, want) != 0) {
		NodeLog(n, "Routed networks: no NAT, as the NAT network of WinNAT of the node, %S, is over %S, which the Egress of the overlay holds", NODE_EGRESS_NETNAT_NAME, have);
		return;
	}
	if (found == false && NodeEgressNetNatAdd(NODE_EGRESS_NETNAT_NAME, want) == false) {
		NodeLog(n, "Routed networks: no NAT, as the NAT network of WinNAT of the node could not be made over %s", prefix);
		return;
	}

	set->NetNat = (found == false);
	UniStrCpy(set->Prefix, sizeof(set->Prefix), want);
	NodeLog(n, "Routed networks: to the internet through the NAT network of WinNAT of the node, %S, over %s%s", NODE_EGRESS_NETNAT_NAME, prefix, found ? ", which was there" : "");
}

// Take out the NAT network of WinNAT that the routed networks made, as long as it is still over the prefix that they gave it
static void NodeRoutedNatDown(NODE *n, NODE_ROUTED_SET *set) {
	wchar_t have[NODE_ROUTED_PREFIX];

	if (set->NetNat == false)
		return;
	set->NetNat = false;

	if (NodeEgressNetNatPrefix(NODE_EGRESS_NETNAT_NAME, have, sizeof(have)) == false || UniStrCmpi(have, set->Prefix) != 0)
		return;

	bool removed = NodeEgressNetNatRemove(NODE_EGRESS_NETNAT_NAME);
	NodeLog(n, "Routed networks: the NAT network of WinNAT of the node, %S, %s", NODE_EGRESS_NETNAT_NAME, removed ? "taken out" : "could not be taken out");
}

// Bring up the routed network of the L3 Network name with the Routed setting setting, under the static key key: NULL when the
// setting gives it no gateway or it does not come up; the node log says why
static NODE_ROUTED *NodeRoutedUp(NODE *n, const char *name, const char *setting, const UCHAR *key) {
	NODE_ROUTED_CONFIG cfg;

	Zero(&cfg, sizeof(cfg));
	StrCpy(cfg.Name, sizeof(cfg.Name), name);
	Copy(cfg.Key, key, PEER_KEY_SIZE);

	if (NodeRoutedParseSetting(setting, name, cfg.Gateways, &cfg.NumGateways, &cfg.Nat) == false) {
		NodeLog(n, "Network %s stays down: the %s setting gives it no valid gateway address", name, NODE_SETTING_ROUTED);
		return NULL;
	}

	return NodeRoutedNew(n, &cfg);
}

// The routed networks of the server role: one for each L3 Network of the configuration store that is online and that the
// Routed setting gives gateway addresses, with the MAC addresses of the node identity key, then their NAT. True when at
// least one came up. The caller holds the node lock.
bool NodeRoutedStart(NODE *n) {
	PEER_KEY key;
	wchar_t key_name[MAX_SIZE];
	UINT num_l3 = 0;

	if (n == NULL || n->Store == NULL || n->Routed != NULL)
		return false;

	Zero(&key, sizeof(key));
	LIST *o = CsEnumNetworks(n->Store);
	for (UINT i = 0; i < LIST_NUM(o); i++)
		if (((CS_NETWORK *)LIST_DATA(o, i))->Mode == CS_MODE_L3)
			num_l3++;

	char *setting = ZeroMalloc(NODE_ROUTED_MAX_SETTING);
	bool have = (num_l3 != 0 && CsGetSetting(n->Store, NODE_SETTING_ROUTED, setting, NODE_ROUTED_MAX_SETTING) && IsEmptyStr(setting) == false);

	StrToUni(key_name, sizeof(key_name), n->IdentityKey);
	if (num_l3 != 0 && have == false)
		NodeLog(n, "Routed networks: %u L3 Networks stay down, as there is no %s setting", num_l3, NODE_SETTING_ROUTED);
	else if (have && PeerKeyOpen(&key, key_name) == false) {
		NodeLog(n, "Routed networks: the identity key \"%s\" cannot be opened or created", n->IdentityKey);
		have = false;
	}

	NODE_ROUTED_SET *set = NULL;
	if (have) {
		set = ZeroMalloc(sizeof(NODE_ROUTED_SET));
		set->Networks = NewListFast(NULL);

		for (UINT i = 0; i < LIST_NUM(o); i++) {
			CS_NETWORK *net = LIST_DATA(o, i);

			if (net->Mode != CS_MODE_L3)
				continue;
			if (net->Online == false) {
				NodeLog(n, "Network %s stays down: it is offline", net->Name);
				continue;
			}

			NODE_ROUTED *r = NodeRoutedUp(n, net->Name, setting, key.Public);
			if (r != NULL)
				Add(set->Networks, r);
		}

		PeerKeyClose(&key);
	}

	Free(setting);
	CsFreeNetworkList(o);

	if (set == NULL)
		return false;

	if (LIST_NUM(set->Networks) == 0) {
		ReleaseList(set->Networks);
		Free(set);
		return false;
	}

	NodeRoutedNatUp(n, set);
	n->Routed = set;
	NodeLog(n, "Routed networks: %u up, the kernel routes between them", LIST_NUM(set->Networks));

	return true;
}

// Take the routed networks of the server role down, and the NAT network of WinNAT that they made. The caller holds the node
// lock.
void NodeRoutedStop(NODE *n) {
	if (n == NULL || n->Routed == NULL)
		return;

	NODE_ROUTED_SET *set = n->Routed;
	n->Routed = NULL;

	NodeRoutedNatDown(n, set);

	UINT num = LIST_NUM(set->Networks);
	for (UINT i = 0; i < num; i++)
		NodeRoutedFree(LIST_DATA(set->Networks, i));

	ReleaseList(set->Networks);
	Free(set);

	NodeLog(n, "Routed networks: %u down", num);
}

// The routed network of the L3 Network name of the running server role, NULL for none. It stays valid while the role
// runs.
NODE_ROUTED *NodeRoutedFind(NODE *n, const char *name) {
	NODE_ROUTED *ret = NULL;

	if (n == NULL || name == NULL)
		return NULL;

	Lock(n->Lock);
	{
		NODE_ROUTED_SET *set = n->Routed;

		for (UINT i = 0; set != NULL && i < LIST_NUM(set->Networks) && ret == NULL; i++) {
			NODE_ROUTED *r = LIST_DATA(set->Networks, i);

			if (StrCmpi(r->Name, name) == 0)
				ret = r;
		}
	}
	Unlock(n->Lock);

	return ret;
}
