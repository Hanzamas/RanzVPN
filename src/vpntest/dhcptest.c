// dhcptest.c
// Named DHCP responder test of vpntest ("dhcp" command, SDN-43 #236)
//
// The DHCP responder of an L2 Network (Cedar/NodeDhcp.c) as a member of the switch of the Network (Core/Switch.h), in
// process. Its configuration is the CONTROL_DHCP that the desired state of the node that answers DHCP for the Network
// carries (Core/Control.h): the IPv4 pool 10.20.0.0/24 with the reservations 10.20.0.0/29 and 10.20.0.100 of the
// Network, the responder's own address 10.20.0.2, the gateway 10.20.0.1, the DNS servers 10.20.0.53 and 192.0.2.53 and
// a lease time of one hour. The clients and a DHCP server of the LAN are members of the switch that keep the frames they
// get; every frame of the responder must carry valid IPv4 and UDP checksums.
// - responder (on the clock of the test): its first frame is a probe, a DHCPDISCOVER from its own MAC address, and it
//   answers no client before NODE_DHCP_PROBE_WAIT. A client gets the lowest free address, 10.20.0.8, with the mask, the
//   gateway, the DNS servers and the lease time in the DHCPOFFER and the DHCPACK, and the lease shows its MAC address,
//   its host name and its end. The responder answers the ARP request for its own address, renews a lease by unicast,
//   does not offer a reservation, lets an offer go when the client takes another server's, refuses (DHCPNAK) an address
//   of another network or of another client, keeps a declined address out of use, ends a released lease and one whose
//   time ran out, and answers DHCPINFORM without a lease.
// - LAN server: a DHCP server of the LAN answers the probe, and the responder answers no client until
//   NODE_DHCP_LAN_HOLD passed without another answer.
// - mode off: a responder whose mode is not pool sends no probe and answers no client.
// - node: a node whose overlay applies a state with the responder of Network lan runs it on the switch that the L2 data
//   path attached (NodeDhcpAttach), and a client gets its address through the thread of the responders; a state without
//   the responder stops it, and a DHCPDISCOVER then goes unanswered.
// Print "DHCP TEST OK" only when every check passes.

#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include "Core/Control.h"
#include "Core/Switch.h"
#include "Core/Transport.h"

#include <stdio.h>

#define	DHCPTEST_BUDGET			120000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	DHCPTEST_BOUND			10000		// A bounded wait on the thread of the responders of a node (ms)
#define	DHCPTEST_QUIET			1000		// How long the node case waits for a frame that must not come (ms)
#define	DHCPTEST_POLL			10			// Poll interval of that wait (ms)
#define	DHCPTEST_START			1000000		// The clock of the test at the start (ms), any time but 0
#define	DHCPTEST_VLAN			1			// The VLAN of the Network on its switch
#define	DHCPTEST_LEASE			3600		// The lease time (s)
#define	DHCPTEST_MAX_FRAMES		8			// Frames that a member keeps at most
#define	DHCPTEST_NETWORK		"lan"		// The L2 Network
#define	DHCPTEST_IP(a, b, c, d)	(((UINT)(a) << 24) | ((UINT)(b) << 16) | ((UINT)(c) << 8) | (UINT)(d))

#define	DHCPTEST_CLIENT_A		0
#define	DHCPTEST_CLIENT_B		1
#define	DHCPTEST_LAN			2			// The DHCP server of the LAN
#define	DHCPTEST_NUM_MEMBERS	3

static const UCHAR dhcptest_responder_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x43, 0x01};
static const UCHAR dhcptest_macs[DHCPTEST_NUM_MEMBERS][6] = {
	{0x02, 0x00, 0x00, 0x00, 0x43, 0x0A},
	{0x02, 0x00, 0x00, 0x00, 0x43, 0x0B},
	{0x02, 0x00, 0x00, 0x00, 0x43, 0x5E},
};

// The checks of the test
typedef struct DHCPTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} DHCPTEST_CTX;

// A member of the switch that keeps the frames it gets: a client, or the DHCP server of the LAN
typedef struct DHCPTEST_MEMBER
{
	UINT Port;									// Its port
	SRWLOCK Lock;								// The frames: the thread of the responders of a node delivers them too
	UINT NumFrames;								// The frames it got
	UINT Sizes[DHCPTEST_MAX_FRAMES];			// ... their sizes
	UCHAR Frames[DHCPTEST_MAX_FRAMES][NODE_DHCP_MAX_FRAME];	// ... and their bytes
} DHCPTEST_MEMBER;

// The switch of the Network with its members, and the responder that the test runs on its clock
typedef struct DHCPTEST_NET
{
	SWITCH *Switch;
	UINT64 Clock;								// The clock of the test (ms)
	NODE_DHCP *Dhcp;							// The responder, NULL for none
	UINT DhcpPort;								// ... and its port
	DHCPTEST_MEMBER Members[DHCPTEST_NUM_MEMBERS];
} DHCPTEST_NET;

// A DHCP message as a member got it
typedef struct DHCPTEST_MSG
{
	UCHAR DstMac[6];
	UCHAR SrcMac[6];
	UINT SrcIp;									// The addresses of the packet, in host byte order
	UINT DstIp;
	USHORT SrcPort;
	USHORT DstPort;
	bool Checksums;								// The IPv4 and UDP checksums are valid
	UINT Op;
	UINT Type;									// The message type (option 53)
	UINT Xid;
	USHORT Flags;
	UINT ClientIp;								// ciaddr and yiaddr, in host byte order
	UINT YourIp;
	UCHAR ClientMac[6];
	UINT ServerId;								// The options, 0 for none
	UINT Mask;
	UINT Router;
	UINT LeaseTime;
	UINT Renewal;
	UINT Rebinding;
	UINT NumDns;
	UINT Dns[4];
} DHCPTEST_MSG;

static bool DhcpTestCheck(DHCPTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool DhcpTestCheck(DHCPTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
{
	char detail[MAX_SIZE * 2];
	va_list args;

	ctx->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return true;
	}

	va_start(args, fmt);
	FormatArgs(detail, sizeof(detail), fmt, args);
	va_end(args);

	Print("  [FAIL] %s: %s\n", what, detail);
	ctx->NumFailed++;

	return false;
}

// The watchdog: a native thread that ends a run that hangs, so that a lost wake-up is a failed test instead of a hung CI
// step. Its parameter is the event that ends it.
static DWORD WINAPI DhcpTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, DHCPTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "DHCP TEST FAILED (did not finish within %u ms)\n", (UINT)DHCPTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// An IPv4 address of host byte order as text
static char *DhcpTestIp(char *str, UINT size, UINT ip)
{
	Format(str, size, "%u.%u.%u.%u", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
	return str;
}

//
// The members
//

// Takes the frames that the switch delivers to a member (SWITCH_SEND_PROC)
static void DhcpTestMemberSend(void *param, UINT port, const UCHAR *frame, UINT size)
{
	DHCPTEST_MEMBER *m = (DHCPTEST_MEMBER *)param;

	UNREFERENCED_PARAMETER(port);
	AcquireSRWLockExclusive(&m->Lock);
	if (m->NumFrames < DHCPTEST_MAX_FRAMES && size <= NODE_DHCP_MAX_FRAME)
	{
		Copy(m->Frames[m->NumFrames], frame, size);
		m->Sizes[m->NumFrames] = size;
		m->NumFrames++;
	}
	ReleaseSRWLockExclusive(&m->Lock);
}

// Takes the frames that the switch delivers to the responder that the test runs, on the clock of the test
static void DhcpTestResponderSend(void *param, UINT port, const UCHAR *frame, UINT size)
{
	DHCPTEST_NET *net = (DHCPTEST_NET *)param;

	UNREFERENCED_PARAMETER(port);
	NodeDhcpInput(net->Dhcp, net->Clock, frame, size);
}

// Forget the frames that the members got
static void DhcpTestClear(DHCPTEST_NET *net)
{
	for (UINT i = 0;i < DHCPTEST_NUM_MEMBERS;i++)
	{
		DHCPTEST_MEMBER *m = &net->Members[i];

		AcquireSRWLockExclusive(&m->Lock);
		m->NumFrames = 0;
		ReleaseSRWLockExclusive(&m->Lock);
	}
}

// The frames that the member i got
static UINT DhcpTestCount(DHCPTEST_NET *net, UINT i)
{
	DHCPTEST_MEMBER *m = &net->Members[i];

	AcquireSRWLockShared(&m->Lock);
	UINT num = m->NumFrames;
	ReleaseSRWLockShared(&m->Lock);

	return num;
}

// The switch of the Network with a port for each member, on access ports of DHCPTEST_VLAN that take the broadcast group
static bool DhcpTestNewNet(DHCPTEST_NET *net)
{
	static const UCHAR bc[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	SWITCH_CONFIG sc;
	bool ok = true;

	Zero(net, sizeof(DHCPTEST_NET));
	Zero(&sc, sizeof(sc));
	net->Switch = SwitchNew(&sc);
	net->Clock = DHCPTEST_START;
	net->DhcpPort = SWITCH_PORT_NONE;
	if (net->Switch == NULL)
	{
		return false;
	}

	for (UINT i = 0;i < DHCPTEST_NUM_MEMBERS;i++)
	{
		DHCPTEST_MEMBER *m = &net->Members[i];
		SWITCH_PORT_CONFIG pc;

		InitializeSRWLock(&m->Lock);
		Zero(&pc, sizeof(pc));
		pc.Mode = SWITCH_ACCESS;
		pc.Vlan = DHCPTEST_VLAN;
		pc.Send = DhcpTestMemberSend;
		pc.Param = m;
		m->Port = SwitchAddPort(net->Switch, &pc);
		ok = ok && m->Port != SWITCH_PORT_NONE && SwitchSubscribe(net->Switch, m->Port, DHCPTEST_VLAN, bc);
	}

	return ok;
}

// The responder of the configuration cfg on its own port of the switch, at the clock of the test
static bool DhcpTestStartResponder(DHCPTEST_NET *net, const NODE_DHCP_CONFIG *cfg)
{
	static const UCHAR bc[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	SWITCH_PORT_CONFIG pc;

	net->Dhcp = NodeDhcpNew(cfg, net->Clock);
	Zero(&pc, sizeof(pc));
	pc.Mode = SWITCH_ACCESS;
	pc.Vlan = DHCPTEST_VLAN;
	pc.Send = DhcpTestResponderSend;
	pc.Param = net;
	net->DhcpPort = SwitchAddPort(net->Switch, &pc);

	return net->Dhcp != NULL && net->DhcpPort != SWITCH_PORT_NONE && SwitchSubscribe(net->Switch, net->DhcpPort, DHCPTEST_VLAN, bc);
}

// The responder leaves the switch and goes
static void DhcpTestStopResponder(DHCPTEST_NET *net)
{
	if (net->DhcpPort != SWITCH_PORT_NONE)
	{
		SwitchDelPort(net->Switch, net->DhcpPort);
		net->DhcpPort = SWITCH_PORT_NONE;
	}
	NodeDhcpFree(net->Dhcp);
	net->Dhcp = NULL;
}

// The frames of the responder into the switch, at the clock of the test: their number
static UINT DhcpTestPump(DHCPTEST_NET *net)
{
	UCHAR buf[NODE_DHCP_MAX_FRAME];
	UINT num = 0;
	UINT size;

	while (net->Dhcp != NULL && (size = NodeDhcpOutput(net->Dhcp, net->Clock, buf, sizeof(buf))) != 0)
	{
		SwitchInput(net->Switch, net->Clock, net->DhcpPort, buf, size);
		num++;
	}

	return num;
}

//
// The frames
//

// The UDP datagram of size bytes from src_ip:src_port to dst_ip:dst_port in a frame from src_mac to dst_mac, with its
// checksums, into f; the addresses in host byte order. Its size.
static UINT DhcpTestUdpFrame(UCHAR *f, const UCHAR *dst_mac, const UCHAR *src_mac, UINT src_ip, USHORT src_port, UINT dst_ip, USHORT dst_port, const UCHAR *data, UINT size)
{
	MAC_HEADER *mac = (MAC_HEADER *)f;
	IPV4_HEADER *ip = (IPV4_HEADER *)(f + sizeof(MAC_HEADER));
	UDP_HEADER *udp = (UDP_HEADER *)(f + sizeof(MAC_HEADER) + sizeof(IPV4_HEADER));
	UINT total = sizeof(MAC_HEADER) + sizeof(IPV4_HEADER) + sizeof(UDP_HEADER) + size;

	Zero(f, total);
	Copy(mac->DestAddress, dst_mac, 6);
	Copy(mac->SrcAddress, src_mac, 6);
	mac->Protocol = Endian16(MAC_PROTO_IPV4);
	IPV4_SET_VERSION(ip, 4);
	IPV4_SET_HEADER_LEN(ip, 5);
	ip->TotalLength = Endian16((USHORT)(sizeof(IPV4_HEADER) + sizeof(UDP_HEADER) + size));
	ip->TimeToLive = 128;
	ip->Protocol = IP_PROTO_UDP;
	ip->SrcIP = Endian32(src_ip);
	ip->DstIP = Endian32(dst_ip);
	ip->Checksum = IpChecksum(ip, sizeof(IPV4_HEADER));
	udp->SrcPort = Endian16(src_port);
	udp->DstPort = Endian16(dst_port);
	udp->PacketLength = Endian16((USHORT)(sizeof(UDP_HEADER) + size));
	Copy(((UCHAR *)udp) + sizeof(UDP_HEADER), data, size);
	udp->Checksum = CalcChecksumForIPv4(ip->SrcIP, ip->DstIP, IP_PROTO_UDP, udp, sizeof(UDP_HEADER) + size, 0);

	return total;
}

// A DHCP message of op and type into buf: the transaction id xid, the broadcast flag, ciaddr and yiaddr (host byte
// order), chaddr, and the options requested (50), server (54) and host (12), each left out when 0 or NULL. Its size,
// padded to DHCP_MIN_SIZE.
static UINT DhcpTestMessage(UCHAR *buf, UINT op, UINT type, UINT xid, bool broadcast, UINT ciaddr, UINT yiaddr, const UCHAR *chaddr, UINT requested, UINT server, const char *host)
{
	DHCPV4_HEADER *h = (DHCPV4_HEADER *)buf;
	LIST *o = NewListFast(NULL);
	UCHAR t = (UCHAR)type;
	UCHAR be[4];

	Add(o, NewDhcpOption(DHCP_ID_MESSAGE_TYPE, &t, 1));
	if (requested != 0)
	{
		WRITE_UINT(be, requested);
		Add(o, NewDhcpOption(DHCP_ID_REQUEST_IP_ADDRESS, be, 4));
	}
	if (server != 0)
	{
		WRITE_UINT(be, server);
		Add(o, NewDhcpOption(DHCP_ID_SERVER_ID, be, 4));
	}
	if (host != NULL)
	{
		Add(o, NewDhcpOption(DHCP_ID_HOST_NAME, host, StrLen(host)));
	}
	BUF *b = BuildDhcpOptionsBuf(o);
	FreeDhcpOptions(o);

	UINT size = MAX(240 + b->Size, DHCP_MIN_SIZE);
	Zero(buf, size);
	h->OpCode = (UCHAR)op;
	h->HardwareType = ARP_HARDWARE_TYPE_ETHERNET;
	h->HardwareAddressSize = 6;
	h->TransactionId = Endian32(xid);
	h->Flags = Endian16(broadcast ? 0x8000 : 0);
	h->ClientIP = Endian32(ciaddr);
	h->YourIP = Endian32(yiaddr);
	Copy(h->ClientMacAddress, chaddr, 6);
	WRITE_UINT(buf + 236, DHCP_MAGIC_COOKIE);
	Copy(buf + 240, b->Buf, b->Size);
	FreeBuf(b);

	return size;
}

// A client member sends a DHCP message of type: to the broadcast address, or with ciaddr set by unicast to the
// responder (unicast true), as a client in RENEWING does
static void DhcpTestClientSends(DHCPTEST_NET *net, UINT member, UINT type, UINT xid, bool broadcast, UINT ciaddr, UINT requested, UINT server, const char *host, bool unicast)
{
	static const UCHAR bc[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	UCHAR msg[1024];
	UCHAR frame[NODE_DHCP_MAX_FRAME];
	const UCHAR *mac = dhcptest_macs[member];

	UINT size = DhcpTestMessage(msg, 1, type, xid, broadcast, ciaddr, 0, mac, requested, server, host);
	size = DhcpTestUdpFrame(frame, (unicast ? dhcptest_responder_mac : bc), mac, ciaddr, 68, (unicast ? DHCPTEST_IP(10, 20, 0, 2) : 0xFFFFFFFF), 67, msg, size);
	SwitchInput(net->Switch, net->Clock, net->Members[member].Port, frame, size);
}

// Read a DHCP message of a frame: false when the frame is none
static bool DhcpTestParse(const UCHAR *frame, UINT size, DHCPTEST_MSG *m)
{
	UCHAR buf[NODE_DHCP_MAX_FRAME];
	bool ok = false;

	Zero(m, sizeof(DHCPTEST_MSG));
	if (size > sizeof(buf))
	{
		return false;
	}
	Copy(buf, frame, size);

	PKT *p = ParsePacket(buf, size);
	if (p != NULL && p->TypeL3 == L3_IPV4 && p->TypeL4 == L4_UDP && p->TypeL7 == L7_DHCPV4)
	{
		IPV4_HEADER *ip = p->L3.IPv4Header;
		UDP_HEADER *udp = p->L4.UDPHeader;
		DHCPV4_HEADER *h = p->L7.DHCPv4Header;
		UINT udp_size = Endian16(udp->PacketLength);
		UINT options_size = 0;

		Copy(m->DstMac, p->MacHeader->DestAddress, 6);
		Copy(m->SrcMac, p->MacHeader->SrcAddress, 6);
		m->SrcIp = Endian32(ip->SrcIP);
		m->DstIp = Endian32(ip->DstIP);
		m->SrcPort = Endian16(udp->SrcPort);
		m->DstPort = Endian16(udp->DstPort);
		// A checksum over a header or a datagram with its own checksum in it gives 0
		m->Checksums = (IpChecksum(ip, sizeof(IPV4_HEADER)) == 0 && udp_size == sizeof(UDP_HEADER) + p->PayloadSize &&
			CalcChecksumForIPv4(ip->SrcIP, ip->DstIP, IP_PROTO_UDP, udp, udp_size, 0) == 0);
		m->Op = h->OpCode;
		m->Xid = Endian32(h->TransactionId);
		m->Flags = Endian16(h->Flags);
		m->ClientIp = Endian32(h->ClientIP);
		m->YourIp = Endian32(h->YourIP);
		Copy(m->ClientMac, h->ClientMacAddress, 6);

		UCHAR *options = DhcpOptionsOf(h, p->PayloadSize, &options_size);
		if (options != NULL)
		{
			LIST *o = ParseDhcpOptions(options, options_size);
			DHCP_OPTION *opt;

			if ((opt = GetDhcpOption(o, DHCP_ID_MESSAGE_TYPE)) != NULL && opt->Size == 1)
			{
				m->Type = *((UCHAR *)opt->Data);
			}
			if ((opt = GetDhcpOption(o, DHCP_ID_SERVER_ID)) != NULL && opt->Size == 4)
			{
				m->ServerId = READ_UINT(opt->Data);
			}
			if ((opt = GetDhcpOption(o, DHCP_ID_SUBNET_MASK)) != NULL && opt->Size == 4)
			{
				m->Mask = READ_UINT(opt->Data);
			}
			if ((opt = GetDhcpOption(o, DHCP_ID_GATEWAY_ADDR)) != NULL && opt->Size == 4)
			{
				m->Router = READ_UINT(opt->Data);
			}
			if ((opt = GetDhcpOption(o, DHCP_ID_LEASE_TIME)) != NULL && opt->Size == 4)
			{
				m->LeaseTime = READ_UINT(opt->Data);
			}
			if ((opt = GetDhcpOption(o, DHCP_ID_RENEWAL_TIME)) != NULL && opt->Size == 4)
			{
				m->Renewal = READ_UINT(opt->Data);
			}
			if ((opt = GetDhcpOption(o, DHCP_ID_REBINDING_TIME)) != NULL && opt->Size == 4)
			{
				m->Rebinding = READ_UINT(opt->Data);
			}
			if ((opt = GetDhcpOption(o, DHCP_ID_DNS_ADDR)) != NULL && opt->Size % 4 == 0)
			{
				for (UINT i = 0;i < opt->Size / 4 && m->NumDns < 4;i++)
				{
					m->Dns[m->NumDns++] = READ_UINT(((UCHAR *)opt->Data) + i * 4);
				}
			}
			FreeDhcpOptions(o);
			ok = true;
		}
	}
	FreePacket(p);

	return ok;
}

// The DHCP message that the member i got last
static bool DhcpTestLast(DHCPTEST_NET *net, UINT i, DHCPTEST_MSG *m)
{
	DHCPTEST_MEMBER *mb = &net->Members[i];
	bool ok = false;

	AcquireSRWLockShared(&mb->Lock);
	if (mb->NumFrames != 0)
	{
		ok = DhcpTestParse(mb->Frames[mb->NumFrames - 1], mb->Sizes[mb->NumFrames - 1], m);
	}
	ReleaseSRWLockShared(&mb->Lock);

	return ok;
}

// Whether m is an answer of the responder of type, which gives yiaddr, to the client mac, with every setting of the
// Network; with the lease time when lease is true
static bool DhcpTestAnswer(const DHCPTEST_MSG *m, UINT type, UINT yiaddr, const UCHAR *mac, bool lease)
{
	return m->Checksums && m->Op == 2 && m->Type == type && m->YourIp == yiaddr && Cmp(m->ClientMac, mac, 6) == 0 &&
		Cmp(m->SrcMac, dhcptest_responder_mac, 6) == 0 && m->SrcIp == DHCPTEST_IP(10, 20, 0, 2) && m->SrcPort == 67 && m->DstPort == 68 &&
		m->ServerId == DHCPTEST_IP(10, 20, 0, 2) && m->Mask == 0xFFFFFF00 && m->Router == DHCPTEST_IP(10, 20, 0, 1) &&
		m->NumDns == 2 && m->Dns[0] == DHCPTEST_IP(10, 20, 0, 53) && m->Dns[1] == DHCPTEST_IP(192, 0, 2, 53) &&
		(lease ? (m->LeaseTime == DHCPTEST_LEASE && m->Renewal == DHCPTEST_LEASE / 2 && m->Rebinding == DHCPTEST_LEASE * 7 / 8) :
			(m->LeaseTime == 0 && m->Renewal == 0 && m->Rebinding == 0));
}

// What a message is, for a failed check
static char *DhcpTestShow(char *str, UINT size, const DHCPTEST_MSG *m)
{
	char yi[32], sid[32], dst[32];

	Format(str, size, "op %u type %u yiaddr %s server %s to %s, checksums %s, lease %u, mask %08X, router %08X, %u DNS servers",
		m->Op, m->Type, DhcpTestIp(yi, sizeof(yi), m->YourIp), DhcpTestIp(sid, sizeof(sid), m->ServerId), DhcpTestIp(dst, sizeof(dst), m->DstIp),
		m->Checksums ? "valid" : "invalid", m->LeaseTime, m->Mask, m->Router, m->NumDns);
	return str;
}

// The configuration of the test: the CONTROL_DHCP of the desired state of the node that answers DHCP for Network lan
static void DhcpTestConfig(NODE_DHCP_CONFIG *cfg, CONTROL_DHCP *c)
{
	static const UCHAR pool[4] = {10, 20, 0, 0};
	static const UCHAR own[4] = {10, 20, 0, 2};
	static const UCHAR gateway[4] = {10, 20, 0, 1};
	static const UCHAR dns_a[4] = {10, 20, 0, 53};
	static const UCHAR dns_b[4] = {192, 0, 2, 53};
	static const UCHAR reserved_a[4] = {10, 20, 0, 0};
	static const UCHAR reserved_b[4] = {10, 20, 0, 100};

	Zero(c, sizeof(CONTROL_DHCP));
	StrCpy(c->Network, sizeof(c->Network), DHCPTEST_NETWORK);
	c->VrfId = 1;
	Copy(c->Pool, pool, 4);
	c->PoolLength = 24;
	Copy(c->Address, own, 4);
	Copy(c->Gateway, gateway, 4);
	c->NumDns = 2;
	Copy(c->Dns[0], dns_a, 4);
	Copy(c->Dns[1], dns_b, 4);
	c->LeaseTime = DHCPTEST_LEASE;
	c->NumReserved = 2;
	Copy(c->Reserved[0].Address, reserved_a, 4);
	c->Reserved[0].Length = 29;
	Copy(c->Reserved[1].Address, reserved_b, 4);
	c->Reserved[1].Length = 32;

	NodeDhcpConfigOf(cfg, c, dhcptest_responder_mac);
}

//
// The cases
//

// The probe, then a lease and what a client does with it
static void DhcpTestResponder(DHCPTEST_CTX *ctx)
{
	DHCPTEST_NET *net = ZeroMalloc(sizeof(DHCPTEST_NET));
	NODE_DHCP_CONFIG cfg;
	CONTROL_DHCP c;
	DHCPTEST_MSG m;
	NODE_DHCP_STATUS st;
	NODE_DHCP_LEASE leases[4];
	char show[MAX_SIZE];
	const UCHAR *mac_a = dhcptest_macs[DHCPTEST_CLIENT_A];
	const UCHAR *mac_b = dhcptest_macs[DHCPTEST_CLIENT_B];

	Print("Responder: the probe, a lease of the pool with the settings of the Network, and what clients do with it\n");

	DhcpTestConfig(&cfg, &c);
	bool ok = DhcpTestNewNet(net) && DhcpTestStartResponder(net, &cfg);
	if (DhcpTestCheck(ctx, ok, "The switch of Network lan with two clients, a server of the LAN and the responder of its CONTROL_DHCP", "could not set it up") == false)
	{
		DhcpTestStopResponder(net);
		SwitchFree(net->Switch);
		Free(net);
		return;
	}
	DhcpTestCheck(ctx, cfg.Serve && cfg.Pool == DHCPTEST_IP(10, 20, 0, 0) && cfg.PoolLength == 24 && cfg.Address == DHCPTEST_IP(10, 20, 0, 2) && cfg.NumDns == 2 && cfg.NumReserved == 2 && cfg.LeaseTime == DHCPTEST_LEASE,
		"The configuration of the responder is the CONTROL_DHCP of the desired state", "pool %08X/%u, address %08X", cfg.Pool, cfg.PoolLength, cfg.Address);

	// The probe goes first, and before NODE_DHCP_PROBE_WAIT the responder answers no client
	UINT sent = DhcpTestPump(net);
	ok = DhcpTestLast(net, DHCPTEST_CLIENT_A, &m);
	DhcpTestCheck(ctx, sent == 1 && ok && m.Op == 1 && m.Type == DHCP_DISCOVER && Cmp(m.ClientMac, dhcptest_responder_mac, 6) == 0 && Cmp(m.SrcMac, dhcptest_responder_mac, 6) == 0 &&
		(m.Flags & 0x8000) != 0 && m.SrcPort == 68 && m.DstPort == 67 && m.DstIp == 0xFFFFFFFF && m.Checksums && DhcpTestCount(net, DHCPTEST_LAN) == 1,
		"Its first frame is a probe: a DHCPDISCOVER of its own MAC address to the broadcast address that asks for answers by broadcast", "%u frames, %s", sent, DhcpTestShow(show, sizeof(show), &m));
	DhcpTestClear(net);
	net->Clock += NODE_DHCP_PROBE_WAIT / 2;
	DhcpTestClientSends(net, DHCPTEST_CLIENT_A, DHCP_DISCOVER, 0x1001, true, 0, 0, 0, "client-a", false);
	sent = DhcpTestPump(net);
	NodeDhcpGetStatus(net->Dhcp, net->Clock, &st);
	DhcpTestCheck(ctx, sent == 0 && st.Serving == false && st.Ignored == 1, "Within NODE_DHCP_PROBE_WAIT of its probe it answers no client", "%u frames, serving %u, ignored %I64u", sent, (UINT)st.Serving, st.Ignored);

	// The lease: DISCOVER, OFFER, REQUEST, ACK
	net->Clock += NODE_DHCP_PROBE_WAIT;
	DhcpTestClientSends(net, DHCPTEST_CLIENT_A, DHCP_DISCOVER, 0x1002, true, 0, 0, 0, "client-a", false);
	sent = DhcpTestPump(net);
	ok = DhcpTestLast(net, DHCPTEST_CLIENT_A, &m);
	DhcpTestCheck(ctx, sent == 1 && ok && DhcpTestAnswer(&m, DHCP_OFFER, DHCPTEST_IP(10, 20, 0, 8), mac_a, true) && m.Xid == 0x1002 && m.DstIp == 0xFFFFFFFF && Cmp(m.DstMac, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) == 0,
		"A DHCPDISCOVER gets a DHCPOFFER by broadcast of 10.20.0.8, the lowest host address of the pool that no reservation, gateway or DNS server holds, with the mask, the gateway, the DNS servers and the lease time", "%u frames, %s", sent, DhcpTestShow(show, sizeof(show), &m));
	DhcpTestClear(net);
	DhcpTestClientSends(net, DHCPTEST_CLIENT_A, DHCP_REQUEST, 0x1002, true, 0, DHCPTEST_IP(10, 20, 0, 8), DHCPTEST_IP(10, 20, 0, 2), "client-a", false);
	sent = DhcpTestPump(net);
	ok = DhcpTestLast(net, DHCPTEST_CLIENT_A, &m);
	DhcpTestCheck(ctx, sent == 1 && ok && DhcpTestAnswer(&m, DHCP_ACK, DHCPTEST_IP(10, 20, 0, 8), mac_a, true),
		"The DHCPREQUEST of the offer gets a DHCPACK of 10.20.0.8 with the same settings", "%u frames, %s", sent, DhcpTestShow(show, sizeof(show), &m));
	UINT num = NodeDhcpGetLeases(net->Dhcp, net->Clock, leases, 4);
	DhcpTestCheck(ctx, num == 1 && Cmp(leases[0].Mac, mac_a, 6) == 0 && leases[0].Address == DHCPTEST_IP(10, 20, 0, 8) && leases[0].Expires == net->Clock + DHCPTEST_LEASE * 1000ULL && StrCmp(leases[0].HostName, "client-a") == 0,
		"The lease holds the client's MAC address, 10.20.0.8, its host name and its end", "%u leases", num);

	// ARP for the responder's own address, then the renewal by unicast at half the lease time
	{
		static const UCHAR bc[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
		UCHAR frame[sizeof(MAC_HEADER) + sizeof(ARPV4_HEADER)];
		MAC_HEADER *mh = (MAC_HEADER *)frame;
		ARPV4_HEADER *a = (ARPV4_HEADER *)(frame + sizeof(MAC_HEADER));

		DhcpTestClear(net);
		Zero(frame, sizeof(frame));
		Copy(mh->DestAddress, bc, 6);
		Copy(mh->SrcAddress, mac_a, 6);
		mh->Protocol = Endian16(MAC_PROTO_ARPV4);
		a->HardwareType = Endian16(ARP_HARDWARE_TYPE_ETHERNET);
		a->ProtocolType = Endian16(MAC_PROTO_IPV4);
		a->HardwareSize = 6;
		a->ProtocolSize = 4;
		a->Operation = Endian16(ARP_OPERATION_REQUEST);
		Copy(a->SrcAddress, mac_a, 6);
		a->SrcIP = Endian32(DHCPTEST_IP(10, 20, 0, 8));
		a->TargetIP = Endian32(DHCPTEST_IP(10, 20, 0, 2));
		SwitchInput(net->Switch, net->Clock, net->Members[DHCPTEST_CLIENT_A].Port, frame, sizeof(frame));
		sent = DhcpTestPump(net);

		DHCPTEST_MEMBER *ma = &net->Members[DHCPTEST_CLIENT_A];
		const ARPV4_HEADER *r = (const ARPV4_HEADER *)(ma->Frames[0] + sizeof(MAC_HEADER));
		ok = (sent == 1 && ma->NumFrames == 1 && ma->Sizes[0] >= sizeof(MAC_HEADER) + sizeof(ARPV4_HEADER) && Endian16(r->Operation) == ARP_OPERATION_RESPONSE &&
			Cmp(r->SrcAddress, dhcptest_responder_mac, 6) == 0 && Endian32(r->SrcIP) == DHCPTEST_IP(10, 20, 0, 2) && Cmp(r->TargetAddress, mac_a, 6) == 0);
		DhcpTestCheck(ctx, ok, "It answers the ARP request for its own address 10.20.0.2 with its MAC address", "%u frames", sent);
	}
	// Half the lease time is past NODE_DHCP_PROBE_TIME: the probe that is due goes first
	net->Clock += DHCPTEST_LEASE * 500ULL;
	DhcpTestPump(net);
	DhcpTestClear(net);
	DhcpTestClientSends(net, DHCPTEST_CLIENT_A, DHCP_REQUEST, 0x1003, false, DHCPTEST_IP(10, 20, 0, 8), 0, 0, NULL, true);
	sent = DhcpTestPump(net);
	ok = DhcpTestLast(net, DHCPTEST_CLIENT_A, &m);
	num = NodeDhcpGetLeases(net->Dhcp, net->Clock, leases, 4);
	DhcpTestCheck(ctx, sent == 1 && ok && DhcpTestAnswer(&m, DHCP_ACK, DHCPTEST_IP(10, 20, 0, 8), mac_a, true) && m.ClientIp == DHCPTEST_IP(10, 20, 0, 8) && m.DstIp == DHCPTEST_IP(10, 20, 0, 8) && Cmp(m.DstMac, mac_a, 6) == 0 &&
		num == 1 && leases[0].Expires == net->Clock + DHCPTEST_LEASE * 1000ULL && StrCmp(leases[0].HostName, "client-a") == 0,
		"A renewal by unicast at half the lease time gets a DHCPACK by unicast to 10.20.0.8, and the lease runs a full lease time from then", "%u frames, %u leases, %s", sent, num, DhcpTestShow(show, sizeof(show), &m));

	// A second client asks for a reservation, then takes another server's offer
	DhcpTestClear(net);
	DhcpTestClientSends(net, DHCPTEST_CLIENT_B, DHCP_DISCOVER, 0x2001, true, 0, DHCPTEST_IP(10, 20, 0, 100), 0, "client-b", false);
	sent = DhcpTestPump(net);
	ok = DhcpTestLast(net, DHCPTEST_CLIENT_B, &m);
	DhcpTestCheck(ctx, sent == 1 && ok && DhcpTestAnswer(&m, DHCP_OFFER, DHCPTEST_IP(10, 20, 0, 9), mac_b, true),
		"A client that asks for the reservation 10.20.0.100 is offered 10.20.0.9", "%u frames, %s", sent, DhcpTestShow(show, sizeof(show), &m));
	DhcpTestClear(net);
	DhcpTestClientSends(net, DHCPTEST_CLIENT_B, DHCP_REQUEST, 0x2001, true, 0, DHCPTEST_IP(10, 20, 0, 9), DHCPTEST_IP(10, 20, 0, 250), "client-b", false);
	sent = DhcpTestPump(net);
	DhcpTestClientSends(net, DHCPTEST_CLIENT_A, DHCP_DISCOVER, 0x1004, true, 0, 0, 0, NULL, false);
	DhcpTestPump(net);
	ok = DhcpTestLast(net, DHCPTEST_CLIENT_A, &m);
	DhcpTestCheck(ctx, sent == 0 && ok && m.Type == DHCP_OFFER && m.YourIp == DHCPTEST_IP(10, 20, 0, 8),
		"A DHCPREQUEST for another server's offer gets no answer, and a client that holds a lease is offered its address again", "%u frames, %s", sent, DhcpTestShow(show, sizeof(show), &m));

	// Addresses that are not the client's
	DhcpTestClear(net);
	DhcpTestClientSends(net, DHCPTEST_CLIENT_B, DHCP_REQUEST, 0x2002, false, 0, DHCPTEST_IP(10, 99, 0, 5), 0, NULL, false);
	sent = DhcpTestPump(net);
	ok = DhcpTestLast(net, DHCPTEST_CLIENT_B, &m);
	DhcpTestCheck(ctx, sent == 1 && ok && m.Op == 2 && m.Type == DHCP_NAK && m.YourIp == 0 && m.ServerId == DHCPTEST_IP(10, 20, 0, 2) && m.DstIp == 0xFFFFFFFF && m.LeaseTime == 0 && m.Checksums,
		"An INIT-REBOOT for 10.99.0.5, an address of another network, gets a DHCPNAK by broadcast", "%u frames, %s", sent, DhcpTestShow(show, sizeof(show), &m));
	DhcpTestClear(net);
	DhcpTestClientSends(net, DHCPTEST_CLIENT_B, DHCP_REQUEST, 0x2003, false, 0, DHCPTEST_IP(10, 20, 0, 8), 0, NULL, false);
	sent = DhcpTestPump(net);
	ok = DhcpTestLast(net, DHCPTEST_CLIENT_B, &m);
	DhcpTestCheck(ctx, sent == 1 && ok && m.Type == DHCP_NAK, "An INIT-REBOOT for 10.20.0.8, another client's lease, gets a DHCPNAK", "%u frames, %s", sent, DhcpTestShow(show, sizeof(show), &m));

	// The second client takes 10.20.0.9, then declines it
	DhcpTestClientSends(net, DHCPTEST_CLIENT_B, DHCP_DISCOVER, 0x2004, true, 0, 0, 0, "client-b", false);
	DhcpTestPump(net);
	DhcpTestClear(net);
	DhcpTestClientSends(net, DHCPTEST_CLIENT_B, DHCP_REQUEST, 0x2004, true, 0, DHCPTEST_IP(10, 20, 0, 9), DHCPTEST_IP(10, 20, 0, 2), "client-b", false);
	DhcpTestPump(net);
	ok = DhcpTestLast(net, DHCPTEST_CLIENT_B, &m);
	num = NodeDhcpGetLeases(net->Dhcp, net->Clock, leases, 4);
	DhcpTestCheck(ctx, ok && DhcpTestAnswer(&m, DHCP_ACK, DHCPTEST_IP(10, 20, 0, 9), mac_b, true) && num == 2, "The second client gets the lease of 10.20.0.9", "%u leases, %s", num, DhcpTestShow(show, sizeof(show), &m));
	DhcpTestClear(net);
	DhcpTestClientSends(net, DHCPTEST_CLIENT_B, DHCP_DECLINE, 0x2005, false, 0, DHCPTEST_IP(10, 20, 0, 9), DHCPTEST_IP(10, 20, 0, 2), NULL, false);
	sent = DhcpTestPump(net);
	DhcpTestClientSends(net, DHCPTEST_CLIENT_B, DHCP_DISCOVER, 0x2006, true, 0, 0, 0, NULL, false);
	DhcpTestPump(net);
	ok = DhcpTestLast(net, DHCPTEST_CLIENT_B, &m);
	num = NodeDhcpGetLeases(net->Dhcp, net->Clock, leases, 4);
	DhcpTestCheck(ctx, sent == 0 && num == 1 && ok && m.Type == DHCP_OFFER && m.YourIp == DHCPTEST_IP(10, 20, 0, 10),
		"A DHCPDECLINE ends the lease of 10.20.0.9 and keeps the address out of use: the client is offered 10.20.0.10", "%u frames, %u leases, %s", sent, num, DhcpTestShow(show, sizeof(show), &m));

	// The first client releases its lease, then asks with DHCPINFORM for the settings of an address it set itself
	DhcpTestClear(net);
	DhcpTestClientSends(net, DHCPTEST_CLIENT_A, DHCP_RELEASE, 0x1005, false, DHCPTEST_IP(10, 20, 0, 8), 0, DHCPTEST_IP(10, 20, 0, 2), NULL, true);
	sent = DhcpTestPump(net);
	num = NodeDhcpGetLeases(net->Dhcp, net->Clock, leases, 4);
	DhcpTestCheck(ctx, sent == 0 && num == 0, "A DHCPRELEASE ends the lease, without an answer", "%u frames, %u leases", sent, num);
	DhcpTestClientSends(net, DHCPTEST_CLIENT_A, DHCP_INFORM, 0x1006, false, DHCPTEST_IP(10, 20, 0, 200), 0, 0, NULL, true);
	sent = DhcpTestPump(net);
	ok = DhcpTestLast(net, DHCPTEST_CLIENT_A, &m);
	DhcpTestCheck(ctx, sent == 1 && ok && DhcpTestAnswer(&m, DHCP_ACK, 0, mac_a, false) && m.ClientIp == DHCPTEST_IP(10, 20, 0, 200) && m.DstIp == DHCPTEST_IP(10, 20, 0, 200),
		"A DHCPINFORM from 10.20.0.200 gets a DHCPACK with the settings of the Network and no lease, by unicast", "%u frames, %s", sent, DhcpTestShow(show, sizeof(show), &m));

	// The lease of the second client runs out
	DhcpTestClientSends(net, DHCPTEST_CLIENT_B, DHCP_REQUEST, 0x2006, true, 0, DHCPTEST_IP(10, 20, 0, 10), DHCPTEST_IP(10, 20, 0, 2), NULL, false);
	DhcpTestPump(net);
	NodeDhcpGetStatus(net->Dhcp, net->Clock, &st);
	UINT64 changes = st.Changes;
	net->Clock += DHCPTEST_LEASE * 1000ULL;
	num = NodeDhcpGetLeases(net->Dhcp, net->Clock, leases, 4);
	NodeDhcpGetStatus(net->Dhcp, net->Clock, &st);
	DhcpTestCheck(ctx, num == 0 && st.NumLeases == 0 && st.Changes == changes + 1, "A lease whose time ran out ends, and its end is a change of the leases", "%u leases, %I64u changes before, %I64u after", num, changes, st.Changes);
	DhcpTestCheck(ctx, st.Offers == 5 && st.Acks == 5 && st.Naks == 2 && st.Arps == 1 && st.Probes == 2 && st.LanAnswers == 0 && st.Serving,
		"The counters of the responder", "offers %I64u, acks %I64u, naks %I64u, arps %I64u, probes %I64u, LAN answers %I64u", st.Offers, st.Acks, st.Naks, st.Arps, st.Probes, st.LanAnswers);

	DhcpTestStopResponder(net);
	SwitchFree(net->Switch);
	Free(net);
}

// A DHCP server of the LAN answers the probe: the responder stays silent until NODE_DHCP_LAN_HOLD passed
static void DhcpTestLanServer(DHCPTEST_CTX *ctx)
{
	static const UCHAR bc[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	DHCPTEST_NET *net = ZeroMalloc(sizeof(DHCPTEST_NET));
	NODE_DHCP_CONFIG cfg;
	CONTROL_DHCP c;
	DHCPTEST_MSG m;
	NODE_DHCP_STATUS st;
	UCHAR msg[1024];
	UCHAR frame[NODE_DHCP_MAX_FRAME];

	Print("LAN server: a DHCP server of the bridged LAN answers, and the responder stays off\n");

	DhcpTestConfig(&cfg, &c);
	if (DhcpTestCheck(ctx, DhcpTestNewNet(net) && DhcpTestStartResponder(net, &cfg), "The switch of Network lan and the responder", "could not set it up") == false)
	{
		DhcpTestStopResponder(net);
		SwitchFree(net->Switch);
		Free(net);
		return;
	}

	// The probe, and the server of the LAN answers it with a DHCPOFFER by broadcast
	DhcpTestPump(net);
	bool ok = DhcpTestLast(net, DHCPTEST_LAN, &m);
	UINT size = DhcpTestMessage(msg, 2, DHCP_OFFER, m.Xid, true, 0, DHCPTEST_IP(192, 168, 1, 50), dhcptest_responder_mac, 0, DHCPTEST_IP(192, 168, 1, 1), NULL);
	size = DhcpTestUdpFrame(frame, bc, dhcptest_macs[DHCPTEST_LAN], DHCPTEST_IP(192, 168, 1, 1), 67, 0xFFFFFFFF, 68, msg, size);
	SwitchInput(net->Switch, net->Clock, net->Members[DHCPTEST_LAN].Port, frame, size);
	DhcpTestClear(net);

	net->Clock += NODE_DHCP_PROBE_WAIT;
	DhcpTestClientSends(net, DHCPTEST_CLIENT_A, DHCP_DISCOVER, 0x3001, true, 0, 0, 0, NULL, false);
	UINT sent = DhcpTestPump(net);
	NodeDhcpGetStatus(net->Dhcp, net->Clock, &st);
	DhcpTestCheck(ctx, ok && m.Type == DHCP_DISCOVER && sent == 0 && st.LanServer && st.Serving == false && st.LanAnswers == 1 && st.Ignored == 1,
		"Once a DHCP server of the LAN answered its probe, the responder answers no client", "probe seen %u, %u frames, LAN server %u, serving %u, LAN answers %I64u", (UINT)ok, sent, (UINT)st.LanServer, (UINT)st.Serving, st.LanAnswers);

	// It probes again every NODE_DHCP_PROBE_TIME; no server answers any more, and NODE_DHCP_LAN_HOLD after the last answer
	// it serves again
	UINT probes = 0;
	while (net->Clock < DHCPTEST_START + NODE_DHCP_LAN_HOLD + NODE_DHCP_PROBE_WAIT)
	{
		net->Clock += NODE_DHCP_PROBE_TIME / 2;
		probes += DhcpTestPump(net);
	}
	DhcpTestClear(net);
	DhcpTestClientSends(net, DHCPTEST_CLIENT_A, DHCP_DISCOVER, 0x3002, true, 0, 0, 0, NULL, false);
	sent = DhcpTestPump(net);
	ok = DhcpTestLast(net, DHCPTEST_CLIENT_A, &m);
	NodeDhcpGetStatus(net->Dhcp, net->Clock, &st);
	DhcpTestCheck(ctx, probes >= 2 && sent == 1 && ok && DhcpTestAnswer(&m, DHCP_OFFER, DHCPTEST_IP(10, 20, 0, 8), dhcptest_macs[DHCPTEST_CLIENT_A], true) && st.LanServer == false,
		"It probes again, and NODE_DHCP_LAN_HOLD after the last answer of the LAN's server it answers again", "%u probes, %u frames, LAN server %u", probes, sent, (UINT)st.LanServer);

	DhcpTestStopResponder(net);
	SwitchFree(net->Switch);
	Free(net);
}

// A responder whose mode is not pool sends nothing
static void DhcpTestOff(DHCPTEST_CTX *ctx)
{
	DHCPTEST_NET *net = ZeroMalloc(sizeof(DHCPTEST_NET));
	NODE_DHCP_CONFIG cfg;
	CONTROL_DHCP c;
	NODE_DHCP_STATUS st;

	Print("Mode off: the responder answers nothing\n");

	DhcpTestConfig(&cfg, &c);
	cfg.Serve = false;
	if (DhcpTestCheck(ctx, DhcpTestNewNet(net) && DhcpTestStartResponder(net, &cfg), "The switch of Network lan and a responder whose mode is off", "could not set it up") == false)
	{
		DhcpTestStopResponder(net);
		SwitchFree(net->Switch);
		Free(net);
		return;
	}

	UINT sent = DhcpTestPump(net);
	net->Clock += NODE_DHCP_PROBE_WAIT * 2;
	DhcpTestClientSends(net, DHCPTEST_CLIENT_A, DHCP_DISCOVER, 0x4001, true, 0, 0, 0, NULL, false);
	sent += DhcpTestPump(net);
	DhcpTestClientSends(net, DHCPTEST_CLIENT_A, DHCP_REQUEST, 0x4001, true, 0, DHCPTEST_IP(10, 20, 0, 8), 0, NULL, false);
	sent += DhcpTestPump(net);
	DhcpTestClientSends(net, DHCPTEST_CLIENT_A, DHCP_INFORM, 0x4002, false, DHCPTEST_IP(10, 20, 0, 200), 0, 0, NULL, false);
	net->Clock += NODE_DHCP_PROBE_TIME * 2;
	sent += DhcpTestPump(net);
	NodeDhcpGetStatus(net->Dhcp, net->Clock, &st);
	DhcpTestCheck(ctx, sent == 0 && st.Probes == 0 && st.Offers == 0 && st.Acks == 0 && st.Naks == 0 && st.Ignored == 3 && st.Serving == false && DhcpTestCount(net, DHCPTEST_CLIENT_A) == 0,
		"It sends no probe and answers neither a DHCPDISCOVER, a DHCPREQUEST nor a DHCPINFORM", "%u frames, %I64u probes, %I64u ignored", sent, st.Probes, st.Ignored);

	DhcpTestStopResponder(net);
	SwitchFree(net->Switch);
	Free(net);
}

// A new data directory of a node of the test, with no role and one worker
static void DhcpTestNewDir(wchar_t *dir, UINT size)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"dhcptest_%u", Rand32());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);

	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s != NULL)
	{
		CsSetSetting(s, NODE_SETTING_ROLES, "none");
		CsSetSetting(s, NODE_SETTING_WORKERS, "1");
		CsClose(s);
	}
}

// Delete the files of a directory, then the directory (it holds no subdirectory)
static void DhcpTestDeleteFiles(wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		if (e->Folder == false)
		{
			ConbinePathW(path, sizeof(path), dir, e->FileNameW);
			FileDeleteW(path);
		}
	}

	FreeDir(d);
	DeleteDirW(dir);
}

// The desired state of the node at Generation g: its address in VRF default, with the responder of Network lan when
// dhcp is true
static CONTROL_STATE *DhcpTestState(UINT64 g, bool dhcp)
{
	static const UCHAR address[4] = {100, 64, 0, 1};
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
	NODE_DHCP_CONFIG cfg;

	st->Generation = g;
	StrCpy(st->Name, sizeof(st->Name), "node-a");
	st->NumAddresses = 1;
	StrCpy(st->Addresses[0].Network, sizeof(st->Addresses[0].Network), "default");
	st->Addresses[0].VrfId = 1;
	Copy(st->Addresses[0].Address, address, 4);
	st->Addresses[0].AddressSize = 4;
	st->Addresses[0].Length = 10;
	st->NumVrfs = 1;
	StrCpy(st->Vrfs[0].Name, sizeof(st->Vrfs[0].Name), "default");
	st->Vrfs[0].Id = 1;
	st->Vrfs[0].Mtu = NODE_SHAPE_DEFAULT_MTU;
	if (dhcp)
	{
		DhcpTestConfig(&cfg, &st->Dhcps[0]);
		st->NumDhcps = 1;
	}

	return st;
}

// Wait until the member i got a frame, within DHCPTEST_BOUND, or for DHCPTEST_QUIET when quiet: whether it got one
static bool DhcpTestWait(DHCPTEST_NET *net, UINT i, bool quiet)
{
	UINT64 end = Tick64() + (quiet ? DHCPTEST_QUIET : DHCPTEST_BOUND);

	while (DhcpTestCount(net, i) == 0)
	{
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(DHCPTEST_POLL);
	}

	return true;
}

// The responder of a node: from its desired state, on the switch that the L2 data path attached
static void DhcpTestNode(DHCPTEST_CTX *ctx)
{
	DHCPTEST_NET *net = ZeroMalloc(sizeof(DHCPTEST_NET));
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);
	PEER_KEY key;
	UCHAR scalar[PEER_KEY_SIZE];
	wchar_t dir[MAX_PATH];
	wchar_t log_dir[MAX_PATH];
	NODE_OVERLAY_CONFIG oc;
	NODE_DHCP_STATUS st;
	DHCPTEST_MSG m;
	char show[MAX_SIZE];
	NODE *n = NULL;

	Print("Node: the responder of the desired state of a node, on the switch of its Network\n");

	Zero(&key, sizeof(key));
	for (UINT j = 0;j < PEER_KEY_SIZE;j++)
	{
		scalar[j] = (UCHAR)(1 + j);
	}
	bool ok = DhcpTestNewNet(net) && loopback != NULL && PeerKeyFromScalar(&key, scalar);
	Zero(scalar, sizeof(scalar));

	if (ok)
	{
		DhcpTestNewDir(dir, sizeof(dir));
		n = NewNode(dir);
		NodeStart(n);

		Zero(&oc, sizeof(oc));
		oc.Data = loopback;
		oc.Key = &key;
		ok = NodeOverlayStart(n, &oc);
	}
	if (DhcpTestCheck(ctx, ok, "A node whose overlay runs without a control stream, and the switch of Network lan with a client", "could not set them up"))
	{
		// The L2 data path attaches the switch before the state gives the Network a responder
		ok = NodeDhcpAttach(n, DHCPTEST_NETWORK, net->Switch, DHCPTEST_VLAN);
		CONTROL_STATE *s1 = DhcpTestState(1, true);
		bool applied = NodeOverlayApply(n, s1);
		Free(s1);
		DhcpTestCheck(ctx, ok && applied && NodeDhcpGetNetwork(n, DHCPTEST_NETWORK, &st), "The node applies Generation 1, whose Network lan has its responder, and runs it on the switch", "attached %u, applied %u", (UINT)ok, (UINT)applied);

		// Its probe, then a DHCPDISCOVER once NODE_DHCP_PROBE_WAIT passed
		ok = DhcpTestWait(net, DHCPTEST_CLIENT_A, false) && DhcpTestLast(net, DHCPTEST_CLIENT_A, &m) && m.Type == DHCP_DISCOVER && Cmp(m.ClientMac, m.SrcMac, 6) == 0;
		DhcpTestCheck(ctx, ok, "The responder of the node probes on the switch of its Network", "no probe");
		SleepThread(NODE_DHCP_PROBE_WAIT + 500);
		DhcpTestClear(net);
		net->Clock = GetTickCount64();
		DhcpTestClientSends(net, DHCPTEST_CLIENT_A, DHCP_DISCOVER, 0x5001, true, 0, 0, 0, "client-n", false);
		ok = DhcpTestWait(net, DHCPTEST_CLIENT_A, false) && DhcpTestLast(net, DHCPTEST_CLIENT_A, &m) && m.Type == DHCP_OFFER && m.YourIp == DHCPTEST_IP(10, 20, 0, 8) &&
			m.Router == DHCPTEST_IP(10, 20, 0, 1) && m.NumDns == 2 && m.LeaseTime == DHCPTEST_LEASE && m.Checksums;
		DhcpTestCheck(ctx, ok, "A client of the Network gets a DHCPOFFER of 10.20.0.8 with the gateway, the DNS servers and the lease time from the node", "%s", DhcpTestShow(show, sizeof(show), &m));
		UCHAR server_mac[6];
		Copy(server_mac, m.SrcMac, 6);
		DhcpTestClear(net);
		net->Clock = GetTickCount64();
		DhcpTestClientSends(net, DHCPTEST_CLIENT_A, DHCP_REQUEST, 0x5001, true, 0, DHCPTEST_IP(10, 20, 0, 8), DHCPTEST_IP(10, 20, 0, 2), "client-n", false);
		ok = DhcpTestWait(net, DHCPTEST_CLIENT_A, false) && DhcpTestLast(net, DHCPTEST_CLIENT_A, &m) && m.Type == DHCP_ACK && m.YourIp == DHCPTEST_IP(10, 20, 0, 8);
		NodeDhcpGetNetwork(n, DHCPTEST_NETWORK, &st);
		DhcpTestCheck(ctx, ok && st.NumLeases == 1 && st.Acks == 1 && (server_mac[0] & 0x03) == 0x02,
			"The DHCPREQUEST gets a DHCPACK, and the node's responder of Network lan, with a locally administered MAC address of its own, holds the lease", "%u leases, %s", st.NumLeases, DhcpTestShow(show, sizeof(show), &m));

		// Generation 2 gives the Network no responder: the node answers no DHCP for it
		CONTROL_STATE *s2 = DhcpTestState(2, false);
		applied = NodeOverlayApply(n, s2);
		Free(s2);
		DhcpTestClear(net);
		net->Clock = GetTickCount64();
		DhcpTestClientSends(net, DHCPTEST_CLIENT_A, DHCP_DISCOVER, 0x5002, true, 0, 0, 0, NULL, false);
		bool answered = DhcpTestWait(net, DHCPTEST_CLIENT_A, true);
		DhcpTestCheck(ctx, applied && answered == false && NodeDhcpGetNetwork(n, DHCPTEST_NETWORK, &st) == false,
			"Generation 2 gives Network lan no responder: the node runs none, and a DHCPDISCOVER goes unanswered", "applied %u, answered %u", (UINT)applied, (UINT)answered);

		NodeDhcpDetach(n, DHCPTEST_NETWORK);
	}

	if (n != NULL)
	{
		NodeStop(n);
		FreeNode(n);
		ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
		DhcpTestDeleteFiles(log_dir);
		DhcpTestDeleteFiles(dir);
	}
	PeerKeyClose(&key);
	TransportLoopbackFree(loopback);
	SwitchFree(net->Switch);
	Free(net);
}

// Read size bytes of a stream within DHCPTEST_QUIET: false when they did not come
static bool DhcpTestReadAll(TRANSPORT_STREAM *s, UCHAR *buf, UINT size)
{
	UINT got = 0;

	while (got < size)
	{
		UINT r = TransportRead(s, buf + got, size - got, DHCPTEST_QUIET);

		if (r == TRANSPORT_LATER || r == 0 || r > size - got)
		{
			return false;
		}
		got += r;
	}

	return true;
}

// A varint of the protobuf wire format at *pos of buf: false when it runs past size
static bool DhcpTestVarint(const UCHAR *buf, UINT size, UINT *pos, UINT64 *v)
{
	*v = 0;
	for (UINT shift = 0;shift < 64;shift += 7)
	{
		if (*pos >= size)
		{
			return false;
		}
		UCHAR b = buf[(*pos)++];
		*v |= ((UINT64)(b & 0x7F)) << shift;
		if ((b & 0x80) == 0)
		{
			return true;
		}
	}

	return false;
}

// One frame of the control stream that holds a ControlMessage whose body is Leases (field 8), read from its bytes as the
// protobuf wire format has them, without the generated code: the Network and each lease as a line "<mac> <address>
// <expires> <host name>". False when the frame is anything else.
static bool DhcpTestLeasesFrame(TRANSPORT_STREAM *s, char *network, UINT network_size, char *lines, UINT lines_size)
{
	UCHAR head[4];
	UCHAR *body = NULL;
	UINT size, pos = 0;
	UINT64 tag, len;
	bool ok = false;

	network[0] = 0;
	lines[0] = 0;
	if (DhcpTestReadAll(s, head, 4) == false || (size = READ_UINT(head)) == 0 || size > 1 << 20)
	{
		return false;
	}
	body = Malloc(size);
	if (DhcpTestReadAll(s, body, size) && DhcpTestVarint(body, size, &pos, &tag) && tag == ((8 << 3) | 2) && DhcpTestVarint(body, size, &pos, &len) && len == size - pos)
	{
		ok = true;
		while (ok && pos < size)
		{
			UINT64 field, flen;

			ok = DhcpTestVarint(body, size, &pos, &field) && (field & 7) == 2 && DhcpTestVarint(body, size, &pos, &flen) && flen <= size - pos;
			if (ok && field == ((1 << 3) | 2) && flen < network_size)
			{
				Copy(network, body + pos, (UINT)flen);
				network[flen] = 0;
			}
			else if (ok && field == ((2 << 3) | 2))
			{
				// One Lease: mac (1), address (2), expires_ms (3), host_name (4)
				UINT end = pos + (UINT)flen, p = pos;
				UCHAR mac[6] = {0}, addr[4] = {0};
				UINT64 expires = 0;
				char host[64] = {0};
				char line[MAX_SIZE];

				while (ok && p < end)
				{
					UINT64 f, v;

					ok = DhcpTestVarint(body, end, &p, &f);
					if (ok && f == ((3 << 3) | 0))
					{
						ok = DhcpTestVarint(body, end, &p, &expires);
						continue;
					}
					ok = ok && (f & 7) == 2 && DhcpTestVarint(body, end, &p, &v) && v <= end - p;
					if (ok && f == ((1 << 3) | 2) && v == 6)
					{
						Copy(mac, body + p, 6);
					}
					else if (ok && f == ((2 << 3) | 2) && v == 4)
					{
						Copy(addr, body + p, 4);
					}
					else if (ok && f == ((4 << 3) | 2) && v < sizeof(host))
					{
						Copy(host, body + p, (UINT)v);
						host[v] = 0;
					}
					else
					{
						ok = false;
					}
					p += (UINT)v;
				}
				Format(line, sizeof(line), "%02x:%02x:%02x:%02x:%02x:%02x %u.%u.%u.%u %I64u %s\n", (UINT)mac[0], (UINT)mac[1], (UINT)mac[2], (UINT)mac[3], (UINT)mac[4], (UINT)mac[5],
					(UINT)addr[0], (UINT)addr[1], (UINT)addr[2], (UINT)addr[3], expires, host);
				StrCat(lines, lines_size, line);
			}
			else
			{
				ok = false;
			}
			pos += (UINT)flen;
		}
	}
	Free(body);

	return ok;
}

// The leases of the responders on the control stream: one Leases message per Network, each report once, and anew when
// it changes
static void DhcpTestLeases(DHCPTEST_CTX *ctx)
{
	TRANSPORT *t = TransportLoopbackNew("dhcp-leases", 0, false);
	TRANSPORT_LISTENER *l = (t != NULL ? TransportListen(t, "controller") : NULL);
	TRANSPORT_STREAM *a = (l != NULL ? TransportDial(t, "controller", NULL) : NULL);
	TRANSPORT_STREAM *b = (a != NULL ? TransportAccept(l, DHCPTEST_BOUND) : NULL);
	CONTROL_LEASES *leases = ControlNewLeases();
	CONTROL_LEASE x[3];
	char network[CONTROL_NAME_SIZE];
	char lines[MAX_SIZE * 2];
	UCHAR one;

	Print("Leases: the leases of a responder on the control stream\n");

	if (DhcpTestCheck(ctx, b != NULL && leases != NULL, "A stream of the loopback transport, as the control stream", "could not set it up") == false)
	{
		ControlFreeLeases(leases);
		TransportClose(a);
		TransportClose(b);
		TransportCloseListener(l);
		TransportLoopbackFree(t);
		return;
	}

	Zero(x, sizeof(x));
	Copy(x[0].Mac, dhcptest_macs[DHCPTEST_CLIENT_A], 6);
	WRITE_UINT(x[0].Address, DHCPTEST_IP(10, 20, 0, 8));
	x[0].Expires = 1792800000123ULL;
	StrCpy(x[0].HostName, sizeof(x[0].HostName), "client-a");
	Copy(x[1].Mac, dhcptest_macs[DHCPTEST_CLIENT_B], 6);
	WRITE_UINT(x[1].Address, DHCPTEST_IP(10, 20, 0, 9));
	x[1].Expires = 1792800000456ULL;
	StrCpy(x[1].HostName, sizeof(x[1].HostName), "bad\x01name\xC3\xA9");

	bool set = ControlSetLeases(leases, DHCPTEST_NETWORK, x, 2);
	bool written = ControlWriteLeases(leases, a);
	bool ok = DhcpTestLeasesFrame(b, network, sizeof(network), lines, sizeof(lines));
	DhcpTestCheck(ctx, set && written && ok && StrCmp(network, DHCPTEST_NETWORK) == 0 &&
		StrCmp(lines, "02:00:00:00:43:0a 10.20.0.8 1792800000123 client-a\n02:00:00:00:43:0b 10.20.0.9 1792800000456 badname\n") == 0,
		"The leases of Network lan go as one ControlMessage of the body Leases, each with its MAC address, its address, its end and its host name in printable ASCII", "set %u, written %u, read %u: %s %s", (UINT)set, (UINT)written, (UINT)ok, network, lines);

	// A report goes once; a new one goes again, also an empty one; one without a responder goes nowhere
	written = ControlWriteLeases(leases, a);
	bool quiet = (TransportRead(b, &one, 1, DHCPTEST_POLL * 10) == TRANSPORT_LATER);
	set = ControlSetLeases(leases, DHCPTEST_NETWORK, x, 0);
	written = ControlWriteLeases(leases, a) && written;
	ok = DhcpTestLeasesFrame(b, network, sizeof(network), lines, sizeof(lines));
	DhcpTestCheck(ctx, written && quiet && set && ok && StrCmp(network, DHCPTEST_NETWORK) == 0 && lines[0] == 0,
		"A report goes once, and the next one goes in its place, also one without a lease", "written %u, quiet %u, set %u, read %u: %s %s", (UINT)written, (UINT)quiet, (UINT)set, (UINT)ok, network, lines);
	set = ControlSetLeases(leases, DHCPTEST_NETWORK, NULL, 0);
	written = ControlWriteLeases(leases, a);
	quiet = (TransportRead(b, &one, 1, DHCPTEST_POLL * 10) == TRANSPORT_LATER);
	DhcpTestCheck(ctx, set && written && quiet, "A Network without a responder has no report: nothing goes", "set %u, written %u, quiet %u", (UINT)set, (UINT)written, (UINT)quiet);

	// One report per Network, for CONTROL_MAX_DHCPS Networks at most
	UINT accepted = 0;
	for (UINT i = 0;i <= CONTROL_MAX_DHCPS;i++)
	{
		char name[CONTROL_NAME_SIZE];

		Format(name, sizeof(name), "lan-%u", i);
		if (ControlSetLeases(leases, name, x, 1))
		{
			accepted++;
		}
	}
	DhcpTestCheck(ctx, accepted == CONTROL_MAX_DHCPS && ControlSetLeases(leases, "", x, 1) == false, "The reports of CONTROL_MAX_DHCPS Networks at most, each with a name", "%u accepted", accepted);

	ControlFreeLeases(leases);
	TransportClose(a);
	TransportClose(b);
	TransportCloseListener(l);
	TransportLoopbackFree(t);
}

RANZ_TEST("dhcp", dhcp_test, "DHCP responder of an L2 Network: its probe, a lease of the pool with the gateway and the DNS servers of the Network, renewal, decline, release, inform and expiry, silence while a DHCP server of the LAN answers or the mode is off, the responder of a node from its desired state on the switch of the Network, and its leases on the control stream.");
void dhcp_test(UINT num, char **arg)
{
	DHCPTEST_CTX ctx;
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, DhcpTestWatchdog, done, 0, NULL) : NULL);

	Zero(&ctx, sizeof(ctx));
	Print("DHCP test: the DHCP responder of an L2 Network from the IPv4 pool of the Network\n");

	DhcpTestResponder(&ctx);
	DhcpTestLanServer(&ctx);
	DhcpTestOff(&ctx);
	DhcpTestNode(&ctx);
	DhcpTestLeases(&ctx);

	if (watchdog != NULL)
	{
		SetEvent(done);
		WaitForSingleObject(watchdog, INFINITE);
		CloseHandle(watchdog);
	}
	if (done != NULL)
	{
		CloseHandle(done);
	}

	if (ctx.NumFailed == 0)
	{
		Print("DHCP TEST OK\n");
	}
	else
	{
		Print("DHCP TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
