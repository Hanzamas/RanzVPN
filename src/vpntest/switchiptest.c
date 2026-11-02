// switchiptest.c
// Named switchip test of vpntest ("switchip" command, SDN-67 #294)
//
// The IP table of the L2 switch (src/Core/SwitchIp.c; SDN-50-N, #492) as the IRB of a stretched Network reads it to find the member
// that a packet of the fabric goes to (SwitchFindIp; Cedar/NodeStretch.c, SDN-67 #294), and as the operators read and clear it:
// - a member of VLAN 1 that sends an ARP request and one that sends an IPv4 and an IPv6 packet have their three addresses in the
//   IP table of VLAN 1, each with the MAC address and the port of its frame, and SwitchGetIps lists them in the order of VLAN and
//   address;
// - SwitchFindIp finds each in VLAN 1 with that MAC address and that port, and none in VLAN 2, none of an address that no member
//   sent from, none of a size that is neither 4 nor 16, none of a VLAN that is no VLAN id and none for a switch or an entry that is
//   none;
// - an address that another member sends from is found with the MAC address and the port of that member, and an address that
//   SwitchClearIps took out is found no more, while the others stay.
// Print "SWITCHIP TEST OK" only when every check passes.

#include "harness_int.h"
#include "testlist.h"

#include "Mayaqua/IpAddr.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"

#include "Core/Switch.h"

#define	SWIPTEST_VLAN			1			// The VLAN of the members
#define	SWIPTEST_OTHER_VLAN		2			// A VLAN that no member sends in
#define	SWIPTEST_FRAME			80			// A test frame at most: the Ethernet header and an IPv4, IPv6 or ARP packet
#define	SWIPTEST_MAX_IPS		8			// The entries of the IP table that the test reads at most
#define	SWIPTEST_NONE			3			// No member: SwitchFindIp finds none

// The members: a, b and c, each on an access port of VLAN 1
static const UCHAR swiptest_macs[3][6] =
{
	{0x02, 0x52, 0x5A, 0x67, 0x00, 0x0A},
	{0x02, 0x52, 0x5A, 0x67, 0x00, 0x0B},
	{0x02, 0x52, 0x5A, 0x67, 0x00, 0x0C},
};

// The broadcast address
static const UCHAR swiptest_broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// The test
typedef struct SWIPTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	SWITCH *Switch;
	UINT Ports[3];
} SWIPTEST_CTX;

static bool SwIpTestCheck(SWIPTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool SwIpTestCheck(SWIPTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
{
	char detail[MAX_SIZE];
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

// A member takes what the switch delivers to its port, which the test does not read
static void SwIpTestTake(void *param, UINT port, const UCHAR *frame, UINT size)
{
	UNREFERENCED_PARAMETER(param);
	UNREFERENCED_PARAMETER(port);
	UNREFERENCED_PARAMETER(frame);
	UNREFERENCED_PARAMETER(size);
}

// The address of a text into addr: 4 bytes for IPv4, 16 for IPv6, and their number; 0 for none
static UINT SwIpTestAddress(UCHAR *addr, char *str)
{
	IP ip;

	Zero(addr, 16);
	if (StrToIP(&ip, str) == false)
	{
		return 0;
	}

	if (IsIP4(&ip))
	{
		Copy(addr, IPV4(ip.address), 4);
		return 4;
	}

	Copy(addr, ip.address, 16);
	return 16;
}

// Member i sends, into the switch, a broadcast ARP request from the address ip (arp), or an IPv4 or IPv6 packet from it to a host of
// its subnet: how many ports the frame reached
static UINT SwIpTestSend(SWIPTEST_CTX *ctx, UINT i, char *ip, bool arp)
{
	UCHAR frame[SWIPTEST_FRAME];
	UCHAR src[16];
	UINT size = SwIpTestAddress(src, ip);
	UCHAR *p = frame + 14;
	UINT len = 0;

	Zero(frame, sizeof(frame));
	Copy(frame + 6, swiptest_macs[i], 6);

	if (arp)
	{
		// An ARP request of IPv4 over Ethernet for 10.67.0.1, to every host
		Copy(frame, swiptest_broadcast, 6);
		WRITE_USHORT(frame + 12, MAC_PROTO_ARPV4);
		WRITE_USHORT(p, ARP_HARDWARE_TYPE_ETHERNET);
		WRITE_USHORT(p + 2, MAC_PROTO_IPV4);
		p[4] = 6;
		p[5] = 4;
		WRITE_USHORT(p + 6, ARP_OPERATION_REQUEST);
		Copy(p + 8, swiptest_macs[i], 6);
		Copy(p + 14, src, 4);
		p[24] = 10;
		p[25] = 67;
		p[27] = 1;
		len = 28;
	}
	else if (size == 4)
	{
		// An IPv4 packet of UDP without data to 10.67.0.1, to the MAC address of member a
		Copy(frame, swiptest_macs[0], 6);
		WRITE_USHORT(frame + 12, MAC_PROTO_IPV4);
		p[0] = 0x45;
		WRITE_USHORT(p + 2, 28);
		p[8] = 64;
		p[9] = IP_PROTO_UDP;
		Copy(p + 12, src, 4);
		p[16] = 10;
		p[17] = 67;
		p[19] = 1;
		WRITE_USHORT(p + 24, 8);
		len = 28;
	}
	else
	{
		// An IPv6 packet of UDP without data to fd67::1, to the MAC address of member a
		Copy(frame, swiptest_macs[0], 6);
		WRITE_USHORT(frame + 12, MAC_PROTO_IPV6);
		p[0] = 0x60;
		WRITE_USHORT(p + 4, 8);
		p[6] = IP_PROTO_UDP;
		p[7] = 64;
		Copy(p + 8, src, 16);
		p[24] = 0xFD;
		p[25] = 0x67;
		p[39] = 1;
		WRITE_USHORT(p + 44, 8);
		len = 48;
	}

	return SwitchInput(ctx->Switch, GetTickCount64(), ctx->Ports[i], frame, 14 + len);
}

// Whether SwitchFindIp finds the address ip in vlan with the MAC address and the port of member i, or for SWIPTEST_NONE finds none
static bool SwIpTestFinds(SWIPTEST_CTX *ctx, UINT vlan, char *ip, UINT i)
{
	UCHAR addr[16];
	SWITCH_IP_ENTRY e;
	UINT size = SwIpTestAddress(addr, ip);

	Zero(&e, sizeof(e));
	bool found = SwitchFindIp(ctx->Switch, vlan, addr, size, &e);

	if (i >= SWIPTEST_NONE)
	{
		return (found == false);
	}

	return (found && e.Vlan == vlan && e.AddressSize == size && Cmp(e.Address, addr, size) == 0 && Cmp(e.Mac, swiptest_macs[i], 6) == 0 && e.Port == ctx->Ports[i]);
}

// switchip: the IP table of the switch, as the IRB of a stretched Network finds a member in it
RANZ_TEST_TAGS("switchip", switchip_test, "core", "Switch IP table: the addresses that the members of a VLAN send from, found one by one with the MAC address and the port of their last frame (SwitchFindIp, as the IRB of a stretched Network finds a member), listed and cleared.");
void switchip_test(UINT num, char **arg)
{
	SWIPTEST_CTX *ctx = ZeroMalloc(sizeof(SWIPTEST_CTX));
	SWITCH_IP_ENTRY list[SWIPTEST_MAX_IPS];
	SWITCH_IP_ENTRY e;
	UCHAR addr[16];
	bool members = true;

	Print("Switch IP test: the IP table of the switch of an L2 Network, as the IRB of a stretched Network finds a member in it\n");

	ctx->Switch = SwitchNew(NULL);
	for (UINT i = 0;i < 3;i++)
	{
		SWITCH_PORT_CONFIG pc;

		Zero(&pc, sizeof(pc));
		pc.Mode = SWITCH_ACCESS;
		pc.Vlan = SWIPTEST_VLAN;
		pc.Send = SwIpTestTake;
		pc.Param = ctx;
		ctx->Ports[i] = (ctx->Switch != NULL ? SwitchAddPort(ctx->Switch, &pc) : SWITCH_PORT_NONE);
		members = (ctx->Ports[i] != SWITCH_PORT_NONE) && members;
	}

	if (SwIpTestCheck(ctx, members, "A switch with members a, b and c on access ports of VLAN 1", "%s", "SwitchNew or SwitchAddPort failed"))
	{
		// Member a sends an ARP request, member b an IPv4 and an IPv6 packet
		SwIpTestSend(ctx, 0, "10.67.0.5", true);
		SwIpTestSend(ctx, 1, "10.67.0.6", false);
		SwIpTestSend(ctx, 1, "fd67::6", false);

		UINT n = SwitchGetIps(ctx->Switch, list, SWIPTEST_MAX_IPS);
		UCHAR a[16], b[16], c[16];
		SwIpTestAddress(a, "10.67.0.5");
		SwIpTestAddress(b, "10.67.0.6");
		SwIpTestAddress(c, "fd67::6");
		SwIpTestCheck(ctx, n == 3 && list[0].Vlan == SWIPTEST_VLAN && list[0].AddressSize == 4 && Cmp(list[0].Address, a, 4) == 0 && Cmp(list[0].Mac, swiptest_macs[0], 6) == 0 &&
			list[1].AddressSize == 4 && Cmp(list[1].Address, b, 4) == 0 && Cmp(list[1].Mac, swiptest_macs[1], 6) == 0 &&
			list[2].AddressSize == 16 && Cmp(list[2].Address, c, 16) == 0 && Cmp(list[2].Mac, swiptest_macs[1], 6) == 0 && list[0].Port == ctx->Ports[0] && list[2].Port == ctx->Ports[1],
			"The IP table holds the sender of the ARP request of member a and the sources of the IPv4 and IPv6 packets of member b, in the order of VLAN and address",
			"%u entries", n);

		SwIpTestCheck(ctx, SwIpTestFinds(ctx, SWIPTEST_VLAN, "10.67.0.5", 0) && SwIpTestFinds(ctx, SWIPTEST_VLAN, "10.67.0.6", 1) && SwIpTestFinds(ctx, SWIPTEST_VLAN, "fd67::6", 1),
			"SwitchFindIp finds each address in VLAN 1 with the MAC address and the port of its member", "%s", "an address not found, or with another MAC address or port");

		SwIpTestAddress(addr, "10.67.0.5");
		SwIpTestCheck(ctx, SwIpTestFinds(ctx, SWIPTEST_OTHER_VLAN, "10.67.0.5", SWIPTEST_NONE) && SwIpTestFinds(ctx, SWIPTEST_VLAN, "10.67.0.9", SWIPTEST_NONE) &&
			SwIpTestFinds(ctx, SWIPTEST_VLAN, "fd67::9", SWIPTEST_NONE) && SwitchFindIp(ctx->Switch, SWIPTEST_VLAN, addr, 5, &e) == false &&
			SwitchFindIp(ctx->Switch, 0, addr, 4, &e) == false && SwitchFindIp(ctx->Switch, SWITCH_MAX_VLAN + 1, addr, 4, &e) == false &&
			SwitchFindIp(ctx->Switch, SWIPTEST_VLAN, addr, 4, NULL) == false && SwitchFindIp(NULL, SWIPTEST_VLAN, addr, 4, &e) == false &&
			SwitchFindIp(ctx->Switch, SWIPTEST_VLAN, NULL, 4, &e) == false,
			"SwitchFindIp finds none in another VLAN, none of an address that no member sent from, and none of a size, a VLAN, a switch, an address or an entry that is none",
			"%s", "it found one");

		// Member c sends from the address of member a, which then goes
		SwIpTestSend(ctx, 2, "10.67.0.5", false);
		SwIpTestCheck(ctx, SwIpTestFinds(ctx, SWIPTEST_VLAN, "10.67.0.5", 2), "An address that member c sends from is found with the MAC address and the port of member c",
			"%s", "found with another MAC address or port, or not at all");

		UINT cleared = SwitchClearIps(ctx->Switch, addr, 4);
		SwIpTestCheck(ctx, cleared == 1 && SwIpTestFinds(ctx, SWIPTEST_VLAN, "10.67.0.5", SWIPTEST_NONE) && SwIpTestFinds(ctx, SWIPTEST_VLAN, "10.67.0.6", 1) &&
			SwIpTestFinds(ctx, SWIPTEST_VLAN, "fd67::6", 1) && SwitchGetIps(ctx->Switch, list, SWIPTEST_MAX_IPS) == 2,
			"An address that SwitchClearIps took out is found no more, and the others stay", "%u cleared", cleared);
	}

	SwitchFree(ctx->Switch);

	if (ctx->NumFailed == 0)
	{
		Print("SWITCHIP TEST OK\n");
	}
	else
	{
		Print("SWITCHIP TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
