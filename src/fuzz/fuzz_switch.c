// fuzz_switch.c
// libFuzzer target: the ingress of the L2 switch of the new core (Core/Switch.c, CORE-S4-1 #74), which reads the frames
// that the members of a Network send. The first byte of an input chooses the port that the frame comes in at: the
// access port of VLAN 10, the trunk port of VLANs 10, 20 and 30, the trunk port of VLAN 20 with the native VLAN 10, or a
// port that no member holds. The second byte moves the clock of the switch on by tens of ms; its value 0xFF ages the MAC
// table after the frame and 0xFE clears it, so that entries also leave the table. The rest of the input is the frame.
// The MAC table holds 64 entries, the limits are low, and the ports subscribe to the broadcast group, to a multicast
// group and to every group, so that inputs reach learning, a full table, unicast, flooding, delivery to groups and the
// limits. Every frame that the switch delivers is read to its last byte, so AddressSanitizer reports one that runs past
// the input or past the buffer of the switch.
//
// The switch learns the source address of the host of each frame in its IP table too, which reads the IPv4 header, the
// ARP packet or the IPv6 header after the tag (SwitchIpLearn of Core/SwitchIp.c; SDN-50-N, #492). The IP table holds 64
// entries as well; it ages with the MAC table, and before 0xFE clears both tables each is read into a list of fewer entries
// than it may hold, its first ones by VLAN and address, and the entries of the source MAC address of the frame and of the
// address in the place of the source of an untagged IPv4 packet are cleared alone.
//
// The frame then comes in at the same port of a second switch of the same ports, whose filter is the policy engine of
// the security of an L2 Network under every protection (Core/SwitchSecurity.h; SDN-41, #234): the member of the access
// port is the gateway of the Network, and the members of the trunk ports are its clients. So inputs also reach the filter
// of a switch, before the learning of a source and at each member that a frame to a group reaches.
//
// fuzz-max-len: 9219
// fuzz-libs: coreswitch corepolicy

#include "fuzz_common.h"

#include "Core/SwitchSecurity.h"

#include <stdlib.h>
#include <string.h>

// Largest input accepted: the two bytes in front, and one byte above the largest frame, so that a frame that is too
// long is fuzzed too; longer inputs are skipped
#define	FUZZ_MAX_INPUT_SIZE		(2 + SWITCH_MAX_FRAME + 1)

#define	FUZZ_NUM_PORTS			4				// The ports of the switch: three members and one port without a member
#define	FUZZ_NUM_MEMBERS		3				// ... the members
#define	FUZZ_AGE				0xFF			// The clock byte that ages the MAC table after the frame
#define	FUZZ_CLEAR				0xFE			// ... and the one that clears it
#define	FUZZ_LIST				8				// The entries of a table that a read before a clear lists at most

// The document of the policy engine of the second switch: its Network, whose starter rule lets every frame through, so
// that only the protections drop one
static const char fuzz_switch_doc[] = "{\"networks\": [{\"name\": \"lan\", \"mode\": \"l2\"}], \"rules\": [{\"name\": \"starter\", \"action\": \"allow\"}]}";

static SWITCH *fuzz_switch = NULL;
static SWITCH *fuzz_secure = NULL;				// The second switch, whose filter is fuzz_engine
static POLICY_ENGINE *fuzz_engine = NULL;
static UINT fuzz_ports[FUZZ_NUM_PORTS];
static UINT64 fuzz_now = 1000;
static volatile UINT fuzz_sum = 0;

// The procedure of every member: it reads the frame to its last byte
static void FuzzSwitchSend(void *param, UINT port, const UCHAR *frame, UINT size)
{
	UINT sum = port;

	for (UINT i = 0; i < size; i++)
	{
		sum += frame[i];
	}

	fuzz_sum += sum;
}

// A switch of the configuration c with its members and their subscriptions, the member of each port for the filter of
// the switch in members (which a switch without a filter ignores), and its ports into ports; NULL when it is not made
static SWITCH *FuzzSwitchNew(SWITCH_CONFIG *c, const UINT *members, UINT *ports)
{
	static const USHORT trunk[] = {10, 20, 30};
	static const USHORT native_trunk[] = {20};
	static const UCHAR broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	static const UCHAR mdns[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB};
	SWITCH_PORT_CONFIG p;

	c->MaxPorts = FUZZ_NUM_PORTS;
	c->MaxMacs = 64;
	c->MaxIps = 64;
	c->AgingTime = 2000;
	c->BroadcastLimit = 50;
	c->MulticastLimit = 20;
	SWITCH *sw = SwitchNew(c);
	if (sw == NULL)
	{
		return NULL;
	}

	memset(&p, 0, sizeof(p));
	p.Send = FuzzSwitchSend;
	p.Mode = SWITCH_ACCESS;
	p.Vlan = 10;
	p.Member = members[0];
	ports[0] = SwitchAddPort(sw, &p);

	p.Mode = SWITCH_TRUNK;
	p.Vlan = 0;
	p.Allowed = trunk;
	p.NumAllowed = sizeof(trunk) / sizeof(trunk[0]);
	p.Member = members[1];
	ports[1] = SwitchAddPort(sw, &p);

	p.Vlan = 10;
	p.Allowed = native_trunk;
	p.NumAllowed = sizeof(native_trunk) / sizeof(native_trunk[0]);
	p.Member = members[2];
	ports[2] = SwitchAddPort(sw, &p);

	// The last port has no member
	ports[3] = FUZZ_NUM_PORTS - 1;

	if (SwitchSubscribe(sw, ports[0], 10, broadcast) && SwitchSubscribe(sw, ports[0], 10, mdns) && SwitchSubscribe(sw, ports[1], 10, broadcast) &&
		SwitchSubscribe(sw, ports[1], 20, NULL) && SwitchSubscribe(sw, ports[1], 30, broadcast) && SwitchSubscribe(sw, ports[2], 10, broadcast) &&
		SwitchSubscribe(sw, ports[2], 20, broadcast))
	{
		return sw;
	}

	SwitchFree(sw);
	return NULL;
}

// Once: the two switches, and the policy engine of the second with its gateway and its two clients
static bool FuzzSwitchSetup()
{
	static const UINT none[FUZZ_NUM_MEMBERS] = {0, 0, 0};
	UINT members[FUZZ_NUM_MEMBERS];
	UINT ports[FUZZ_NUM_PORTS];
	POLICY_MEMBER_CONFIG pc;
	SWITCH_SECURITY sec;
	SWITCH_CONFIG c;
	char error[256];

	if (fuzz_secure != NULL)
	{
		return true;
	}

	fuzz_engine = PolicyNew(FUZZ_NUM_MEMBERS);
	if (fuzz_engine == NULL || PolicySetRules(fuzz_engine, fuzz_switch_doc, (UINT)strlen(fuzz_switch_doc), error, sizeof(error)) == false)
	{
		return false;
	}

	memset(&sec, 0, sizeof(sec));
	sec.CheckMac = true;
	sec.CheckIp = true;
	sec.MaxMacs = 2;
	sec.MaxIps = 4;
	sec.ArpDhcpOnly = true;
	sec.DhcpGuard = true;
	sec.RaGuard = true;
	memset(&pc, 0, sizeof(pc));
	pc.Network = "lan";
	for (UINT i = 0; i < FUZZ_NUM_MEMBERS; i++)
	{
		members[i] = SwitchSecurityMember(fuzz_engine, &pc, &sec, (i == 0 ? SWITCH_GATEWAY : SWITCH_CLIENT));
		if (members[i] == POLICY_NO_MEMBER)
		{
			return false;
		}
	}

	memset(&c, 0, sizeof(c));
	fuzz_switch = FuzzSwitchNew(&c, none, fuzz_ports);
	if (fuzz_switch == NULL)
	{
		return false;
	}

	// The frame of an input comes in at the same port of both switches
	memset(&c, 0, sizeof(c));
	SwitchSecurityFilter(&c, fuzz_engine);
	SWITCH *secure = FuzzSwitchNew(&c, members, ports);
	if (secure == NULL || memcmp(ports, fuzz_ports, sizeof(ports)) != 0)
	{
		return false;
	}

	fuzz_secure = secure;
	return true;
}

// One input: the port, the step of the clock and a frame
static void FuzzSwitch(const uint8_t *data, size_t size)
{
	if (size < 2 || size > FUZZ_MAX_INPUT_SIZE || FuzzSwitchSetup() == false)
	{
		return;
	}

	// malloc() rather than Malloc(): the copy is exactly the size of the frame, so AddressSanitizer reports any read past
	// its end
	UINT frame_size = (UINT)size - 2;
	UCHAR *frame = malloc(frame_size != 0 ? frame_size : 1);
	if (frame == NULL)
	{
		return;
	}
	if (frame_size != 0)
	{
		memcpy(frame, data + 2, frame_size);
	}

	UINT port = fuzz_ports[data[0] % FUZZ_NUM_PORTS];
	fuzz_now += (UINT64)data[1] * 10;
	SwitchInput(fuzz_switch, fuzz_now, port, frame, frame_size);
	SwitchInput(fuzz_secure, fuzz_now, port, frame, frame_size);

	if (data[1] == FUZZ_AGE)
	{
		SwitchAge(fuzz_switch, fuzz_now);
		SwitchAge(fuzz_secure, fuzz_now);
		PolicyAge(fuzz_engine, fuzz_now);
	}
	else if (data[1] == FUZZ_CLEAR)
	{
		SWITCH_MAC_ENTRY macs[FUZZ_LIST];
		SWITCH_IP_ENTRY ips[FUZZ_LIST];

		// The first entries of each table, then the entries of the source of the frame and of the address at the place of the
		// source of an IPv4 packet, then every entry (SDN-50-N, #492)
		SwitchGetMacs(fuzz_switch, macs, FUZZ_LIST);
		SwitchGetIps(fuzz_switch, ips, FUZZ_LIST);
		if (frame_size >= 30)
		{
			SwitchClearMac(fuzz_switch, frame + 6);
			SwitchClearIps(fuzz_switch, frame + 26, 4);
		}
		SwitchClearMacs(fuzz_switch);
		SwitchClearMacs(fuzz_secure);
		SwitchClearIps(fuzz_switch, NULL, 0);
		SwitchClearIps(fuzz_secure, NULL, 0);
	}

	free(frame);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzSwitch, data, size);

	return 0;
}
