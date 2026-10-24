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
// fuzz-max-len: 9219
// fuzz-libs: coreswitch

#include "fuzz_common.h"

#include "Core/Switch.h"

#include <stdlib.h>
#include <string.h>

// Largest input accepted: the two bytes in front, and one byte above the largest frame, so that a frame that is too
// long is fuzzed too; longer inputs are skipped
#define	FUZZ_MAX_INPUT_SIZE		(2 + SWITCH_MAX_FRAME + 1)

#define	FUZZ_NUM_PORTS			4				// The ports of the switch: three members and one port without a member
#define	FUZZ_AGE				0xFF			// The clock byte that ages the MAC table after the frame
#define	FUZZ_CLEAR				0xFE			// ... and the one that clears it

static SWITCH *fuzz_switch = NULL;
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

// Once: the switch, its members and their subscriptions
static bool FuzzSwitchSetup()
{
	static const USHORT trunk[] = {10, 20, 30};
	static const USHORT native_trunk[] = {20};
	static const UCHAR broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	static const UCHAR mdns[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB};
	SWITCH_CONFIG c;
	SWITCH_PORT_CONFIG p;

	if (fuzz_switch != NULL)
	{
		return true;
	}

	memset(&c, 0, sizeof(c));
	c.MaxPorts = FUZZ_NUM_PORTS;
	c.MaxMacs = 64;
	c.AgingTime = 2000;
	c.BroadcastLimit = 50;
	c.MulticastLimit = 20;
	fuzz_switch = SwitchNew(&c);
	if (fuzz_switch == NULL)
	{
		return false;
	}

	memset(&p, 0, sizeof(p));
	p.Send = FuzzSwitchSend;
	p.Mode = SWITCH_ACCESS;
	p.Vlan = 10;
	fuzz_ports[0] = SwitchAddPort(fuzz_switch, &p);

	p.Mode = SWITCH_TRUNK;
	p.Vlan = 0;
	p.Allowed = trunk;
	p.NumAllowed = sizeof(trunk) / sizeof(trunk[0]);
	fuzz_ports[1] = SwitchAddPort(fuzz_switch, &p);

	p.Vlan = 10;
	p.Allowed = native_trunk;
	p.NumAllowed = sizeof(native_trunk) / sizeof(native_trunk[0]);
	fuzz_ports[2] = SwitchAddPort(fuzz_switch, &p);

	// The last port has no member
	fuzz_ports[3] = FUZZ_NUM_PORTS - 1;

	return SwitchSubscribe(fuzz_switch, fuzz_ports[0], 10, broadcast) && SwitchSubscribe(fuzz_switch, fuzz_ports[0], 10, mdns) &&
		SwitchSubscribe(fuzz_switch, fuzz_ports[1], 10, broadcast) && SwitchSubscribe(fuzz_switch, fuzz_ports[1], 20, NULL) &&
		SwitchSubscribe(fuzz_switch, fuzz_ports[1], 30, broadcast) && SwitchSubscribe(fuzz_switch, fuzz_ports[2], 10, broadcast) &&
		SwitchSubscribe(fuzz_switch, fuzz_ports[2], 20, broadcast);
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

	fuzz_now += (UINT64)data[1] * 10;
	SwitchInput(fuzz_switch, fuzz_now, fuzz_ports[data[0] % FUZZ_NUM_PORTS], frame, frame_size);

	if (data[1] == FUZZ_AGE)
	{
		SwitchAge(fuzz_switch, fuzz_now);
	}
	else if (data[1] == FUZZ_CLEAR)
	{
		SwitchClearMacs(fuzz_switch);
	}

	free(frame);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzSwitch, data, size);

	return 0;
}
