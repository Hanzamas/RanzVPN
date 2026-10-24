// fuzz_nodedhcp.c
// libFuzzer target: the DHCP responder of an L2 Network (Cedar/NodeDhcp.c, SDN-43 #236), which reads the frames that the
// members of the switch of its Network send: the DHCP messages of the clients, the answers of a DHCP server of the LAN
// and the ARP requests (NodeDhcpInput). The first byte of an input picks the configuration: bit 0 turns the mode off,
// bit 1 takes the smallest pool, a /30, in place of a /24 with two reservations. The rest is a run of frames, at most
// FUZZ_DHCP_MAX_FRAMES of them, so one input can carry a DHCPDISCOVER and the DHCPREQUEST after it: each after a byte
// that moves the clock on, in seconds, so offers, declined addresses and leases run out, and its size in 2 bytes
// (big-endian). The responder probes and serves before the first frame. After each frame every frame that the
// responder queued is taken and its leases and status are read. Each input builds the responder anew and frees it, so
// Mayaqua's leak check finds nothing left. Each frame is copied into a buffer of its size exactly, so that
// AddressSanitizer reports a read past it.
//
// fuzz-max-len: 12137

#include "fuzz_common.h"

#include "Cedar/CedarType.h"
#include "Cedar/Node.h"

#include <stdlib.h>
#include <string.h>

#define	FUZZ_DHCP_MAX_FRAMES	8				// Frames of one input at most
#define	FUZZ_DHCP_START			1000000			// The clock at the start (ms)

static const UCHAR fuzz_dhcp_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x43, 0x01};

// The configuration of the input's first byte
static void FuzzNodeDhcpConfig(NODE_DHCP_CONFIG *cfg, UCHAR pick)
{
	memset(cfg, 0, sizeof(NODE_DHCP_CONFIG));
	cfg->Serve = ((pick & 0x01) == 0);
	memcpy(cfg->Mac, fuzz_dhcp_mac, 6);
	cfg->LeaseTime = 3600;
	if ((pick & 0x02) != 0)
	{
		// 10.30.0.0/30: the responder at .1 and one client at .2
		cfg->Pool = 0x0A1E0000;
		cfg->PoolLength = 30;
		cfg->Address = 0x0A1E0001;
		return;
	}

	// 10.20.0.0/24 with the reservations 10.20.0.0/29 and 10.20.0.100, the gateway .1, the responder at .2
	cfg->Pool = 0x0A140000;
	cfg->PoolLength = 24;
	cfg->Address = 0x0A140002;
	cfg->Gateway = 0x0A140001;
	cfg->NumDns = 2;
	cfg->Dns[0] = 0x0A140035;
	cfg->Dns[1] = 0xC0000235;
	cfg->NumReserved = 2;
	cfg->ReservedAddress[0] = 0x0A140000;
	cfg->ReservedLength[0] = 29;
	cfg->ReservedAddress[1] = 0x0A140064;
	cfg->ReservedLength[1] = 32;
}

// Take every frame that the responder queued
static void FuzzNodeDhcpDrain(NODE_DHCP *d, UINT64 now, UCHAR *out)
{
	while (NodeDhcpOutput(d, now, out, NODE_DHCP_MAX_FRAME) != 0)
	{
	}
}

// One input: the configuration, then the frames
static void FuzzNodeDhcp(const uint8_t *data, size_t size)
{
	NODE_DHCP_CONFIG cfg;
	NODE_DHCP_STATUS st;
	UINT64 now = FUZZ_DHCP_START;

	if (size == 0)
	{
		return;
	}

	UCHAR *out = malloc(NODE_DHCP_MAX_FRAME);
	NODE_DHCP_LEASE *leases = malloc(sizeof(NODE_DHCP_LEASE) * NODE_DHCP_MAX_LEASES);
	if (out == NULL || leases == NULL)
	{
		free(out);
		free(leases);
		return;
	}

	FuzzNodeDhcpConfig(&cfg, data[0]);
	NODE_DHCP *d = NodeDhcpNew(&cfg, now);

	// The probe, then the responder serves
	FuzzNodeDhcpDrain(d, now, out);
	now += NODE_DHCP_PROBE_WAIT;

	size_t pos = 1;
	for (UINT i = 0;i < FUZZ_DHCP_MAX_FRAMES && pos + 3 <= size;i++)
	{
		UINT step = data[pos];
		UINT frame_size = ((UINT)data[pos + 1] << 8) | data[pos + 2];
		pos += 3;
		if (frame_size > size - pos)
		{
			frame_size = (UINT)(size - pos);
		}

		now += (UINT64)step * 1000;
		UCHAR *frame = malloc(frame_size != 0 ? frame_size : 1);
		if (frame == NULL)
		{
			break;
		}
		memcpy(frame, data + pos, frame_size);
		NodeDhcpInput(d, now, frame, frame_size);
		free(frame);
		pos += frame_size;

		FuzzNodeDhcpDrain(d, now, out);
		NodeDhcpGetLeases(d, now, leases, NODE_DHCP_MAX_LEASES);
		NodeDhcpGetStatus(d, now, &st);
	}

	NodeDhcpFree(d);
	free(out);
	free(leases);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzNodeDhcp, data, size);

	return 0;
}
