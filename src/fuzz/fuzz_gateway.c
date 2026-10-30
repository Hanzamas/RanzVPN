// fuzz_gateway.c
// libFuzzer target: the gateway HA of the Node module (Cedar/NodeGateway.c, SDN-19 #195), which reads the control records
// that a peer sends on its Noise session as a probe or the answer to one (NodeGatewayParseProbe), the records of the datagram
// path of the peer agent, of which the control records carry a probe or its answer behind the VRF tag of no VRF
// (NodeGatewayParseDatagram; SDN-19-R1, #507), and the IP packets of the host whose flow hash picks the gateway of a flow
// (NodeGatewayFlowHash). The first byte of an input, modulo 3, picks what the rest is: 0, a control record; 1, a packet; 2, a
// record of the datagram path. A control record that reads as a probe is written back and must give the same bytes; a record
// of the datagram path is a control record exactly when it starts with the VRF tag 0 and the kind NODE_GATEWAY_DATAGRAM, and
// one that holds a probe is written back to the same bytes; a packet hashes the same twice, and to 0 when it is neither IPv4
// nor IPv6. The rest of the input is copied into a buffer of its size exactly, so that AddressSanitizer reports a read past
// it.
//
// fuzz-max-len: 65536

#include "fuzz_common.h"

#include "Cedar/CedarType.h"
#include "Cedar/Node.h"
#include "Cedar/NodeGateway.h"

#include <stdlib.h>
#include <string.h>

// Largest input accepted: the kind byte and the largest payload of a record; longer inputs are skipped
#define	FUZZ_MAX_INPUT_SIZE		65536

// One input: the kind, then a control record, a packet or a record of the datagram path
static void FuzzGateway(const uint8_t *data, size_t size)
{
	if (size < 1 || size > FUZZ_MAX_INPUT_SIZE)
	{
		return;
	}

	// malloc() rather than Malloc(): the copy is exactly the rest of the input, so AddressSanitizer reports any read past it
	UINT n = (UINT)size - 1;
	UCHAR *buf = malloc(n != 0 ? n : 1);
	if (buf == NULL)
	{
		return;
	}
	memcpy(buf, data + 1, n);

	if (data[0] % 3 == 0)
	{
		NODE_GATEWAY_PROBE_MSG m;

		if (NodeGatewayParseProbe(buf, n, &m))
		{
			UCHAR again[NODE_GATEWAY_PROBE_SIZE];

			if (n != NODE_GATEWAY_PROBE_SIZE || (m.Kind != NODE_GATEWAY_PROBE_ASK && m.Kind != NODE_GATEWAY_PROBE_ANSWER) ||
				NodeGatewayWriteProbe(again, m.Kind, m.Sequence, m.Time) != NODE_GATEWAY_PROBE_SIZE || memcmp(again, buf, n) != 0)
			{
				abort();
			}
		}
	}
	else if (data[0] % 3 == 2)
	{
		NODE_GATEWAY_PROBE_MSG m;
		bool control = NodeGatewayParseDatagram(buf, n, &m);
		bool tagged = (n > NODE_OVERLAY_VRF_TAG && buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 0 && buf[NODE_OVERLAY_VRF_TAG] == NODE_GATEWAY_DATAGRAM);

		if (control != tagged || (control == false && m.Kind != 0))
		{
			abort();
		}
		if (control && m.Kind != 0)
		{
			UCHAR again[NODE_GATEWAY_DATAGRAM_SIZE];

			if (n != NODE_GATEWAY_DATAGRAM_SIZE || (m.Kind != NODE_GATEWAY_PROBE_ASK && m.Kind != NODE_GATEWAY_PROBE_ANSWER) ||
				NodeGatewayWriteDatagram(again, m.Kind, m.Sequence, m.Time) != NODE_GATEWAY_DATAGRAM_SIZE || memcmp(again, buf, n) != 0)
			{
				abort();
			}
		}
	}
	else
	{
		UINT h = NodeGatewayFlowHash(buf, n);
		UINT version = (n != 0 ? buf[0] >> 4 : 0);

		if (h != NodeGatewayFlowHash(buf, n) || (h != 0 && (n < 20 || (version != 4 && version != 6))))
		{
			abort();
		}
	}

	free(buf);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzGateway, data, size);

	return 0;
}
