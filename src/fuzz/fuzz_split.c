// fuzz_split.c
// libFuzzer target: TCP splitting of the Node module (Cedar/NodeSplit.c, CORE-P2-3 #94), which reads the control records that a
// peer sends on its Noise session for a split flow (NodeSplitParseRecord) and writes its own (NodeSplitWriteRecord), and builds
// the reset that refuses the SYN of a TCP connection of the host from that SYN (NodeSplitReset). The first byte of an input,
// modulo 2, picks what the rest is: 0, a control record; 1, an IP packet of the host. A record that reads as one of a split flow
// is written back and must give the same bytes; a reset that a packet gives is an IPv4 TCP segment with RST and ACK from the
// destination of the packet to its source. The rest of the input is copied into a buffer of its size exactly, so that
// AddressSanitizer reports a read past it.
//
// fuzz-max-len: 65536

#include "fuzz_common.h"

#include "Cedar/CedarType.h"
#include "Cedar/Node.h"
#include "Cedar/NodeEgress.h"
#include "Cedar/NodeSplit.h"

#include <stdlib.h>
#include <string.h>

// Largest input accepted: the kind byte and the largest payload of a record; longer inputs are skipped
#define	FUZZ_MAX_INPUT_SIZE		65536

// One input: the kind, then a control record or a packet
static void FuzzSplit(const uint8_t *data, size_t size)
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

	if (data[0] % 2 == 0)
	{
		NODE_SPLIT_RECORD r;

		if (NodeSplitParseRecord(buf, n, &r))
		{
			UCHAR *again = malloc(NODE_SPLIT_MAX_RECORD);

			if (again == NULL)
			{
				free(buf);
				return;
			}
			if (r.Kind < NODE_SPLIT_RECORD_OPEN || r.Kind > NODE_SPLIT_RECORD_RESET || NodeSplitWriteRecord(again, NODE_SPLIT_MAX_RECORD, &r) != n ||
				memcmp(again, buf, n) != 0)
			{
				abort();
			}
			free(again);
		}
	}
	else
	{
		UCHAR reset[40];
		NODE_EGRESS_PACKET p, q;
		UINT len = NodeSplitReset(reset, sizeof(reset), buf, n);

		if (len != 0)
		{
			if (len != 40 || NodeEgressParse(buf, n, &p) == false || NodeEgressParse(reset, len, &q) == false || q.Protocol != NODE_EGRESS_TCP ||
				q.TcpFlags != (NODE_EGRESS_RST | NODE_EGRESS_ACK) || memcmp(q.Src, p.Dst, 4) != 0 || memcmp(q.Dst, p.Src, 4) != 0 || q.SrcPort != p.DstPort ||
				q.DstPort != p.SrcPort)
			{
				abort();
			}
		}
	}

	free(buf);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzSplit, data, size);

	return 0;
}
