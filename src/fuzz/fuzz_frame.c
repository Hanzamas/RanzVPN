// fuzz_frame.c
// libFuzzer target: the header of a record of a Noise session (Cedar/NodeSourceGroup.c, SDN-87 #386), which a node reads
// in front of the data record of every record that a peer sends it (NodeFrameParse). A record of frame version 0 begins
// with the VRF tag of a VRF and has no header; a record whose VRF tag is 0, the VRF tag of no VRF, is of frame version 1,
// whose options carry the source group of its packet, or of a later frame version, which the node drops. Every input is a
// record, copied into a buffer of its size exactly, so that AddressSanitizer reports a read past it. What the node reads
// must hold:
// - a record that it takes has a header within the record: none, or the 8 bytes of the fixed header and whole words of
//   options; a record that it drops has no header and no claim;
// - a record whose VRF tag is not 0 is taken with no header and no claim;
// - a claim comes from the session, with its tag set and the group generation of its sender, and its group ID has 16 bits.
//
// fuzz-max-len: 2048

#include "fuzz_common.h"

#include "Cedar/CedarType.h"
#include "Cedar/Node.h"
#include "Cedar/NodeSourceGroup.h"

#include <stdlib.h>
#include <string.h>

// Largest input accepted (fuzz-max-len above): longer inputs are skipped. A header holds at most 255 words of options.
#define	FUZZ_MAX_INPUT_SIZE		2048

// One input: a record of a Noise session
static void FuzzFrame(const uint8_t *data, size_t size)
{
	NODE_SOURCE_CLAIM claim;
	UINT header = 0;

	if (size > FUZZ_MAX_INPUT_SIZE)
	{
		return;
	}

	// malloc() rather than Malloc(): the copy is exactly 'size' bytes, so AddressSanitizer reports any read past
	// the end of the input
	UCHAR *copy = malloc(size != 0 ? size : 1);
	if (copy == NULL)
	{
		return;
	}
	memcpy(copy, data, size);

	bool taken = NodeFrameParse(copy, (UINT)size, &claim, &header);

	if (taken)
	{
		if (header > size || (header != 0 && (header < NODE_FRAME_HEADER || (header - NODE_FRAME_HEADER) % 4 != 0)))
		{
			abort();
		}
		if (header == 0 && claim.Carried)
		{
			abort();
		}
	}
	else if (header != 0 || claim.Carried)
	{
		abort();
	}

	if (size >= NODE_OVERLAY_VRF_TAG && READ_UINT(copy) != 0 && (taken == false || header != 0 || claim.Carried))
	{
		abort();
	}

	if (claim.Carrier != NODE_CARRIER_SESSION || (claim.Carried && (claim.HasTags == false || claim.HasGeneration == false || claim.Group > 0xFFFF)))
	{
		abort();
	}

	free(copy);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzFrame, data, size);

	return 0;
}
