// fuzz_vxlan.c
// libFuzzer target: the ingress of the VXLAN module of the new core (Core/Vxlan.c, SDN-62 #289), which reads the
// datagrams that VTEPs send. Every input runs as a datagram through VxlanInput of a module that carries VNI 5001 with
// a flood list of two VTEPs and VNI 16777215 (0xFFFFFF) without one. The receiver sends every frame that the ingress
// takes back to the VTEP it came from and to the flood list of its VNI, so the encapsulation reads the frame to its
// last byte and AddressSanitizer reports a frame that runs past the input.
//
// fuzz-max-len: 9217
// fuzz-libs: corevxlan

#include "fuzz_common.h"

#include "Core/Vxlan.h"

#include <stdlib.h>
#include <string.h>

// Largest input accepted: one byte above the largest datagram of the module, so that a datagram that is too long is
// fuzzed too; longer inputs are skipped
#define	FUZZ_MAX_INPUT_SIZE		(VXLAN_MAX_DATAGRAM + 1)

static VXLAN *fuzz_vxlan = NULL;
static VXLAN_ADDR fuzz_from;

// The send procedure of the module: its datagrams go nowhere
static bool FuzzVxlanSend(void *param, const VXLAN_ADDR *dst, const void *data, UINT size)
{
	return true;
}

// The receiver: the frame goes back to the VTEP it came from, and to the flood list of its VNI
static void FuzzVxlanReceive(VXLAN *v, void *param, UINT vni, const VXLAN_ADDR *from, const UCHAR *frame, UINT size)
{
	VxlanSendTo(v, vni, from, frame, size);
	VxlanSend(v, vni, frame, size);
}

// Once: the module, with VNI 5001 and the flood list of two VTEPs, and VNI 16777215 without a flood list
static bool FuzzVxlanSetup()
{
	VXLAN_ADDR vteps[2];

	if (fuzz_vxlan != NULL)
	{
		return true;
	}

	fuzz_vxlan = VxlanNew(FuzzVxlanSend, NULL, FuzzVxlanReceive, NULL);
	if (fuzz_vxlan == NULL)
	{
		return false;
	}

	VxlanAddrSetV4(&vteps[0], 192, 0, 2, 10, VXLAN_PORT);
	VxlanAddrSetV4(&vteps[1], 192, 0, 2, 20, VXLAN_PORT);
	VxlanAddrSetV4(&fuzz_from, 192, 0, 2, 10, 49152);

	return VxlanSetVni(fuzz_vxlan, 5001, vteps, 2) && VxlanSetVni(fuzz_vxlan, VXLAN_MAX_VNI, NULL, 0);
}

// One input: a datagram from a VTEP
static void FuzzVxlan(const uint8_t *data, size_t size)
{
	if (size == 0 || size > FUZZ_MAX_INPUT_SIZE || FuzzVxlanSetup() == false)
	{
		return;
	}

	// malloc() rather than Malloc(): the copy is exactly 'size' bytes, so AddressSanitizer reports any read past
	// the end of the input
	UCHAR *copy = malloc(size);
	if (copy == NULL)
	{
		return;
	}
	memcpy(copy, data, size);

	VxlanInput(fuzz_vxlan, &fuzz_from, copy, (UINT)size);

	free(copy);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzVxlan, data, size);

	return 0;
}
