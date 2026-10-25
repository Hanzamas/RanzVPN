// fuzz_geneve.c
// libFuzzer target: the Geneve header of the VXLAN module of the new core (Core/VxlanGeneve.c, SDN-71 #347), which
// reads the datagrams that VTEPs of Geneve send. Every input runs:
// - through the parser of the header (VxlanParseGeneve), whose header must lie inside the input and whose options must
//   lie one after the other inside the header and within their limits; the data of each option is read to its last
//   byte, so AddressSanitizer reports an option that runs past the input;
// - as a datagram from a VTEP of Geneve through VxlanInput of a module that carries VNI 6001 with a flood list of a
//   VTEP of Geneve and one of VXLAN, and VNI 16777215 (0xFFFFFF) without one. The receiver sends every frame that the
//   ingress takes back to the VTEP it came from, in Geneve, and to the flood list of its VNI, so the encapsulation reads
//   the frame to its last byte and AddressSanitizer reports a frame that runs past the input.
//
// fuzz-max-len: 9217
// fuzz-libs: corevxlan

#include "fuzz_common.h"

#include "Core/Vxlan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Largest input accepted: one byte above the largest datagram of the module, so that a datagram that is too long is
// fuzzed too; longer inputs are skipped
#define	FUZZ_MAX_INPUT_SIZE		(VXLAN_MAX_DATAGRAM + 1)

static VXLAN *fuzz_geneve = NULL;
static VXLAN_ADDR fuzz_from;
static GENEVE_HEADER fuzz_header;
// The sum of the bytes of the options, so that the compiler keeps the reads
static volatile UINT fuzz_sum = 0;

// A property of the parser that does not hold: libFuzzer saves the input, with no abort message box and no Windows
// Error Reporting (as FuzzRun in fuzz_common.c)
static void FuzzFail(const char *what)
{
	fprintf(stderr, "==RANZ FUZZ== %s\n", what);
	fflush(stderr);
	_set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
	abort();
}

// The send procedure of the module: its datagrams go nowhere
static bool FuzzGeneveSend(void *param, const VXLAN_ADDR *dst, const void *data, UINT size)
{
	return true;
}

// The receiver: the frame goes back to the VTEP it came from, in Geneve, and to the flood list of its VNI
static void FuzzGeneveReceive(VXLAN *v, void *param, UINT vni, const VXLAN_ADDR *from, const UCHAR *frame, UINT size)
{
	VxlanSendTo(v, vni, from, frame, size);
	VxlanSend(v, vni, frame, size);
}

// Once: the module, with VNI 6001 and the flood list of a VTEP of Geneve and one of VXLAN, and VNI 16777215 without a
// flood list; the datagrams come from a VTEP of Geneve
static bool FuzzGeneveSetup()
{
	VXLAN_ADDR vteps[2];

	if (fuzz_geneve != NULL)
	{
		return true;
	}

	fuzz_geneve = VxlanNew(FuzzGeneveSend, NULL, FuzzGeneveReceive, NULL);
	if (fuzz_geneve == NULL)
	{
		return false;
	}

	VxlanAddrSetV4(&vteps[0], 192, 0, 2, 10, GENEVE_PORT);
	vteps[0].Encap = VXLAN_ENCAP_GENEVE;
	VxlanAddrSetV4(&vteps[1], 192, 0, 2, 20, VXLAN_PORT);
	VxlanAddrSetV4(&fuzz_from, 192, 0, 2, 10, 49152);
	fuzz_from.Encap = VXLAN_ENCAP_GENEVE;

	return VxlanSetVni(fuzz_geneve, 6001, vteps, 2) && VxlanSetVni(fuzz_geneve, VXLAN_MAX_VNI, NULL, 0);
}

// The header that VxlanParseGeneve read from the size bytes at data: inside the input, a whole number of words, and
// options that lie one after the other inside it, each within its limits, and fill it; each byte of their data is read
static void FuzzGeneveCheck(const UCHAR *data, UINT size, const GENEVE_HEADER *h)
{
	UINT pos = GENEVE_HEADER_SIZE;
	UINT sum = 0;

	if (h->Size < GENEVE_HEADER_SIZE || h->Size > size || h->Size % 4 != 0 || h->NumOptions > GENEVE_MAX_OPTIONS)
	{
		FuzzFail("VxlanParseGeneve gave a header outside the input, of a size that is no whole number of words, or with too many options");
	}

	for (UINT i = 0;i < h->NumOptions;i++)
	{
		const GENEVE_OPTION *o = &h->Options[i];

		if (o->Data != data + pos + 4 || o->Length > GENEVE_MAX_OPTION_DATA || o->Length % 4 != 0 || pos + 4 + o->Length > h->Size)
		{
			FuzzFail("VxlanParseGeneve gave an option that is not where the one before it ends, outside its header, or longer than an option holds");
		}
		if (o->Critical != ((o->Type & GENEVE_OPTION_CRITICAL) != 0))
		{
			FuzzFail("VxlanParseGeneve gave an option whose critical bit is not the high bit of its type");
		}

		for (UINT j = 0;j < o->Length;j++)
		{
			sum += o->Data[j];
		}
		pos += 4 + o->Length;
	}

	if (pos != h->Size)
	{
		FuzzFail("VxlanParseGeneve gave options that do not fill the option length");
	}

	fuzz_sum += sum;
}

// One input: a datagram from a VTEP of Geneve
static void FuzzGeneve(const uint8_t *data, size_t size)
{
	if (size == 0 || size > FUZZ_MAX_INPUT_SIZE || FuzzGeneveSetup() == false)
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

	if (VxlanParseGeneve(copy, (UINT)size, &fuzz_header))
	{
		FuzzGeneveCheck(copy, (UINT)size, &fuzz_header);
	}

	VxlanInput(fuzz_geneve, &fuzz_from, copy, (UINT)size);

	free(copy);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzGeneve, data, size);

	return 0;
}
