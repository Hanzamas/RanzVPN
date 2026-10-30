// fuzz-fault.c
// The planted fault of the fuzz campaign (AUD-3, #363; .github/workflows/fuzz.yml, .github/scripts/fuzz-campaign.py): a
// libFuzzer target whose input "FUZZ" writes one byte past a buffer on the stack, which AddressSanitizer stops on. The
// campaign runs it as it runs a target of src/fuzz, from a seed that is one byte away from the input ("FUZY"), and the
// leg must end in a finding with the input that found it saved. A campaign that reported nothing could not be told from
// one that found nothing, so a leg that does not report this fault fails.
//
// The build job of fuzz.yml builds it with clang-cl -fsanitize=fuzzer,address as fuzz_canary.exe. It is no target of
// src/fuzz, so the registry check, CMake and the other jobs know nothing of it.

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size >= 4 && data[0] == 'F' && data[1] == 'U' && data[2] == 'Z' && data[3] == 'Z')
	{
		char buffer[4];
		// The fault: the index is one past the buffer, and volatile keeps the compiler from seeing that
		volatile size_t index = sizeof(buffer);
		volatile char *block = buffer;

		block[index] = 1;
	}

	return 0;
}
