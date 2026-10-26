// fuzz_nodemimic.c
// libFuzzer target: what the mimicry sidecar of a node sends it (Cedar/NodeMimic.c and Cedar/NodeMimicTransport.c,
// CORE-P2-6 #406): the messages of the control pipe, one JSON object per line (NodeMimicParseMessage), the line in front
// of a stream of the data pipe of the server role (NodeMimicParseBind) and the answer to a dial of the client role
// (NodeMimicParseAnswer). The input is a run of lines, split at each newline as the node splits what it reads, and each
// line goes to all three, copied into a buffer of its size and its NUL exactly, so that AddressSanitizer reports a read
// past it. A binding that a line gives is none or NODE_MIMIC_BINDING bytes, and a reason ends within its buffer.
//
// fuzz-max-len: 8192

#include "fuzz_common.h"

#include "Cedar/CedarType.h"
#include "Cedar/Node.h"

#include <stdlib.h>
#include <string.h>

// One line of the input, without its newline
static void FuzzNodeMimicLine(const uint8_t *data, size_t size)
{
	NODE_MIMIC_MESSAGE *m = malloc(sizeof(NODE_MIMIC_MESSAGE));
	char *line = malloc(size + 1);
	UCHAR binding[NODE_MIMIC_BINDING];
	char reason[64];
	UINT binding_size = 0xFFFF;

	if (m == NULL || line == NULL)
	{
		abort();
	}

	memcpy(line, data, size);
	line[size] = 0;

	if (NodeMimicParseMessage(line, m) && m->Type[0] == 0)
	{
		// A message has a type
		abort();
	}

	if (NodeMimicParseBind(line, binding, &binding_size) && binding_size != 0 && binding_size != NODE_MIMIC_BINDING)
	{
		abort();
	}

	binding_size = 0xFFFF;
	UINT answer = NodeMimicParseAnswer(line, binding, &binding_size, reason, sizeof(reason));
	if (answer > NODE_MIMIC_ANSWER_BAD || (answer == NODE_MIMIC_ANSWER_OK && binding_size != 0 && binding_size != NODE_MIMIC_BINDING) ||
		strnlen(reason, sizeof(reason)) >= sizeof(reason))
	{
		abort();
	}

	free(line);
	free(m);
}

static void FuzzNodeMimic(const uint8_t *data, size_t size)
{
	size_t start = 0;

	for (size_t i = 0;i <= size;i++)
	{
		if (i == size || data[i] == '\n')
		{
			FuzzNodeMimicLine(data + start, i - start);
			start = i + 1;
		}
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzNodeMimic, data, size);

	return 0;
}
