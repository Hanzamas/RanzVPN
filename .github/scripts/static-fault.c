// static-fault.c
// The planted finding of the static analysis job of windows.yml (ADR-0040 item 3): a pointer that is
// NULL on one path is written through on that path. clang-tidy (clang-analyzer-core.NullDereference)
// and MSVC /analyze (C6011) must each report it as a new finding, or the job fails, so an analyzer
// that reports nothing cannot pass for one that found nothing.

#include <stddef.h>

int StaticFaultPlanted(int *p) {
	if (p == NULL) {
		// The finding: p is NULL here
		*p = 1;
	}

	return p != NULL;
}
