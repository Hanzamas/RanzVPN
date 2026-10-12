// fuzz_common.h
// Shared part of the libFuzzer targets in src/fuzz

#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H

#include "Mayaqua/MayaType.h"

// libFuzzer entry points (https://llvm.org/docs/LibFuzzer.html).
// LLVMFuzzerInitialize() is defined once, in fuzz_common.c; every fuzz_<name>.c
// defines LLVMFuzzerTestOneInput().
int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

// One run of a target's parser over one input
typedef void (FUZZ_PROC)(const uint8_t *data, size_t size);

// Runs proc over the input and calls abort() when the run leaked Mayaqua objects
void FuzzRun(FUZZ_PROC *proc, const uint8_t *data, size_t size);

// Copy of the input as a BUF positioned at its beginning
BUF *FuzzNewBuf(const uint8_t *data, size_t size);

#endif	// FUZZ_COMMON_H
