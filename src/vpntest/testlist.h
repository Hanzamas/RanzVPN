// testlist.h
// The tests of vpntest register themselves
//
// A test file registers its test procedure with RANZ_TEST after its includes, next to the procedure:
//
//   RANZ_TEST("fifo", fifo_test, "FIFO and queue: what the test checks.");
//   void fifo_test(UINT num, char **arg)
//
// The macro also declares the procedure. vpntest.c finds the registrations of every object file of the program in
// one section, so a new test is a new file (src/vpntest/CMakeLists.txt takes every .c file of the directory): no
// table, declaration or list of names is edited anywhere. "vpntest list" prints the registered tests, and
// .github/scripts/vpntest.ps1 runs each of them as a smoke test, except the ones in .github/quality/smoke-exclude.txt
// (and, in the fuzz-asan job, .github/quality/asan-exclude.txt). A test that prints "<NAME> TEST OK", with <NAME> its
// name in capitals, and no leak, passes there.
//
// RANZ_TEST_TAGS adds comma-separated tags, which "vpntest list" prints and RANZ_SMOKE_TAG of vpntest.ps1 selects by:
//   core  the test exercises the modules of the new core (src/Core); the coverage job runs these tests
//
// How it is collected: a registration is a pointer in the section .rztest$m. The linkers (link.exe, lld-link) join the
// sections that differ only after the '$' into one, ordered by that suffix, so the pointers of all object files lie
// between the markers that vpntest.c puts in .rztest$a and .rztest$z. A section name with a '$' is also what
// AddressSanitizer leaves alone, so it does not pad the pointers with red zones. The section is not a COMDAT, so
// /OPT:REF keeps it. vpntest.ps1 checks that every registration of the sources is in "vpntest list", so a
// registration that did not make it into the program fails the script instead of leaving a test unrun.

#ifndef	TESTLIST_H
#define	TESTLIST_H

#include "Mayaqua/MayaType.h"

// Test function definition
typedef void (TEST_PROC)(UINT num, char **arg);

typedef struct TEST_LIST
{
	char *command_str;		// The name on the command line, the same in no other test
	TEST_PROC *proc;
	char *tags;				// Comma-separated tags, "" for none
	char *help;				// One line for the command list
} TEST_LIST;

#pragma section(".rztest$a", read)
#pragma section(".rztest$m", read)
#pragma section(".rztest$z", read)

// Registers proc under name, with tags (a string) and help, and declares proc
#define	RANZ_TEST_TAGS(name, proc, tags, help)															\
	void proc(UINT num, char **arg);																	\
	const TEST_LIST ranz_test_##proc = {name, proc, tags, help};										\
	__declspec(allocate(".rztest$m")) const TEST_LIST *const ranz_test_ref_##proc = &ranz_test_##proc

#define	RANZ_TEST(name, proc, help)		RANZ_TEST_TAGS(name, proc, "", help)

#endif	// TESTLIST_H
