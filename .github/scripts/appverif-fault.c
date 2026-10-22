// appverif-fault.c
// The planted fault of the Application Verifier job of windows.yml (ADR-0040 item 4): it closes a
// handle a second time, which the Handles layer stops on. Without Application Verifier the second
// CloseHandle only fails and the program exits with 0. .github/scripts/appverif.ps1 runs it under
// Application Verifier before the tests and fails the job when the fault goes unreported, so a
// verifier that reports nothing cannot pass for one that found nothing.

#include <windows.h>

#include <stdio.h>

int main(void) {
	HANDLE event = CreateEventW(NULL, FALSE, FALSE, NULL);

	if (event == NULL) {
		printf("CreateEventW failed: %lu\n", GetLastError());
		return 2;
	}

	CloseHandle(event);

	// The fault: the handle is closed already
	BOOL closed = CloseHandle(event);
	printf("The second CloseHandle returned %d (error %lu)\n", closed, GetLastError());

	return 0;
}
