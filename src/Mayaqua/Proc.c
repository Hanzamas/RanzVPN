// Proc.c
// Process handle close and wait of the Win32 layer (declared in Win32.h)

#include "Win32.h"

void Win32CloseProcess(void *handle) {
	if (handle == NULL)
		return;

	CloseHandle((HANDLE)handle);
}

bool Win32WaitProcess(void *h, UINT timeout) {
	if (h == NULL)
		return false;
	if (timeout == 0)
		timeout = INFINITE;

	if (WaitForSingleObject((HANDLE)h, timeout) == WAIT_TIMEOUT)
		return false;

	return true;
}
