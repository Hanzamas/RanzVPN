// Console.c
// Console input and output of the Win32 layer (declared in Win32.h)

#include "Win32.h"

#include "Internat.h"
#include "Memory.h"
#include "Str.h"

static HANDLE hstdout = INVALID_HANDLE_VALUE;
static HANDLE hstdin = INVALID_HANDLE_VALUE;

// The standard handles that the console input and output functions read and write
void Win32InitConsole() {
	if (hstdout == INVALID_HANDLE_VALUE)
		hstdout = GetStdHandle(STD_OUTPUT_HANDLE);

	if (hstdin == INVALID_HANDLE_VALUE)
		hstdin = GetStdHandle(STD_INPUT_HANDLE);
}

bool Win32InputW(wchar_t *str, UINT size) {
	bool ret = false;
	DWORD read_size = 0;
	if (str == NULL)
		return false;
	if (size == 0)
		size = 0x7fffffff;

	if (size <= sizeof(wchar_t)) {
		Zero(str, size);

		Win32InputDiscardLine();

		return false;
	}

	if (ReadConsoleW(hstdin, str, (size / sizeof(wchar_t)) - 1, &read_size, NULL)) {
		str[read_size] = 0;

		UniTrimCrlf(str);

		ret = true;
	} else {
		ret = Win32InputFromFileW(str, size);
	}

	return ret;
}

void Win32InputDiscardLine() {
	char *a = Win32InputFromFileLineA();

	Free(a);
}

bool Win32InputFromFileW(wchar_t *str, UINT size) {
	if (str == NULL)
		return false;

	char *a = Win32InputFromFileLineA();
	if (a == NULL) {
		UniStrCpy(str, size, L"");
		return false;
	}

	UtfToUni(str, size, a);

	UniTrimCrlf(str);

	Free(a);

	return true;
}
char *Win32InputFromFileLineA() {
	BUF *b = NewBuf();
	char zero = 0;
	char *ret = NULL;
	bool ok = true;

	while (true) {
		char c;
		DWORD read_size = 0;

		if (ReadFile(hstdin, &c, 1, &read_size, NULL) == false) {
			ok = false;
			break;
		}
		if (read_size != 1) {
			ok = false;
			break;
		}

		WriteBuf(b, &c, 1);

		if (c == 10)
			break;
	}

	WriteBuf(b, &zero, 1);

	if (ok)
		ret = CopyStr(b->Buf);

	FreeBuf(b);

	return ret;
}

void Win32PrintW(wchar_t *str) {
	DWORD write_size = 0;
	if (str == NULL)
		return;

	// A GUI program started without a console, such as ranz-node by its service commands, has no standard output.
	// A write to that handle is an invalid handle reference, which the strict handle checks of the node
	// (Cedar/NodeHarden.c) raise as an exception.
	if (hstdout == NULL || hstdout == INVALID_HANDLE_VALUE)
		return;

	if (WriteConsoleW(hstdout, str, UniStrLen(str), &write_size, NULL) == false)
		Win32PrintToFileW(str);
}
void Win32PrintToFileW(wchar_t *str) {
	DWORD size = 0;
	if (str == NULL)
		return;

	char *utf = CopyUniToUtf(str);

	WriteFile(hstdout, utf, StrLen(utf), &size, NULL);

	Free(utf);
}
