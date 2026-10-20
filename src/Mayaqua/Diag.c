// Diag.c
// Call stacks of the Win32 layer, for the memory check (declared in Win32.h)
//
// WIN32_NO_DEBUG_HELP_DLL (no DbgHelp call stacks) comes from the build, per configuration
// (cmake/RanzOptions.cmake)

#include "Win32.h"

#include "Mayaqua.h"
#include "Memory.h"
#include "Tracking.h"

#include <string.h>

#ifndef	WIN32_NO_DEBUG_HELP_DLL
#include <DbgHelp.h>		// The call stacks of Win32GetCallStack and Win32GetCallStackSymbolInfo
#endif

static HANDLE hCurrentProcessHandle = NULL;

#define	CALLSTACK_DEPTH			12
#define	CALLSTACK_NAME_CHARS	512		// Longest symbol name that SymFromAddrW writes, with its NUL

// The frames of the calling thread: one CALLSTACK_DATA per return address, symbol names not resolved yet
CALLSTACK_DATA *Win32GetCallStack()
{
#ifndef	WIN32_NO_DEBUG_HELP_DLL
	void *frames[CALLSTACK_DEPTH];
	CALLSTACK_DATA *cs = NULL, *s = NULL;
	UINT num, i;

	// Frame 0 is this function (skip 0): the callers drop their own frames with WalkDownCallStack
	num = (UINT)CaptureStackBackTrace(0, CALLSTACK_DEPTH, frames, NULL);

	for (i = 0;i < num;i++)
	{
		CALLSTACK_DATA *n = Win32MemoryAlloc(sizeof(CALLSTACK_DATA));

		n->symbol_cache = false;
		n->next = NULL;
		n->offset = (UINT64)(UINT_PTR)frames[i];
		n->disp = 0;
		n->name = NULL;
		n->line = 0;
		n->filename[0] = 0;

		if (s == NULL)
		{
			cs = n;
		}
		else
		{
			s->next = n;
		}
		s = n;
	}

	return cs;
#else
	return NULL;
#endif
}

// Resolves the name, the line and the file name of one frame, when a stack is printed
bool Win32GetCallStackSymbolInfo(CALLSTACK_DATA *s)
{
#ifdef	WIN32_NO_DEBUG_HELP_DLL
	return false;
#else
	struct
	{
		SYMBOL_INFOW info;
		wchar_t name_tail[CALLSTACK_NAME_CHARS];	// SYMBOL_INFOW.Name continues in here
	} sym;
	IMAGEHLP_LINEW64 line;
	DWORD64 disp64 = 0;
	DWORD disp32 = 0;		// The DWORD that SymGetLineFromAddrW64 writes
	wchar_t *file_name;
	int size;
	if (s == NULL)
	{
		return false;
	}

	if (s->symbol_cache)
	{
		return true;
	}

	Zero(&sym, sizeof(sym));
	sym.info.SizeOfStruct = sizeof(sym.info);
	sym.info.MaxNameLen = CALLSTACK_NAME_CHARS - 1;

	s->disp = 0;
	s->name = NULL;
	if (SymFromAddrW(hCurrentProcessHandle, s->offset, &disp64, &sym.info))
	{
		size = WideCharToMultiByte(CP_ACP, 0, sym.info.Name, -1, NULL, 0, NULL, NULL);
		if (size > 0)
		{
			s->name = Win32MemoryAlloc((UINT)size);
			if (WideCharToMultiByte(CP_ACP, 0, sym.info.Name, -1, s->name, size, NULL, NULL) != 0)
			{
				s->disp = disp64;
			}
			else
			{
				Win32MemoryFree(s->name);
				s->name = NULL;
			}
		}
	}

	s->line = 0;
	s->filename[0] = 0;
	Zero(&line, sizeof(line));
	line.SizeOfStruct = sizeof(line);
	if (SymGetLineFromAddrW64(hCurrentProcessHandle, s->offset, &disp32, &line))
	{
		// The file name without its directory
		file_name = wcsrchr(line.FileName, L'\\');
		file_name = (file_name == NULL) ? line.FileName : file_name + 1;
		if (WideCharToMultiByte(CP_ACP, 0, file_name, -1, s->filename, sizeof(s->filename), NULL, NULL) != 0)
		{
			s->line = line.LineNumber;
		}
		else
		{
			s->filename[0] = 0;
		}
	}

	s->symbol_cache = true;

	return true;
#endif
}

// The process handle of the symbol queries; DbgHelp symbols are loaded only for a memory check run
void Win32InitCallStack()
{
	hCurrentProcessHandle = GetCurrentProcess();

	if (IsMemCheck())
	{
#ifndef	WIN32_NO_DEBUG_HELP_DLL
		SymInitialize(hCurrentProcessHandle, NULL, TRUE);
#endif
	}
}

void Win32FreeCallStack()
{
	if (IsMemCheck())
	{
#ifndef	WIN32_NO_DEBUG_HELP_DLL
		SymCleanup(hCurrentProcessHandle);
#endif
	}
}
