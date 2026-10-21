// Tracking.c
// Object tracking module

#include "Tracking.h"

#include "Mayaqua.h"
#include "Memory.h"
#include "Native.h"
#include "Str.h"
#include "Win32.h"

static LOCK *obj_lock;
static volatile LONG obj_id;
static LOCK *cs_lock;
static TRACKING_LIST **hashlist;

static bool do_not_get_callstack;

void MemoryDebugMenu() {
	char tmp[MAX_SIZE];
	TOKEN_LIST *t;
	char *cmd;
	Print("Mayaqua Kernel Memory Debug Tools\n"
	      "Copyright (c) SoftEther VPN Project. All Rights Reserved.\n\n");

	g_memcheck = false;
	while (true) {
		Print("debug>");
		GetLine(tmp, sizeof(tmp));
		t = ParseToken(tmp, " \t");
		if (t->NumTokens == 0) {
			FreeToken(t);
			DebugPrintAllObjects();
			continue;
		}
		cmd = t->Token[0];
		if (!StrCmpi(cmd, "?")) {
			DebugPrintCommandList();
		} else if (!StrCmpi(cmd, "a")) {
			DebugPrintAllObjects();
		} else if (!StrCmpi(cmd, "i")) {
			if (t->NumTokens == 1) {
				Print("Usage: i <obj_id>\n\n");
			} else {
				DebugPrintObjectInfo(ToInt(t->Token[1]));
			}
		} else if (!StrCmpi(cmd, "q")) {
			break;
		} else if (ToInt(cmd) != 0) {
			DebugPrintObjectInfo(ToInt(t->Token[0]));
		} else {
			Print("Command Not Found,\n\n");
		}
		FreeToken(t);
	}
	FreeToken(t);
	g_memcheck = true;
}

static int SortObjectView(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL) {
		return 0;
	}
	TRACKING_OBJECT *o1 = *(TRACKING_OBJECT **)p1;
	TRACKING_OBJECT *o2 = *(TRACKING_OBJECT **)p2;
	if (o1 == NULL || o2 == NULL) {
		return 0;
	}

	if (o1->Id > o2->Id) {
		return 1;
	} else if (o1->Id == o2->Id) {
		return 0;
	}
	return -1;
}

static void PrintObjectInfo(TRACKING_OBJECT *o) {
	SYSTEMTIME t;
	char tmp[MAX_SIZE];
	if (o == NULL) {
		return;
	}

	UINT64ToSystem(&t, o->CreatedDate);
	GetDateTimeStrMilli(tmp, sizeof(tmp), &t);

	Print("    TRACKING_OBJECT ID: %u\n"
	      "  TRACKING_OBJECT TYPE: %s\n"
	      "      ADDRESS: 0x%p\n"
	      "  TRACKING_OBJECT SIZE: %u bytes\n"
	      " CREATED DATE: %s\n",
	      o->Id, o->Name, UINT64_TO_POINTER(o->Address), o->Size, tmp);

	PrintCallStack(o->CallStack);
}

void DebugPrintObjectInfo(UINT id) {
	TRACKING_OBJECT *o = NULL;
	RawLock(obj_lock);
	{
		for (UINT i = 0; i < TRACKING_NUM_ARRAY; i++) {
			if (hashlist[i] != NULL) {
				TRACKING_LIST *t = hashlist[i];

				while (true) {
					if (t->Object->Id == id) {
						o = t->Object;
						break;
					}

					if (t->Next == NULL) {
						break;
					}

					t = t->Next;
				}

				if (o != NULL) {
					break;
				}
			}
		}
	}
	RawUnlock(obj_lock);

	if (o == NULL) {
		Print("obj_id %u Not Found.\n\n", id);
		return;
	}

	PrintObjectInfo(o);
	Print("\n");
}

static void PrintObjectList(TRACKING_OBJECT *o) {
	char tmp[MAX_SIZE];
	SYSTEMTIME t;
	UINT64ToSystem(&t, o->CreatedDate);
	GetTimeStrMilli(tmp, sizeof(tmp), &t);
	TrackGetObjSymbolInfo(o);
	Print("%-4u - [%-6s] %s 0x%p size=%-5u %11s %u\n",
	      o->Id, o->Name, tmp, UINT64_TO_POINTER(o->Address), o->Size, o->FileName, o->LineNumber);
}

void DebugPrintAllObjects() {
	LIST *view = NewListFast(SortObjectView);
	RawLock(obj_lock);
	{
		for (UINT i = 0; i < TRACKING_NUM_ARRAY; i++) {
			if (hashlist[i] != NULL) {
				TRACKING_LIST *t = hashlist[i];

				while (true) {
					Add(view, t->Object);

					if (t->Next == NULL) {
						break;
					}

					t = t->Next;
				}
			}
		}
	}
	RawUnlock(obj_lock);

	Sort(view);

	for (UINT i = 0; i < LIST_NUM(view); i++) {
		TRACKING_OBJECT *o = (TRACKING_OBJECT *)LIST_DATA(view, i);
		PrintObjectList(o);
	}

	ReleaseList(view);

	Print("\n");
}

void DebugPrintCommandList() {
	Print(
	    "a - All Objects\n"
	    "i - Object Information\n"
	    "? - Help\n"
	    "q - Quit\n\n");
}

void GetMemoryStatus(MEMORY_STATUS *status) {
	UINT num, size;
	if (status == NULL) {
		return;
	}

	RawLock(obj_lock);
	{
		size = num = 0;

		for (UINT i = 0; i < TRACKING_NUM_ARRAY; i++) {
			if (hashlist[i] != NULL) {
				TRACKING_LIST *t = hashlist[i];

				while (true) {
					TRACKING_OBJECT *o = t->Object;

					if (StrCmpi(o->Name, "MEM") == 0) {
						num++;
						size += o->Size;
					}

					if (t->Next == NULL) {
						break;
					}

					t = t->Next;
				}
			}
		}
	}
	RawUnlock(obj_lock);

	status->MemoryBlocksNum = num;
	status->MemorySize = size;
}

void TrackGetObjSymbolInfo(TRACKING_OBJECT *o) {
	if (o == NULL) {
		return;
	}

	if (!(o->LineNumber == 0 && o->FileName[0] == 0)) {
		return;
	}

	if (o->CallStack != NULL) {
		GetCallStackSymbolInfo(o->CallStack);
		if (StrLen(o->CallStack->filename) != 0 && o->CallStack->line != 0) {
			StrCpy(o->FileName, sizeof(o->FileName), o->CallStack->filename);
			o->LineNumber = o->CallStack->line;
		}
	}
}

void TrackNewObj(UINT64 addr, char *name, UINT size) {
	if (addr == 0 || name == NULL) {
		return;
	}

	if ((IsTrackingEnabled() && IsMemCheck()) == false) {
		return;
	}

	UINT new_id = (UINT)InterlockedIncrement(&obj_id);

	TRACKING_OBJECT *o = Win32MemoryAlloc(sizeof(TRACKING_OBJECT));
	o->Id = new_id;
	o->Address = addr;
	o->Name = name;
	o->Size = size;
	o->CreatedDate = LocalTime64();
	o->CallStack = WalkDownCallStack(GetCallStack(), 2);

	o->FileName[0] = 0;
	o->LineNumber = 0;

	RawLock(obj_lock);
	{
		InsertTrackingList(o);
	}
	RawUnlock(obj_lock);
}

void TrackDeleteObj(UINT64 addr) {
	TRACKING_OBJECT *o;
	if (addr == 0) {
		return;
	}

	if ((IsTrackingEnabled() && IsMemCheck()) == false) {
		return;
	}

	RawLock(obj_lock);
	{
		o = SearchTrackingList(addr);
		if (o == NULL) {
			RawUnlock(obj_lock);
			return;
		}
		DeleteTrackingList(o, true);
	}
	RawUnlock(obj_lock);
}

void TrackChangeObjSize(UINT64 addr, UINT size, UINT64 new_addr) {
	TRACKING_OBJECT *o;
	if (addr == 0) {
		return;
	}

	if ((IsTrackingEnabled() && IsMemCheck()) == false) {
		return;
	}

	RawLock(obj_lock);
	{
		o = SearchTrackingList(addr);
		if (o == NULL) {
			RawUnlock(obj_lock);
			return;
		}

		DeleteTrackingList(o, false);

		o->Size = size;
		o->Address = new_addr;

		InsertTrackingList(o);
	}
	RawUnlock(obj_lock);
}

TRACKING_OBJECT *SearchTrackingList(UINT64 Address) {
	if (Address == 0) {
		return NULL;
	}

	UINT i = TRACKING_HASH(Address);

	if (hashlist[i] != NULL) {
		TRACKING_LIST *tt = hashlist[i];

		while (true) {
			if (tt->Object->Address == Address) {
				return tt->Object;
			}

			tt = tt->Next;

			if (tt == NULL) {
				break;
			}
		}
	}

	return NULL;
}

void DeleteTrackingList(TRACKING_OBJECT *o, bool free_object_memory) {
	if (o == NULL) {
		return;
	}

	UINT i = TRACKING_HASH(o->Address);

	if (hashlist[i] != NULL) {
		TRACKING_LIST *ft = NULL;

		if (hashlist[i]->Object == o) {
			ft = hashlist[i];
			hashlist[i] = hashlist[i]->Next;
		} else {
			TRACKING_LIST *tt = hashlist[i];
			TRACKING_LIST *prev = NULL;

			while (true) {
				if (tt->Object == o) {
					prev->Next = tt->Next;
					ft = tt;
					break;
				}

				if (tt->Next == NULL) {
					break;
				}

				prev = tt;
				tt = tt->Next;
			}
		}

		if (ft != NULL) {
			Win32MemoryFree(ft);

			if (free_object_memory) {
				FreeCallStack(o->CallStack);
				Win32MemoryFree(o);
			}
		}
	}
}

void InsertTrackingList(TRACKING_OBJECT *o) {
	if (o == NULL) {
		return;
	}

	TRACKING_LIST *t = Win32MemoryAlloc(sizeof(TRACKING_LIST));
	t->Object = o;
	t->Next = NULL;

	UINT i = TRACKING_HASH(o->Address);

	if (hashlist[i] == NULL) {
		hashlist[i] = t;
	} else {
		TRACKING_LIST *tt = hashlist[i];
		while (true) {
			if (tt->Next == NULL) {
				tt->Next = t;
				break;
			}

			tt = tt->Next;
		}
	}
}

void InitTracking() {
	hashlist = (TRACKING_LIST **)Win32MemoryAlloc(sizeof(TRACKING_LIST *) * TRACKING_NUM_ARRAY);

	for (UINT i = 0; i < TRACKING_NUM_ARRAY; i++) {
		hashlist[i] = NULL;
	}

	obj_id = 0;

	obj_lock = NewRawLock();
	cs_lock = NewRawLock();

	CALLSTACK_DATA *s = GetCallStack();
	if (s == NULL) {
		do_not_get_callstack = true;
	} else {
		do_not_get_callstack = false;
		FreeCallStack(s);
	}
}

void FreeTracking() {
	DeleteRawLock(obj_lock);
	DeleteRawLock(cs_lock);
	cs_lock = NULL;
	obj_lock = NULL;

	for (UINT i = 0; i < TRACKING_NUM_ARRAY; i++) {
		if (hashlist[i] != NULL) {
			TRACKING_LIST *t = hashlist[i];

			while (true) {
				TRACKING_LIST *t2 = t;
				TRACKING_OBJECT *o = t->Object;

				FreeCallStack(o->CallStack);
				Win32MemoryFree(o);

				t = t->Next;

				Win32MemoryFree(t2);

				if (t == NULL) {
					break;
				}
			}
		}
	}

	Win32MemoryFree(hashlist);
}

void PrintCallStack(CALLSTACK_DATA *s) {
	char tmp[MAX_SIZE * 2];

	GetCallStackStr(tmp, sizeof(tmp), s);
	Print("%s", tmp);
}

void GetCallStackStr(char *str, UINT size, CALLSTACK_DATA *s) {
	char tmp[MAX_SIZE];
	char tmp2[MAX_SIZE];
	char tmp3[MAX_SIZE];
	UINT num, i;
	if (str == NULL) {
		return;
	}

	if (s == NULL) {
		StrCpy(str, size, "(Unknown)\n");
	} else {
		num = 0;
		str[0] = 0;
		while (true) {
			if (s == NULL) {
				break;
			}

			GetCallStackSymbolInfo(s);

			if (s->name == NULL) {
				Format(tmp, sizeof(tmp), "0x%02x ---", (UINT)s->offset);
			} else {
				Format(tmp, sizeof(tmp), "0x%p %s() + 0x%02x",
				       (void *)s->offset, s->name, (UINT)s->disp);
			}
			for (i = 0; i < num; i++) {
				tmp2[i] = ' ';
			}
			tmp2[i] = '\0';
			StrCpy(tmp3, sizeof(tmp3), tmp2);
			StrCat(tmp3, sizeof(tmp3), tmp);
			Format(tmp, sizeof(tmp), "%-55s %11s %u\n", tmp3, s->filename, s->line);
			StrCat(str, size, tmp);
			num++;
			s = s->next;
		}
	}
}

CALLSTACK_DATA *GetCallStack() {
	CALLSTACK_DATA *s;
	if (do_not_get_callstack) {
		return NULL;
	}

	RawLock(cs_lock);
	{
		s = Win32GetCallStack();
	}
	RawUnlock(cs_lock);
	if (s == NULL) {
		return NULL;
	}

	s = WalkDownCallStack(s, 3);

	return s;
}

bool GetCallStackSymbolInfo(CALLSTACK_DATA *s) {
	bool ret;
	if (s == NULL) {
		return false;
	}

	RawLock(cs_lock);
	{
		ret = Win32GetCallStackSymbolInfo(s);
	}
	RawUnlock(cs_lock);

	return ret;
}

CALLSTACK_DATA *WalkDownCallStack(CALLSTACK_DATA *s, UINT num) {
	CALLSTACK_DATA *tmp;
	if (s == NULL) {
		return NULL;
	}

	CALLSTACK_DATA *cs = s;
	UINT i = 0;

	while (true) {
		if (i >= num) {
			return cs;
		}
		i++;
		tmp = cs;
		cs = tmp->next;
		Win32MemoryFree(tmp->name);
		Win32MemoryFree(tmp);

		if (cs == NULL) {
			return NULL;
		}
	}
}

void FreeCallStack(CALLSTACK_DATA *s) {
	if (s == NULL) {
		return;
	}

	while (true) {
		CALLSTACK_DATA *next = s->next;
		Win32MemoryFree(s->name);
		Win32MemoryFree(s);
		if (next == NULL) {
			break;
		}
		s = next;
	}
}

