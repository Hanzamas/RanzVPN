// RpcField.c
// Field-descriptor engine for the admin RPC structures
//
// Out writes the rows in table order. A top-level row uses the non-indexed
// Pack call (the first writer of a key wins); an item row uses the indexed
// call with the item count as total, item by item (the last writer wins).
// In reads the rows in the same order, so a row can depend on the rows read
// before it. Free releases the hook frees and the item arrays.

#include "RpcField.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"

// Member of row f in the structure at base
#define	RPC_FIELD_MEMBER(base, f)		((void *)(((UCHAR *)(base)) + (f)->Offset))

static void RpcFieldOutRows(const RPC_TABLE *t, PACK *p, void *base, UINT index, UINT total);
static void RpcFieldInRows(const RPC_TABLE *t, void *base, PACK *p, UINT index, UINT total);
static void RpcFieldFreeRows(const RPC_TABLE *t, void *base);

// Key of a row for a debug message
static char *RpcFieldKeyName(char *key)
{
	return (key != NULL ? key : "(no key)");
}

// Keys of the RPC envelope, which no row may write or read
static bool RpcFieldIsReservedKey(char *key)
{
	if (key == NULL)
	{
		return false;
	}

	return (StrCmpi(key, "function_name") == 0 || StrCmpi(key, "error") == 0 || StrCmpi(key, "error_code") == 0);
}

// Value of a BOOL row (a bool or a UINT member)
static bool RpcFieldGetBool(const RPC_FIELD *f, void *base)
{
	void *m = RPC_FIELD_MEMBER(base, f);

	if (f->Size == sizeof(bool))
	{
		return *((bool *)m);
	}

	return (*((UINT *)m) != 0);
}
static void RpcFieldSetBool(const RPC_FIELD *f, void *base, bool b)
{
	void *m = RPC_FIELD_MEMBER(base, f);

	if (f->Size == sizeof(bool))
	{
		*((bool *)m) = b;
	}
	else
	{
		*((UINT *)m) = (b ? 1 : 0);
	}
}

// Item count of an ARRAY row, or 0 when the item array would not fit in 32 bits
static UINT RpcFieldArrayCount(const RPC_FIELD *f, PACK *p)
{
	UINT num;

	if (f->Flags & RPC_FF_READ_NUMITEM)
	{
		num = PackGetInt(p, "NumItem");
	}
	else
	{
		num = PackGetIndexCount(p, f->Key);
	}

	if (((UINT64)num * (UINT64)f->Item->Size) > 0xFFFFFFFFULL)
	{
		num = 0;
	}

	return num;
}

// Write the items of a top-level ARRAY row
static void RpcFieldOutArray(const RPC_FIELD *f, PACK *p, void *base, UINT total)
{
	UINT i, num;
	UCHAR *items;

	if (total != 0 || f->Item == NULL)
	{
		Debug("RpcFieldOut: %s: nested or untyped array skipped\n", RpcFieldKeyName(f->Key));
		return;
	}

	num = *((UINT *)(((UCHAR *)base) + f->CountOffset));
	items = *((UCHAR **)RPC_FIELD_MEMBER(base, f));
	if (num == 0 || items == NULL)
	{
		return;
	}

	for (i = 0;i < num;i++)
	{
		RpcFieldOutRows(f->Item, p, items + ((size_t)f->Item->Size * i), i, num);
	}
}

// Read the items of a top-level ARRAY row
static void RpcFieldInArray(const RPC_FIELD *f, void *base, PACK *p, UINT total)
{
	UINT i, num;
	UCHAR *items;

	if (total != 0 || f->Item == NULL)
	{
		Debug("RpcFieldIn: %s: nested or untyped array skipped\n", RpcFieldKeyName(f->Key));
		return;
	}

	num = RpcFieldArrayCount(f, p);
	items = ZeroMalloc(f->Item->Size * num);

	*((UINT *)(((UCHAR *)base) + f->CountOffset)) = num;
	*((UCHAR **)RPC_FIELD_MEMBER(base, f)) = items;

	for (i = 0;i < num;i++)
	{
		RpcFieldInRows(f->Item, items + ((size_t)f->Item->Size * i), p, i, num);
	}
}

// Release the items of an ARRAY row
static void RpcFieldFreeArray(const RPC_FIELD *f, void *base)
{
	UINT i, num;
	UCHAR *items;
	const RPC_FIELD *r;
	bool item_free = false;

	if (f->Item == NULL)
	{
		return;
	}

	num = *((UINT *)(((UCHAR *)base) + f->CountOffset));
	items = *((UCHAR **)RPC_FIELD_MEMBER(base, f));

	for (r = f->Item->Fields;r->Type != RPC_FT_END;r++)
	{
		if (r->Hook != NULL && r->Hook->Free != NULL)
		{
			item_free = true;
		}
	}

	if (item_free && items != NULL)
	{
		for (i = 0;i < num;i++)
		{
			RpcFieldFreeRows(f->Item, items + ((size_t)f->Item->Size * i));
		}
	}

	Free(items);
}

// Generic write of one row
static void RpcFieldOutGeneric(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	void *m = RPC_FIELD_MEMBER(base, f);

	switch (f->Type)
	{
	case RPC_FT_INT:
	case RPC_FT_COUNT:
		if (total == 0)
		{
			PackAddInt(p, f->Key, *((UINT *)m));
		}
		else
		{
			PackAddIntEx(p, f->Key, *((UINT *)m), index, total);
		}
		break;

	case RPC_FT_BOOL:
		if (total == 0)
		{
			PackAddBool(p, f->Key, RpcFieldGetBool(f, base));
		}
		else
		{
			PackAddBoolEx(p, f->Key, RpcFieldGetBool(f, base), index, total);
		}
		break;

	case RPC_FT_INT64:
	case RPC_FT_TIME64:
		if (total == 0)
		{
			PackAddInt64(p, f->Key, *((UINT64 *)m));
		}
		else
		{
			PackAddInt64Ex(p, f->Key, *((UINT64 *)m), index, total);
		}
		break;

	case RPC_FT_STR:
		if (total == 0)
		{
			PackAddStr(p, f->Key, (char *)m);
		}
		else
		{
			PackAddStrEx(p, f->Key, (char *)m, index, total);
		}
		break;

	case RPC_FT_UNISTR:
		if (total == 0)
		{
			PackAddUniStr(p, f->Key, (wchar_t *)m);
		}
		else
		{
			PackAddUniStrEx(p, f->Key, (wchar_t *)m, index, total);
		}
		break;

	case RPC_FT_DATA:
		if (total == 0)
		{
			PackAddData(p, f->Key, m, f->Size);
		}
		else
		{
			PackAddDataEx(p, f->Key, m, f->Size, index, total);
		}
		break;

	case RPC_FT_IP32:
		if (total == 0)
		{
			PackAddIp32(p, f->Key, *((UINT *)m));
		}
		else
		{
			PackAddIp32Ex(p, f->Key, *((UINT *)m), index, total);
		}
		break;

	case RPC_FT_IP:
		if (total == 0)
		{
			PackAddIp(p, f->Key, (IP *)m);
		}
		else
		{
			PackAddIpEx(p, f->Key, (IP *)m, index, total);
		}
		break;

	case RPC_FT_ARRAY:
		RpcFieldOutArray(f, p, base, total);
		break;

	default:
		Debug("RpcFieldOut: %s: row type %u has no Out hook\n", RpcFieldKeyName(f->Key), f->Type);
		break;
	}
}

// Generic read of one row
static void RpcFieldInGeneric(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	void *m = RPC_FIELD_MEMBER(base, f);

	switch (f->Type)
	{
	case RPC_FT_INT:
		*((UINT *)m) = (total == 0 ? PackGetInt(p, f->Key) : PackGetIntEx(p, f->Key, index));
		break;

	case RPC_FT_BOOL:
		RpcFieldSetBool(f, base, (total == 0 ? PackGetBool(p, f->Key) : PackGetBoolEx(p, f->Key, index)));
		break;

	case RPC_FT_INT64:
	case RPC_FT_TIME64:
		*((UINT64 *)m) = (total == 0 ? PackGetInt64(p, f->Key) : PackGetInt64Ex(p, f->Key, index));
		break;

	case RPC_FT_STR:
		if (total == 0)
		{
			PackGetStr(p, f->Key, (char *)m, f->Size);
		}
		else
		{
			PackGetStrEx(p, f->Key, (char *)m, f->Size, index);
		}
		break;

	case RPC_FT_UNISTR:
		if (total == 0)
		{
			PackGetUniStr(p, f->Key, (wchar_t *)m, f->Size);
		}
		else
		{
			PackGetUniStrEx(p, f->Key, (wchar_t *)m, f->Size, index);
		}
		break;

	case RPC_FT_DATA:
		if (total == 0)
		{
			PackGetData2(p, f->Key, m, f->Size);
		}
		else
		{
			PackGetDataEx2(p, f->Key, m, f->Size, index);
		}
		break;

	case RPC_FT_IP32:
		*((UINT *)m) = (total == 0 ? PackGetIp32(p, f->Key) : PackGetIp32Ex(p, f->Key, index));
		break;

	case RPC_FT_IP:
		if (total == 0)
		{
			PackGetIp(p, f->Key, (IP *)m);
		}
		else
		{
			PackGetIpEx(p, f->Key, (IP *)m, index);
		}
		break;

	case RPC_FT_COUNT:
		// Derived: the ARRAY row sets the count
		break;

	case RPC_FT_ARRAY:
		RpcFieldInArray(f, base, p, total);
		break;

	default:
		Debug("RpcFieldIn: %s: row type %u has no In hook\n", RpcFieldKeyName(f->Key), f->Type);
		break;
	}
}

// Write the rows of a table
static void RpcFieldOutRows(const RPC_TABLE *t, PACK *p, void *base, UINT index, UINT total)
{
	const RPC_FIELD *f;

	for (f = t->Fields;f->Type != RPC_FT_END;f++)
	{
		if (RpcFieldIsReservedKey(f->Key))
		{
			Debug("RpcFieldOut: %s: %s is a reserved key\n", t->Name, f->Key);
			continue;
		}

		if (f->Hook != NULL && f->Hook->Out != NULL)
		{
			f->Hook->Out(f, p, base, index, total);
		}
		else
		{
			RpcFieldOutGeneric(f, p, base, index, total);
		}
	}
}

// Read the rows of a table
static void RpcFieldInRows(const RPC_TABLE *t, void *base, PACK *p, UINT index, UINT total)
{
	const RPC_FIELD *f;

	for (f = t->Fields;f->Type != RPC_FT_END;f++)
	{
		if (RpcFieldIsReservedKey(f->Key))
		{
			Debug("RpcFieldIn: %s: %s is a reserved key\n", t->Name, f->Key);
			continue;
		}

		if (f->Hook != NULL && f->Hook->In != NULL)
		{
			f->Hook->In(f, base, p, index, total);
		}
		else
		{
			RpcFieldInGeneric(f, base, p, index, total);
		}
	}
}

// Release what the rows of a table allocated
static void RpcFieldFreeRows(const RPC_TABLE *t, void *base)
{
	const RPC_FIELD *f;

	for (f = t->Fields;f->Type != RPC_FT_END;f++)
	{
		if (f->Hook != NULL && f->Hook->Free != NULL)
		{
			f->Hook->Free(f, base);
		}
		else if (f->Type == RPC_FT_ARRAY)
		{
			RpcFieldFreeArray(f, base);
		}
	}
}

// Write a structure to a Pack
void RpcFieldOut(const RPC_TABLE *t, PACK *p, void *s)
{
	// Validate arguments
	if (t == NULL || p == NULL || s == NULL)
	{
		return;
	}

	RpcFieldOutRows(t, p, s, 0, 0);
}

// Read a structure from a Pack (the structure is zeroed first)
void RpcFieldIn(const RPC_TABLE *t, void *s, PACK *p)
{
	// Validate arguments
	if (t == NULL || s == NULL || p == NULL)
	{
		return;
	}

	Zero(s, t->Size);
	RpcFieldInRows(t, s, p, 0, 0);
}

// Release what RpcFieldIn allocated
void RpcFieldFree(const RPC_TABLE *t, void *s)
{
	// Validate arguments
	if (t == NULL || s == NULL)
	{
		return;
	}

	RpcFieldFreeRows(t, s);
}

// Write a structure as item index of total (indexed Pack calls)
void RpcFieldOutItem(const RPC_TABLE *t, PACK *p, void *s, UINT index, UINT total)
{
	// Validate arguments
	if (t == NULL || p == NULL || s == NULL || total == 0)
	{
		return;
	}

	RpcFieldOutRows(t, p, s, index, total);
}

// Read a structure as item index (indexed Pack calls; the structure is
// zeroed first). The item count is not known here: hooks get INFINITE.
void RpcFieldInItem(const RPC_TABLE *t, void *s, PACK *p, UINT index)
{
	// Validate arguments
	if (t == NULL || s == NULL || p == NULL)
	{
		return;
	}

	Zero(s, t->Size);
	RpcFieldInRows(t, s, p, index, INFINITE);
}
