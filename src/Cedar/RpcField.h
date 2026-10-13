// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// RpcField.h
// Header of RpcField.c: field-descriptor tables for the admin RPC structures
//
// A table lists the members of one RPC structure in the order of the Pack
// calls that marshal them (the order of the old OutRpc* function). The
// engine walks the table to write a Pack (RpcFieldOut), to read one
// (RpcFieldIn) and to release what a read allocated (RpcFieldFree).
//
// Rows are written only through the RPC_ROW_* macros below: the offset and
// the size always come from the member, and a width check fails the
// compilation when a row type does not fit its member (bool, UINT, UINT64,
// IP, char or wchar_t).

#ifndef	RPCFIELD_H
#define	RPCFIELD_H

#include "Mayaqua/MayaType.h"

#include <stddef.h>

typedef struct RPC_FIELD RPC_FIELD;
typedef struct RPC_TABLE RPC_TABLE;
typedef struct RPC_HOOK RPC_HOOK;

// Row types: generic rows (the engine reads and writes them)
#define	RPC_FT_END			0		// End of a table
#define	RPC_FT_INT			1		// UINT
#define	RPC_FT_BOOL			2		// bool or UINT, written as 0 or 1
#define	RPC_FT_INT64		3		// UINT64
#define	RPC_FT_TIME64		4		// UINT64 time (kept apart from INT64)
#define	RPC_FT_STR			5		// char array
#define	RPC_FT_UNISTR		6		// wchar_t array
#define	RPC_FT_DATA			7		// Fixed-size data, read only when the size matches
#define	RPC_FT_IP32			8		// UINT IPv4 address
#define	RPC_FT_IP			9		// IP
#define	RPC_FT_COUNT		10		// UINT item count, written as "NumItem" at its position
#define	RPC_FT_ARRAY		11		// Counted array of fixed-size items

// Row types: hook-only rows (typed so that a later codec knows the member)
#define	RPC_FT_STRUCT		12		// Embedded structure
#define	RPC_FT_STRUCTPTR	13		// Pointer to a structure
#define	RPC_FT_X			14		// Certificate
#define	RPC_FT_BUF			15		// BUF
#define	RPC_FT_INTARRAY		16		// Fixed UINT array
#define	RPC_FT_OPAQUE		17		// Hand-written member group

// Row flags
#define	RPC_FF_READ_NUMITEM	0x00000001	// ARRAY: the count comes from "NumItem", not from the sentinel key
#define	RPC_FF_ALIAS		0x00000002	// Second key for the same member (metadata; a codec skips it)

// Hook procedures. base is the structure (the item for an item row);
// total == 0 marks a top-level row, otherwise the row is item index of total.
typedef void (RPC_FIELD_OUT_PROC)(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total);
typedef void (RPC_FIELD_IN_PROC)(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total);
typedef void (RPC_FIELD_FREE_PROC)(const RPC_FIELD *f, void *base);

// Hand-written part of a row. A NULL Out or In falls back to the generic
// action of the row type, so a hook can override one direction of a generic
// row; hook-only rows need both.
struct RPC_HOOK
{
	RPC_FIELD_OUT_PROC *Out;			// Write the member
	RPC_FIELD_IN_PROC *In;				// Read the member
	RPC_FIELD_FREE_PROC *Free;			// Release what In allocated, or NULL
};

// One row
struct RPC_FIELD
{
	UINT Type;							// RPC_FT_*
	char *Key;							// Pack element name, verbatim (ARRAY: the sentinel key)
	UINT Offset;						// offsetof the member
	UINT Size;							// sizeof the member
	UINT Flags;							// RPC_FF_*
	UINT CountOffset;					// ARRAY: offsetof the item count
	const RPC_TABLE *Item;				// ARRAY: table of one item
	const RPC_HOOK *Hook;				// Hand-written part, or NULL
};

// Table of one structure
struct RPC_TABLE
{
	char *Name;							// Structure name
	UINT Size;							// sizeof the structure
	const RPC_FIELD *Fields;			// Rows, ending with RPC_ROW_END
};

// Width check: 0 when cond holds, a compilation error otherwise
#define	RPC_FIELD_CHECK(cond)			(0 * sizeof(char[(cond) ? 1 : -1]))
#define	RPC_FIELD_SIZEOF(type, member)	sizeof(((type *)0)->member)
#define	RPC_FIELD_ELEMSIZE(type, member)	sizeof(((type *)0)->member[0])

// Width rule of a row type over a member of the given size (no rule for
// strings, data and hook-only types)
#define	RPC_FIELD_WIDTH_OK(ft, size)																\
	(((ft) == RPC_FT_INT || (ft) == RPC_FT_IP32 || (ft) == RPC_FT_COUNT) ? ((size) == sizeof(UINT)) :	\
	((ft) == RPC_FT_BOOL) ? ((size) == sizeof(bool) || (size) == sizeof(UINT)) :					\
	((ft) == RPC_FT_INT64 || (ft) == RPC_FT_TIME64) ? ((size) == sizeof(UINT64)) :					\
	((ft) == RPC_FT_IP) ? ((size) == sizeof(IP)) :													\
	((ft) == RPC_FT_STRUCTPTR || (ft) == RPC_FT_X || (ft) == RPC_FT_BUF) ? ((size) == sizeof(void *)) :	\
	((ft) == RPC_FT_INTARRAY) ? ((size) != 0 && ((size) % sizeof(UINT)) == 0) :					\
	1)

// Row over a member, with a width condition
#define	RPC_FIELD_ROW(ft, type, member, key, flags, hook, cond)							\
	{ (ft), (key), (UINT)offsetof(type, member),										\
	(UINT)(RPC_FIELD_SIZEOF(type, member) + RPC_FIELD_CHECK(cond)), (flags), 0, NULL, (hook) }

// Generic rows
#define	RPC_ROW_INT(type, member, key)																\
	RPC_FIELD_ROW(RPC_FT_INT, type, member, key, 0, NULL, RPC_FIELD_SIZEOF(type, member) == sizeof(UINT))
#define	RPC_ROW_BOOL(type, member, key)															\
	RPC_FIELD_ROW(RPC_FT_BOOL, type, member, key, 0, NULL,											\
	RPC_FIELD_SIZEOF(type, member) == sizeof(bool) || RPC_FIELD_SIZEOF(type, member) == sizeof(UINT))
#define	RPC_ROW_INT64(type, member, key)															\
	RPC_FIELD_ROW(RPC_FT_INT64, type, member, key, 0, NULL, RPC_FIELD_SIZEOF(type, member) == sizeof(UINT64))
#define	RPC_ROW_TIME64(type, member, key)															\
	RPC_FIELD_ROW(RPC_FT_TIME64, type, member, key, 0, NULL, RPC_FIELD_SIZEOF(type, member) == sizeof(UINT64))
#define	RPC_ROW_STR(type, member, key)																\
	RPC_FIELD_ROW(RPC_FT_STR, type, member, key, 0, NULL, RPC_FIELD_ELEMSIZE(type, member) == sizeof(char))
#define	RPC_ROW_UNISTR(type, member, key)															\
	RPC_FIELD_ROW(RPC_FT_UNISTR, type, member, key, 0, NULL, RPC_FIELD_ELEMSIZE(type, member) == sizeof(wchar_t))
#define	RPC_ROW_DATA(type, member, key)															\
	RPC_FIELD_ROW(RPC_FT_DATA, type, member, key, 0, NULL, RPC_FIELD_SIZEOF(type, member) != 0)
#define	RPC_ROW_IP32(type, member, key)															\
	RPC_FIELD_ROW(RPC_FT_IP32, type, member, key, 0, NULL, RPC_FIELD_SIZEOF(type, member) == sizeof(UINT))
#define	RPC_ROW_IP(type, member, key)																\
	RPC_FIELD_ROW(RPC_FT_IP, type, member, key, 0, NULL, RPC_FIELD_SIZEOF(type, member) == sizeof(IP))

// Item count, written as "NumItem" at this position (read by the ARRAY row)
#define	RPC_ROW_COUNT(type, member)																\
	RPC_FIELD_ROW(RPC_FT_COUNT, type, member, "NumItem", 0, NULL, RPC_FIELD_SIZEOF(type, member) == sizeof(UINT))

// Counted array: items is the pointer member, count the UINT member,
// item_table the table of one item and sentinel the key whose index count
// is the number of items on read (unless flags has RPC_FF_READ_NUMITEM)
#define	RPC_ROW_ARRAY(type, items, count, item_table, sentinel, flags)							\
	{ RPC_FT_ARRAY, (sentinel), (UINT)offsetof(type, items),									\
	(UINT)(RPC_FIELD_SIZEOF(type, items) + RPC_FIELD_CHECK(RPC_FIELD_SIZEOF(type, items) == sizeof(void *))	\
	+ RPC_FIELD_CHECK(RPC_FIELD_SIZEOF(type, count) == sizeof(UINT))),							\
	(flags), (UINT)offsetof(type, count), (item_table), NULL }

// Row of type ft whose hook does the Pack calls of one or both directions
#define	RPC_ROW_HOOK(ft, type, member, key, flags, hook)											\
	RPC_FIELD_ROW(ft, type, member, key, flags, hook, RPC_FIELD_WIDTH_OK(ft, RPC_FIELD_SIZEOF(type, member)))

// Hook row over the whole structure (an item that is itself a hand-written structure)
#define	RPC_ROW_WHOLE(type, key, flags, hook)														\
	{ RPC_FT_STRUCT, (key), 0, (UINT)sizeof(type), (flags), 0, NULL, (hook) }

// Hook row over a member group that only hand-written code reads and writes
#define	RPC_ROW_OPAQUE(type, member, key, flags, hook)											\
	RPC_FIELD_ROW(RPC_FT_OPAQUE, type, member, key, flags, hook, 1)

// End of a table
#define	RPC_ROW_END																					\
	{ RPC_FT_END, NULL, 0, 0, 0, 0, NULL, NULL }

// Table of a structure: var is the table name, fields its row array
#define	RPC_TABLE_DEF(var, type, fields)															\
	static const RPC_TABLE var = { #type, (UINT)sizeof(type), (fields) }

// Function prototype
void RpcFieldOut(const RPC_TABLE *t, PACK *p, void *s);
void RpcFieldIn(const RPC_TABLE *t, void *s, PACK *p);
void RpcFieldFree(const RPC_TABLE *t, void *s);
void RpcFieldOutItem(const RPC_TABLE *t, PACK *p, void *s, UINT index, UINT total);
void RpcFieldInItem(const RPC_TABLE *t, void *s, PACK *p, UINT index);

#endif	// RPCFIELD_H
