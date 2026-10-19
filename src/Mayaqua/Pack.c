// Pack.c
// Data package code

#include "Pack.h"

#include "Encrypt.h"
#include "Internat.h"
#include "Mayaqua.h"
#include "Memory.h"
#include "Network.h"
#include "Str.h"

// Smallest element on the wire: name length (the name may be empty), type, value count, one value
#define	PACK_ELEMENT_MIN_WIRE_SIZE		(4 + 4 + 4 + 4)

static void FreeValue(VALUE *v, UINT type);

// Smallest value of the type on the wire: the value, or the length before it; 0 for an unknown type
static UINT PackValueMinWireSize(UINT type)
{
	switch (type)
	{
	case VALUE_INT:
	case VALUE_DATA:
	case VALUE_STR:
	case VALUE_UNISTR:
		return 4;
	case VALUE_INT64:
		return 8;
	}

	return 0;
}

PACK *BufToPack(BUF *b)
{
	PACK *p;
	if (b == NULL)
	{
		return NULL;
	}

	p = NewPack();
	if (ReadPack(b, p) == false)
	{
		FreePack(p);
		return NULL;
	}

	return p;
}

BUF *PackToBuf(PACK *p)
{
	BUF *b;
	if (p == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	WritePack(b, p);

	return b;
}

bool ReadPack(BUF *b, PACK *p)
{
	UINT i, num;
	if (b == NULL || p == NULL)
	{
		return false;
	}

	num = ReadBufInt(b);
	// The peer claims the count: no more elements than the bytes present can hold
	if (num > MAX_ELEMENT_NUM || num > ReadBufRemainSize(b) / PACK_ELEMENT_MIN_WIRE_SIZE)
	{
		return false;
	}

	for (i = 0;i < num;i++)
	{
		ELEMENT *e;
		e = ReadElement(b);
		if (AddElement(p, e) == false)
		{
			return false;
		}
	}

	return true;
}

void WritePack(BUF *b, PACK *p)
{
	UINT i;
	if (b == NULL || p == NULL)
	{
		return;
	}

	WriteBufInt(b, LIST_NUM(p->elements));

	for (i = 0;i < LIST_NUM(p->elements);i++)
	{
		ELEMENT *e = LIST_DATA(p->elements, i);
		WriteElement(b, e);
	}
}

ELEMENT *ReadElement(BUF *b)
{
	UINT i, j;
	char name[MAX_ELEMENT_NAME_LEN + 1];
	UINT type, num_value, value_size;
	VALUE **values;
	ELEMENT *e;
	if (b == NULL)
	{
		return NULL;
	}

	if (ReadBufStr(b, name, sizeof(name)) == false)
	{
		return NULL;
	}

	// The type and the value count must be there: ReadBufInt() reads 0 past the end
	if (ReadBufRemainSize(b) < 8)
	{
		return NULL;
	}

	type = ReadBufInt(b);

	num_value = ReadBufInt(b);

	// A known type, and no more values than the bytes present can hold, before anything is allocated
	value_size = PackValueMinWireSize(type);
	if (value_size == 0 || num_value == 0 || num_value > MAX_VALUE_NUM || num_value > ReadBufRemainSize(b) / value_size)
	{
		return NULL;
	}

	values = (VALUE **)Malloc(sizeof(VALUE *) * num_value);
	for (i = 0;i < num_value;i++)
	{
		values[i] = ReadValue(b, type);
		if (values[i] == NULL)
		{
			// A value that cannot be read fails the element: no ELEMENT holds a NULL value
			for (j = 0;j < i;j++)
			{
				FreeValue(values[j], type);
			}
			Free(values);

			return NULL;
		}
	}

	e = NewElement(name, type, num_value, values);

	Free(values);

	return e;
}

void WriteElement(BUF *b, ELEMENT *e)
{
	UINT i;
	if (b == NULL || e == NULL)
	{
		return;
	}

	WriteBufStr(b, e->name);
	WriteBufInt(b, e->type);
	WriteBufInt(b, e->num_value);
	for (i = 0;i < e->num_value;i++)
	{
		VALUE *v = e->values[i];
		WriteValue(b, v, e->type);
	}
}

VALUE *ReadValue(BUF *b, UINT type)
{
	UINT len;
	BYTE *u;
	void *data;
	char *str;
	wchar_t *unistr;
	UINT unistr_size;
	UINT size;
	UINT u_size;
	UINT min_size;
	VALUE *v = NULL;
	if (b == NULL)
	{
		return NULL;
	}

	// The value, or the length before it, must be there: ReadBufInt() reads 0 past the end
	min_size = PackValueMinWireSize(type);
	if (min_size == 0 || ReadBufRemainSize(b) < min_size)
	{
		return NULL;
	}

	// A length is checked against the bytes present before the block is allocated
	switch (type)
	{
	case VALUE_INT:
		v = NewIntValue(ReadBufInt(b));
		break;
	case VALUE_INT64:
		v = NewInt64Value(ReadBufInt64(b));
		break;
	case VALUE_DATA:
		size = ReadBufInt(b);
		if (size > MAX_VALUE_SIZE || size > ReadBufRemainSize(b))
		{
			break;
		}
		data = Malloc(size);
		if (ReadBuf(b, data, size) != size)
		{
			Free(data);
			break;
		}
		v = NewDataValue(data, size);
		Free(data);
		break;
	case VALUE_STR:
		len = ReadBufInt(b);
		if (len > (MAX_VALUE_SIZE - 1) || len > ReadBufRemainSize(b))
		{
			break;
		}
		str = Malloc(len + 1);
		if (ReadBuf(b, str, len) != len)
		{
			Free(str);
			break;
		}
		str[len] = 0;
		v = NewStrValue(str);
		Free(str);
		break;
	case VALUE_UNISTR:
		u_size = ReadBufInt(b);
		if (u_size > MAX_VALUE_SIZE || u_size > ReadBufRemainSize(b))
		{
			break;
		}
		u = ZeroMalloc(u_size + 1);
		if (ReadBuf(b, u, u_size) != u_size)
		{
			Free(u);
			break;
		}
		unistr_size = CalcUtf8ToUni(u, u_size);
		if (unistr_size == 0)
		{
			Free(u);
			break;
		}
		unistr = Malloc(unistr_size);
		Utf8ToUni(unistr, unistr_size, u, u_size);
		Free(u);
		v = NewUniStrValue(unistr);
		Free(unistr);
		break;
	}

	return v;
}

void WriteValue(BUF *b, VALUE *v, UINT type)
{
	UINT len;
	BYTE *u;
	UINT u_size;
	if (b == NULL || v == NULL)
	{
		return;
	}

	switch (type)
	{
	case VALUE_INT:
		WriteBufInt(b, v->IntValue);
		break;
	case VALUE_INT64:
		WriteBufInt64(b, v->Int64Value);
		break;
	case VALUE_DATA:
		WriteBufInt(b, v->Size);
		WriteBuf(b, v->Data, v->Size);
		break;
	case VALUE_STR:
		len = StrLen(v->Str);
		WriteBufInt(b, len);
		WriteBuf(b, v->Str, len);
		break;
	case VALUE_UNISTR:
		u_size = CalcUniToUtf8(v->UniStr) + 1;
		u = ZeroMalloc(u_size);
		UniToUtf8(u, u_size, v->UniStr);
		WriteBufInt(b, u_size);
		WriteBuf(b, u, u_size);
		Free(u);
		break;
	}
}

// The value at the index of the element, or NULL when there is no element, the index is past its values, or the
// slot is still empty (an element added with PackAdd*Ex gets its values one index at a time)
static VALUE *GetElementValue(ELEMENT *e, UINT index)
{
	if (e == NULL || e->values == NULL || index >= e->num_value)
	{
		return NULL;
	}

	return e->values[index];
}

static int ComparePackName(void *p1, void *p2)
{
	ELEMENT *o1, *o2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	o1 = *(ELEMENT **)p1;
	o2 = *(ELEMENT **)p2;
	if (o1 == NULL || o2 == NULL)
	{
		return 0;
	}

	return StrCmpi(o1->name, o2->name);
}

static void FreeValue(VALUE *v, UINT type)
{
	if (v == NULL)
	{
		return;
	}

	switch (type)
	{
	case VALUE_INT:
	case VALUE_INT64:
		break;
	case VALUE_DATA:
		Free(v->Data);
		break;
	case VALUE_STR:
		Free(v->Str);
		break;
	case VALUE_UNISTR:
		Free(v->UniStr);
		break;
	}

	Free(v);
}

VALUE *NewUniStrValue(wchar_t *str)
{
	VALUE *v;
	if (str == NULL)
	{
		return NULL;
	}

	v = Malloc(sizeof(VALUE));

	v->Size = UniStrSize(str);
	v->UniStr = Malloc(v->Size);
	UniStrCpy(v->UniStr, v->Size, str);

	UniTrim(v->UniStr);

	return v;
}

VALUE *NewStrValue(char *str)
{
	VALUE *v;
	if (str == NULL)
	{
		return NULL;
	}

	v = Malloc(sizeof(VALUE));

	v->Size = StrLen(str) + 1;
	v->Str = Malloc(v->Size);
	StrCpy(v->Str, v->Size, str);

	Trim(v->Str);

	return v;
}

VALUE *NewDataValue(void *data, UINT size)
{
	VALUE *v;
	if (data == NULL)
	{
		return NULL;
	}

	v = Malloc(sizeof(VALUE));

	v->Size = size;
	v->Data = Malloc(v->Size);
	Copy(v->Data, data, size);

	return v;
}

VALUE *NewInt64Value(UINT64 i)
{
	VALUE *v;

	v = Malloc(sizeof(VALUE));
	v->Int64Value = i;
	v->Size = sizeof(UINT64);

	return v;
}

VALUE *NewIntValue(UINT i)
{
	VALUE *v;

	v = Malloc(sizeof(VALUE));
	v->IntValue = i;
	v->Size = sizeof(UINT);

	return v;
}

static void FreeElement(ELEMENT *e)
{
	UINT i;
	if (e == NULL)
	{
		return;
	}

	for (i = 0;i < e->num_value;i++)
	{
		FreeValue(e->values[i], e->type);
	}
	Free(e->values);

	Free(e);
}

ELEMENT *NewElement(char *name, UINT type, UINT num_value, VALUE **values)
{
	ELEMENT *e;
	UINT i;
	if (name == NULL || num_value == 0 || values == NULL)
	{
		return NULL;
	}

	e = ZeroMalloc(sizeof(ELEMENT));
	StrCpy(e->name, sizeof(e->name), name);
	e->num_value = num_value;
	e->type = type;

	e->values = (VALUE **)ZeroMalloc(sizeof(VALUE *) * num_value);
	for (i = 0;i < e->num_value;i++)
	{
		e->values[i] = values[i];
	}

	return e;
}

ELEMENT *GetElement(PACK *p, char *name, UINT type)
{
	ELEMENT t;
	ELEMENT *e;
	if (p == NULL || name == NULL)
	{
		return NULL;
	}

	StrCpy(t.name, sizeof(t.name), name);
	e = Search(p->elements, &t);

	if (e == NULL)
	{
		return NULL;
	}

	if (type != INFINITE)
	{
		if (e->type != type)
		{
			return NULL;
		}
	}

	return e;
}

bool AddElement(PACK *p, ELEMENT *e)
{
	if (p == NULL || e == NULL)
	{
		return false;
	}

	if (LIST_NUM(p->elements) >= MAX_ELEMENT_NUM)
	{
		FreeElement(e);
		return false;
	}

	// Without this, the lookup below qsorts the whole list on every new name (n adds = n sorts).
	// Only the element appended by the previous AddElement can be out of place, so move it into
	// its sorted slot instead. The list then holds the same order the qsort gave, so WritePack
	// still emits the elements in the same order (wire format).
	if (p->elements->sorted == false && LIST_NUM(p->elements) >= 1)
	{
		ELEMENT *last = LIST_DATA(p->elements, LIST_NUM(p->elements) - 1);

		p->elements->num_item--;
		p->elements->sorted = true;
		Insert(p->elements, last);
	}

	if (GetElement(p, e->name, INFINITE))
	{
		FreeElement(e);
		return false;
	}

	if (e->num_value == 0)
	{
		FreeElement(e);
		return false;
	}

	Add(p->elements, e);
	return true;
}

void FreePack(PACK *p)
{
	UINT i;
	ELEMENT **elements;
	if (p == NULL)
	{
		return;
	}

	elements = ToArray(p->elements);
	for (i = 0;i < LIST_NUM(p->elements);i++)
	{
		FreeElement(elements[i]);
	}
	Free(elements);

	ReleaseList(p->elements);
	Free(p);
}

PACK *NewPack()
{
	PACK *p;

	p = ZeroMallocEx(sizeof(PACK), true);

	p->elements = NewListFast(ComparePackName);

	return p;
}

K *PackGetK(PACK *p, char *name)
{
	K *k;
	BUF *b;
	if (p == NULL || name == NULL)
	{
		return NULL;
	}

	b = PackGetBuf(p, name);
	if (b == NULL)
	{
		return NULL;
	}

	k = BufToK(b, true, false, NULL);

	if (k == NULL)
	{
		k = BufToK(b, true, true, NULL);
	}

	FreeBuf(b);

	return k;
}

X *PackGetX(PACK *p, char *name)
{
	X *x;
	BUF *b;
	if (p == NULL || name == NULL)
	{
		return NULL;
	}

	b = PackGetBuf(p, name);
	if (b == NULL)
	{
		return NULL;
	}

	x = BufToX(b, false);

	if (x == NULL)
	{
		x = BufToX(b, true);
	}

	FreeBuf(b);

	return x;
}

LIST *PackGetXList(PACK *p, char *name)
{
	X *x;
	BUF *b;
	LIST *chain;
	UINT i;
	if (p == NULL || name == NULL)
	{
		return NULL;
	}

	ELEMENT *e = GetElement(p, name, VALUE_DATA);
	if (e == NULL)
	{
		return NULL;
	}

	chain = NewList(NULL);
	for (i = 0;i < e->num_value;i++)
	{
		b = PackGetBufEx(p, name, i);
		if (b == NULL)
		{
			FreeXList(chain);
			return NULL;
		}

		x = BufToX(b, false);

		if (x == NULL)
		{
			x = BufToX(b, true);
		}

		FreeBuf(b);

		Add(chain, x);
	}

	return chain;
}

ELEMENT *PackAddK(PACK *p, char *name, K *k)
{
	BUF *b;
	ELEMENT *e = NULL;
	if (p == NULL || name == NULL || k == NULL)
	{
		return NULL;
	}

	b = KToBuf(k, false, NULL);
	if (b == NULL)
	{
		return NULL;
	}

	e = PackAddBuf(p, name, b);
	FreeBuf(b);

	return e;
}

ELEMENT *PackAddX(PACK *p, char *name, X *x)
{
	BUF *b;
	ELEMENT *e = NULL;
	if (p == NULL || name == NULL || x == NULL)
	{
		return NULL;
	}

	b = XToBuf(x, false);
	if (b == NULL)
	{
		return NULL;
	}

	e = PackAddBuf(p, name, b);
	FreeBuf(b);

	return e;
}

ELEMENT *PackAddXList(PACK *p, char *name, LIST *chain)
{
	BUF *b;
	X *x;
	ELEMENT *e = NULL;
	if (p == NULL || name == NULL || chain == NULL)
	{
		return NULL;
	}

	UINT i;
	for (i = 0;i < LIST_NUM(chain);i++)
	{
		x = LIST_DATA(chain, i);
		b = XToBuf(x, false);

		if (b == NULL)
		{
			return NULL;
		}

		e = PackAddBufEx(p, name, b, i, LIST_NUM(chain));
		FreeBuf(b);
	}

	return e;
}

BUF *PackGetBuf(PACK *p, char *name)
{
	return PackGetBufEx(p, name, 0);
}
BUF *PackGetBufEx(PACK *p, char *name, UINT index)
{
	UINT size;
	void *tmp;
	BUF *b;
	if (p == NULL || name == NULL)
	{
		return NULL;
	}

	size = PackGetDataSizeEx(p, name, index);
	tmp = MallocEx(size, true);
	if (PackGetDataEx(p, name, tmp, index) == false)
	{
		Free(tmp);
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, tmp, size);
	SeekBuf(b, 0, 0);

	Free(tmp);

	return b;
}

bool PackGetData(PACK *p, char *name, void *data)
{
	return PackGetDataEx(p, name, data, 0);
}
bool PackGetDataEx(PACK *p, char *name, void *data, UINT index)
{
	ELEMENT *e;
	VALUE *v;
	if (p == NULL || name == NULL)
	{
		return false;
	}

	e = GetElement(p, name, VALUE_DATA);
	if (e == NULL)
	{
		return false;
	}
	v = GetElementValue(e, index);
	if (v != NULL)
	{
		Copy(data, v->Data, v->Size);
	}
	return true;
}
bool PackGetData2(PACK *p, char *name, void *data, UINT size)
{
	return PackGetDataEx2(p, name, data, size, 0);
}
bool PackGetDataEx2(PACK *p, char *name, void *data, UINT size, UINT index)
{
	ELEMENT *e;
	VALUE *v;
	if (p == NULL || name == NULL)
	{
		return false;
	}

	e = GetElement(p, name, VALUE_DATA);
	if (e == NULL)
	{
		return false;
	}
	v = GetElementValue(e, index);
	if ((v == NULL ? 0 : v->Size) != size)
	{
		return false;
	}
	if (v != NULL)
	{
		Copy(data, v->Data, v->Size);
	}
	return true;
}

UINT PackGetDataSize(PACK *p, char *name)
{
	return PackGetDataSizeEx(p, name, 0);
}
UINT PackGetDataSizeEx(PACK *p, char *name, UINT index)
{
	VALUE *v = GetElementValue(GetElement(p, name, VALUE_DATA), index);

	return v == NULL ? 0 : v->Size;
}

UINT64 PackGetInt64(PACK *p, char *name)
{
	return PackGetInt64Ex(p, name, 0);
}
UINT64 PackGetInt64Ex(PACK *p, char *name, UINT index)
{
	VALUE *v = GetElementValue(GetElement(p, name, VALUE_INT64), index);

	return v == NULL ? 0 : v->Int64Value;
}

UINT PackGetIndexCount(PACK *p, char *name)
{
	ELEMENT *e;
	if (p == NULL || name == NULL)
	{
		return 0;
	}

	e = GetElement(p, name, INFINITE);
	if (e == NULL)
	{
		return 0;
	}

	return e->num_value;
}

bool PackGetBool(PACK *p, char *name)
{
	return PackGetInt(p, name) == 0 ? false : true;
}
bool PackGetBoolEx(PACK *p, char *name, UINT index)
{
	return PackGetIntEx(p, name, index) == 0 ? false : true;
}

ELEMENT *PackAddBool(PACK *p, char *name, bool b)
{
	return PackAddInt(p, name, b ? 1 : 0);
}
ELEMENT *PackAddBoolEx(PACK *p, char *name, bool b, UINT index, UINT total)
{
	return PackAddIntEx(p, name, b ? 1 : 0, index, total);
}

ELEMENT *PackAddIp6AddrEx(PACK *p, char *name, IPV6_ADDR *addr, UINT index, UINT total)
{
	if (p == NULL || name == NULL || addr == NULL)
	{
		return NULL;
	}

	return PackAddDataEx(p, name, addr, sizeof(IPV6_ADDR), index, total);
}

bool PackGetIp6AddrEx(PACK *p, char *name, IPV6_ADDR *addr, UINT index)
{
	if (p == NULL || name == NULL || addr == NULL)
	{
		Zero(addr, sizeof(IPV6_ADDR));
		return false;
	}

	return PackGetDataEx2(p, name, addr, sizeof(IPV6_ADDR), index);
}

void PackAddIp32Ex(PACK *p, char *name, UINT ip32, UINT index, UINT total)
{
	IP ip;
	if (p == NULL || name == NULL)
	{
		return;
	}

	UINTToIP(&ip, ip32);

	PackAddIpEx(p, name, &ip, index, total);
}
void PackAddIp32(PACK *p, char *name, UINT ip32)
{
	PackAddIp32Ex(p, name, ip32, 0, 1);
}
void PackAddIpEx(PACK *p, char *name, IP *ip, UINT index, UINT total)
{
	UINT i;
	char tmp[MAX_PATH];
	if (p == NULL || name == NULL || ip == NULL)
	{
		return;
	}

	Format(tmp, sizeof(tmp), "%s@ipv6_bool", name);
	PackAddBoolEx(p, tmp, IsIP6(ip), index, total);

	Format(tmp, sizeof(tmp), "%s@ipv6_array", name);
	PackAddDataEx(p, tmp, ip->address, sizeof(ip->address), index, total);

	Format(tmp, sizeof(tmp), "%s@ipv6_scope_id", name);
	PackAddIntEx(p, tmp, ip->ipv6_scope_id, index, total);

	i = IPToUINT(ip);

	if (IsBigEndian())
	{
		i = Swap32(i);
	}

	PackAddIntEx(p, name, i, index, total);
}
void PackAddIp(PACK *p, char *name, IP *ip)
{
	PackAddIpEx(p, name, ip, 0, 1);
}

UINT PackGetIp32Ex(PACK *p, char *name, UINT index)
{
	IP ip;
	if (p == NULL || name == NULL)
	{
		return 0;
	}

	if (PackGetIpEx(p, name, &ip, index) == false)
	{
		return 0;
	}

	return IPToUINT(&ip);
}
UINT PackGetIp32(PACK *p, char *name)
{
	return PackGetIp32Ex(p, name, 0);
}
bool PackGetIpEx(PACK *p, char *name, IP *ip, UINT index)
{
	UINT i;
	char tmp[MAX_PATH];
	if (p == NULL || ip == NULL || name == NULL)
	{
		return false;
	}

	Format(tmp, sizeof(tmp), "%s@ipv6_bool", name);
	if (PackGetBoolEx(p, tmp, index))
	{
		UCHAR data[16];
		UINT scope_id;

		Zero(data, sizeof(data));

		Format(tmp, sizeof(tmp), "%s@ipv6_array", name);
		PackGetDataEx2(p, tmp, data, sizeof(data), index);

		Format(tmp, sizeof(tmp), "%s@ipv6_scope_id", name);
		scope_id = PackGetIntEx(p, tmp, index);

		SetIP6(ip, data);
		ip->ipv6_scope_id = scope_id;
	}
	else
	{
		if (GetElement(p, name, VALUE_INT) == NULL)
		{
			Zero(ip, sizeof(IP));
			return false;
		}

		i = PackGetIntEx(p, name, index);

		if (IsBigEndian())
		{
			i = Swap32(i);
		}

		UINTToIP(ip, i);
	}

	return true;
}
bool PackGetIp(PACK *p, char *name, IP *ip)
{
	return PackGetIpEx(p, name, ip, 0);
}

UINT PackGetInt(PACK *p, char *name)
{
	return PackGetIntEx(p, name, 0);
}
UINT PackGetIntEx(PACK *p, char *name, UINT index)
{
	VALUE *v = GetElementValue(GetElement(p, name, VALUE_INT), index);

	return v == NULL ? 0 : v->IntValue;
}

bool PackGetUniStr(PACK *p, char *name, wchar_t *unistr, UINT size)
{
	return PackGetUniStrEx(p, name, unistr, size, 0);
}
bool PackGetUniStrEx(PACK *p, char *name, wchar_t *unistr, UINT size, UINT index)
{
	ELEMENT *e;
	VALUE *v;
	if (p == NULL || name == NULL || unistr == NULL || size == 0)
	{
		return false;
	}

	unistr[0] = 0;

	e = GetElement(p, name, VALUE_UNISTR);
	if (e == NULL)
	{
		return false;
	}
	v = GetElementValue(e, index);
	UniStrCpy(unistr, size, v == NULL ? NULL : v->UniStr);
	return true;
}

bool PackGetStr(PACK *p, char *name, char *str, UINT size)
{
	return PackGetStrEx(p, name, str, size, 0);
}
bool PackGetStrEx(PACK *p, char *name, char *str, UINT size, UINT index)
{
	ELEMENT *e;
	VALUE *v;
	if (p == NULL || name == NULL || str == NULL || size == 0)
	{
		return false;
	}

	str[0] = 0;

	e = GetElement(p, name, VALUE_STR);
	if (e == NULL)
	{
		return false;
	}

	v = GetElementValue(e, index);
	StrCpy(str, size, v == NULL ? NULL : v->Str);
	return true;
}

// Add the value at the index of the element of the name and type, which holds total values when it is new.
// An element of that name and type with total values or more gets the value at the index, replacing the
// one there; a shorter one drops the value and is returned as is. A name used by another type, or a full
// PACK, rejects the value: NULL. The value is the PACK's or freed in every case.
static ELEMENT *PackAddValueEx(PACK *p, char *name, UINT type, VALUE *v, UINT index, UINT total)
{
	ELEMENT *e;
	if (p == NULL || name == NULL || v == NULL || total == 0)
	{
		FreeValue(v, type);
		return NULL;
	}

	e = GetElement(p, name, type);
	if (e != NULL)
	{
		if (e->num_value >= total)
		{
			FreeValue(e->values[index], type);
			e->values[index] = v;
		}
		else
		{
			FreeValue(v, type);
		}

		return e;
	}

	e = ZeroMallocEx(sizeof(ELEMENT), true);
	StrCpy(e->name, sizeof(e->name), name);
	e->num_value = total;
	e->type = type;
	e->values = ZeroMallocEx(sizeof(VALUE *) * total, true);
	e->values[index] = v;

	if (AddElement(p, e) == false)
	{
		return NULL;
	}

	return e;
}

// Add an element of the name holding the one value. A name already in the PACK, of any type, or a full
// PACK rejects the value: NULL. The value is the PACK's or freed in every case.
static ELEMENT *PackAddValue(PACK *p, char *name, UINT type, VALUE *v)
{
	ELEMENT *e;
	if (p == NULL || name == NULL || v == NULL)
	{
		FreeValue(v, type);
		return NULL;
	}

	e = NewElement(name, type, 1, &v);
	if (AddElement(p, e) == false)
	{
		return NULL;
	}

	return e;
}

ELEMENT *PackAddBufEx(PACK *p, char *name, BUF *b, UINT index, UINT total)
{
	if (p == NULL || name == NULL || b == NULL || total == 0)
	{
		return NULL;
	}

	return PackAddDataEx(p, name, b->Buf, b->Size, index, total);
}

ELEMENT *PackAddDataEx(PACK *p, char *name, void *data, UINT size, UINT index, UINT total)
{
	if (p == NULL || data == NULL || name == NULL || total == 0)
	{
		return NULL;
	}

	return PackAddValueEx(p, name, VALUE_DATA, NewDataValue(data, size), index, total);
}

ELEMENT *PackAddBuf(PACK *p, char *name, BUF *b)
{
	if (p == NULL || name == NULL || b == NULL)
	{
		return NULL;
	}

	return PackAddData(p, name, b->Buf, b->Size);
}

ELEMENT *PackAddData(PACK *p, char *name, void *data, UINT size)
{
	if (p == NULL || data == NULL || name == NULL)
	{
		return NULL;
	}

	return PackAddValue(p, name, VALUE_DATA, NewDataValue(data, size));
}

ELEMENT *PackAddInt64Ex(PACK *p, char *name, UINT64 i, UINT index, UINT total)
{
	if (p == NULL || name == NULL || total == 0)
	{
		return NULL;
	}

	return PackAddValueEx(p, name, VALUE_INT64, NewInt64Value(i), index, total);
}

ELEMENT *PackAddIntEx(PACK *p, char *name, UINT i, UINT index, UINT total)
{
	if (p == NULL || name == NULL || total == 0)
	{
		return NULL;
	}

	return PackAddValueEx(p, name, VALUE_INT, NewIntValue(i), index, total);
}

ELEMENT *PackAddInt64(PACK *p, char *name, UINT64 i)
{
	if (p == NULL || name == NULL)
	{
		return NULL;
	}

	return PackAddValue(p, name, VALUE_INT64, NewInt64Value(i));
}

ELEMENT *PackAddInt(PACK *p, char *name, UINT i)
{
	if (p == NULL || name == NULL)
	{
		return NULL;
	}

	return PackAddValue(p, name, VALUE_INT, NewIntValue(i));
}

ELEMENT *PackAddUniStrEx(PACK *p, char *name, wchar_t *unistr, UINT index, UINT total)
{
	if (p == NULL || name == NULL || unistr == NULL || total == 0)
	{
		return NULL;
	}

	return PackAddValueEx(p, name, VALUE_UNISTR, NewUniStrValue(unistr), index, total);
}

ELEMENT *PackAddUniStr(PACK *p, char *name, wchar_t *unistr)
{
	if (p == NULL || name == NULL || unistr == NULL)
	{
		return NULL;
	}

	return PackAddValue(p, name, VALUE_UNISTR, NewUniStrValue(unistr));
}

ELEMENT *PackAddStrEx(PACK *p, char *name, char *str, UINT index, UINT total)
{
	if (p == NULL || name == NULL || str == NULL || total == 0)
	{
		return NULL;
	}

	return PackAddValueEx(p, name, VALUE_STR, NewStrValue(str), index, total);
}

ELEMENT *PackAddStr(PACK *p, char *name, char *str)
{
	if (p == NULL || name == NULL || str == NULL)
	{
		return NULL;
	}

	return PackAddValue(p, name, VALUE_STR, NewStrValue(str));
}

