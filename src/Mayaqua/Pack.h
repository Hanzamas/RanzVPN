// Pack.h
// Header of Pack.c

#ifndef	PACK_H
#define	PACK_H

#include "MayaType.h"

#define	MAX_VALUE_SIZE			(384 * 1024 * 1024)	// Maximum Data size that can be stored in a single VALUE
#define	MAX_VALUE_NUM			262144	// Maximum VALUE number that can be stored in a single ELEMENT
#define	MAX_ELEMENT_NAME_LEN	63		// The length of the name that can be attached to the ELEMENT
#define	MAX_ELEMENT_NUM			262144	// Maximum ELEMENT number that can be stored in a single PACK
#define	MAX_PACK_SIZE			(512 * 1024 * 1024)	// Maximum size of a serialized PACK
#define	HTTP_PACK_RAND_SIZE_MAX			1000


#define	VALUE_INT			0
#define	VALUE_DATA			1
#define	VALUE_STR			2
#define	VALUE_UNISTR		3
#define	VALUE_INT64			4

#define	MAX_NOOP_PER_SESSION	30
#define NOOP 1
#define NOOP_IGNORE 2 // A noop, but don't send a response noop

struct VALUE
{
	UINT Size;
	UINT IntValue;
	void *Data;
	char *Str;
	wchar_t *UniStr;
	UINT64 Int64Value;
};

struct ELEMENT
{
	char name[MAX_ELEMENT_NAME_LEN + 1];
	UINT num_value;
	UINT type;
	VALUE **values;
};

struct PACK
{
	LIST *elements;
};

PACK *NewPack();
bool AddElement(PACK *p, ELEMENT *e);
ELEMENT *GetElement(PACK *p, char *name, UINT type);
void FreePack(PACK *p);
ELEMENT *NewElement(char *name, UINT type, UINT num_value, VALUE **values);
VALUE *NewIntValue(UINT i);
VALUE *NewDataValue(void *data, UINT size);
VALUE *NewStrValue(char *str);
VALUE *NewUniStrValue(wchar_t *str);
BUF *PackToBuf(PACK *p);
void WritePack(BUF *b, PACK *p);
void WriteElement(BUF *b, ELEMENT *e);
void WriteValue(BUF *b, VALUE *v, UINT type);
PACK *BufToPack(BUF *b);
bool ReadPack(BUF *b, PACK *p);
ELEMENT *ReadElement(BUF *b);
VALUE *ReadValue(BUF *b, UINT type);
VALUE *NewInt64Value(UINT64 i);

X *PackGetX(PACK *p, char *name);
LIST *PackGetXList(PACK *p, char *name);
K *PackGetK(PACK *p, char *name);
ELEMENT *PackAddX(PACK *p, char *name, X *x);
ELEMENT *PackAddXList(PACK *p, char *name, LIST *chain);
ELEMENT *PackAddK(PACK *p, char *name, K *k);
ELEMENT *PackAddStr(PACK *p, char *name, char *str);
ELEMENT *PackAddStrEx(PACK *p, char *name, char *str, UINT index, UINT total);
ELEMENT *PackAddUniStr(PACK *p, char *name, wchar_t *unistr);
ELEMENT *PackAddUniStrEx(PACK *p, char *name, wchar_t *unistr, UINT index, UINT total);
ELEMENT *PackAddInt(PACK *p, char *name, UINT i);
ELEMENT *PackAddIntEx(PACK *p, char *name, UINT i, UINT index, UINT total);
ELEMENT *PackAddInt64(PACK *p, char *name, UINT64 i);
ELEMENT *PackAddInt64Ex(PACK *p, char *name, UINT64 i, UINT index, UINT total);
ELEMENT *PackAddData(PACK *p, char *name, void *data, UINT size);
ELEMENT *PackAddDataEx(PACK *p, char *name, void *data, UINT size, UINT index, UINT total);
ELEMENT *PackAddBuf(PACK *p, char *name, BUF *b);
ELEMENT *PackAddBufEx(PACK *p, char *name, BUF *b, UINT index, UINT total);
bool PackGetStr(PACK *p, char *name, char *str, UINT size);
bool PackGetStrEx(PACK *p, char *name, char *str, UINT size, UINT index);
bool PackGetUniStr(PACK *p, char *name, wchar_t *unistr, UINT size);
bool PackGetUniStrEx(PACK *p, char *name, wchar_t *unistr, UINT size, UINT index);
UINT PackGetIndexCount(PACK *p, char *name);
UINT PackGetInt(PACK *p, char *name);
UINT PackGetIntEx(PACK *p, char *name, UINT index);
UINT64 PackGetInt64(PACK *p, char *name);
UINT64 PackGetInt64Ex(PACK *p, char *name, UINT index);
UINT PackGetDataSizeEx(PACK *p, char *name, UINT index);
UINT PackGetDataSize(PACK *p, char *name);
bool PackGetData(PACK *p, char *name, void *data);
bool PackGetDataEx(PACK *p, char *name, void *data, UINT index);
BUF *PackGetBuf(PACK *p, char *name);
BUF *PackGetBufEx(PACK *p, char *name, UINT index);
bool PackGetBool(PACK *p, char *name);
ELEMENT *PackAddBool(PACK *p, char *name, bool b);
ELEMENT *PackAddBoolEx(PACK *p, char *name, bool b, UINT index, UINT total);
bool PackGetBoolEx(PACK *p, char *name, UINT index);
void PackAddIp(PACK *p, char *name, IP *ip);
void PackAddIpEx(PACK *p, char *name, IP *ip, UINT index, UINT total);
bool PackGetIp(PACK *p, char *name, IP *ip);
bool PackGetIpEx(PACK *p, char *name, IP *ip, UINT index);
UINT PackGetIp32(PACK *p, char *name);
UINT PackGetIp32Ex(PACK *p, char *name, UINT index);
void PackAddIp32(PACK *p, char *name, UINT ip32);
void PackAddIp32Ex(PACK *p, char *name, UINT ip32, UINT index, UINT total);
ELEMENT *PackAddIp6AddrEx(PACK *p, char *name, IPV6_ADDR *addr, UINT index, UINT total);
bool PackGetIp6AddrEx(PACK *p, char *name, IPV6_ADDR *addr, UINT index);
bool PackGetData2(PACK *p, char *name, void *data, UINT size);
bool PackGetDataEx2(PACK *p, char *name, void *data, UINT size, UINT index);

#endif
