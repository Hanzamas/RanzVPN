// HubTable.c
// Virtual Hub tables: user list cache, IP access control list, CRL, access list, trusted certificates, MAC and IP tables

#include "Hub.h"

#include "Connection.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include <stdlib.h>
#include <string.h>
#include "HubInternal.h"

bool IsUserMatchInUserList(LIST *o, char *filename, UINT64 user_hash) {
	USERLIST *u;
	bool ret = false;
	if (o == NULL || filename == NULL || user_hash == 0)
		return false;

	LockList(o);
	{
		u = FindUserList(o, filename);
		if (u == NULL)
			u = LoadUserList(o, filename);

		if (u != NULL)
			ret = IsInt64InList(u->UserHashList, user_hash);
	}
	UnlockList(o);

	return ret;
}

USERLIST *LoadUserList(LIST *o, char *filename) {
	if (o == NULL || filename == NULL)
		return NULL;

	USERLIST *u = ZeroMalloc(sizeof(USERLIST));

	StrCpy(u->Filename, sizeof(u->Filename), filename);

	u->UserHashList = NewInt64List();

	BUF *b = ReadDumpWithMaxSize(filename, ACCESS_LIST_INCLUDE_FILE_MAX_SIZE);
	if (b != NULL) {
		while (true) {
			char *line = CfgReadNextLine(b);
			UINT64 ui;
			if (line == NULL)
				break;

			Trim(line);

			if (IsEmptyStr(line) == false) {
				if (StartWith(line, "#") == false &&
				    StartWith(line, "//") == false &&
				    StartWith(line, ";") == false) {
					ui = UsernameToInt64(line);

					AddInt64Distinct(u->UserHashList, ui);
				}
			}

			Free(line);
		}

		FreeBuf(b);
	}

	Add(o, u);

	return u;
}

void FreeUserListEntry(USERLIST *u) {
	if (u == NULL)
		return;

	ReleaseInt64List(u->UserHashList);

	Free(u);
}

USERLIST *FindUserList(LIST *o, char *filename) {
	USERLIST t;
	if (o == NULL || filename == NULL)
		return NULL;

	Zero(&t, sizeof(t));

	StrCpy(t.Filename, sizeof(t.Filename), filename);

	USERLIST *u = Search(o, &t);

	return u;
}

int CompareUserList(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL)
		return 0;
	USERLIST *u1 = *(USERLIST **)p1;
	USERLIST *u2 = *(USERLIST **)p2;
	if (u1 == NULL || u2 == NULL)
		return 0;

	return StrCmpi(u1->Filename, u2->Filename);
}

void DeleteAllUserListCache(LIST *o) {
	if (o == NULL)
		return;

	LockList(o);
	{
		for (UINT i = 0; i < LIST_NUM(o); i++) {
			USERLIST *u = LIST_DATA(o, i);

			FreeUserListEntry(u);
		}

		DeleteAll(o);
	}
	UnlockList(o);
}

void SetAcList(LIST *o, LIST *src) {
	if (o == NULL || src == NULL)
		return;

	DelAllAc(o);

	for (UINT i = 0; i < LIST_NUM(src); i++) {
		AC *ac = LIST_DATA(src, i);

		AddAc(o, ac);
	}
}

void DelAllAc(LIST *o) {
	if (o == NULL)
		return;

	for (UINT i = 0; i < LIST_NUM(o); i++) {
		AC *ac = LIST_DATA(o, i);

		Free(ac);
	}

	DeleteAll(o);
}

void FreeAcList(LIST *o) {
	if (o == NULL)
		return;

	DelAllAc(o);

	ReleaseList(o);
}

char *GenerateAcStr(AC *ac) {
	char tmp[MAX_SIZE];
	char ip[64], mask[64];

	if (ac == NULL)
		return NULL;

	IPToStr(ip, sizeof(ip), &ac->IpAddress);
	MaskToStr(mask, sizeof(mask), &ac->SubnetMask);

	if (ac->Masked == false)
		Format(tmp, sizeof(tmp), "%s", ip);
	else
		Format(tmp, sizeof(tmp), "%s/%s", ip, mask);

	return CopyStr(tmp);
}

bool IsIpDeniedByAcList(IP *ip, LIST *o) {
	if (ip == NULL || o == NULL)
		return false;

	for (UINT i = 0; i < LIST_NUM(o); i++) {
		AC *ac = LIST_DATA(o, i);

		if (IsIpMaskedByAc(ip, ac)) {
			if (ac->Deny == false)
				return false;
			else
				return true;
		}
	}

	return false;
}

bool IsIpMaskedByAc(IP *ip, AC *ac) {
	UINT uip, net, mask;
	if (ip == NULL || ac == NULL)
		return false;

	if (IsIP4(ip)) {
		uip = IPToUINT(ip);
		net = IPToUINT(&ac->IpAddress);
		mask = IPToUINT(&ac->SubnetMask);

		if (ac->Masked == false) {
			if (uip == net)
				return true;
		} else {
			if ((uip & mask) == (net & mask))
				return true;
		}

		return false;
	} else {
		if (ac->Masked == false) {
			if (CmpIpAddr(ip, &ac->IpAddress) == 0)
				return true;
		} else {
			IP and1, and2;

			IPAnd6(&and1, ip, &ac->SubnetMask);
			IPAnd6(&and2, &ac->IpAddress, &ac->SubnetMask);

			if (CmpIpAddr(&and1, &and2) == 0)
				return true;
		}

		return false;
	}
}

void AddAc(LIST *o, AC *ac) {
	if (o == NULL || ac == NULL)
		return;

	if (LIST_NUM(o) < MAX_HUB_ACS) {
		Insert(o, Clone(ac, sizeof(AC)));

		NormalizeAcList(o);
	}
}

void NormalizeAcList(LIST *o) {
	if (o == NULL)
		return;

	for (UINT i = 0; i < LIST_NUM(o); i++) {
		AC *ac = LIST_DATA(o, i);

		if (IsIP6(&ac->IpAddress))
			ac->IpAddress.ipv6_scope_id = 0;

		ac->Id = (i + 1);
	}
}

int CmpAc(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL)
		return 0;
	AC *a1 = *(AC **)p1;
	AC *a2 = *(AC **)p2;
	if (a1 == NULL || a2 == NULL)
		return 0;
	if (a1->Priority > a2->Priority)
		return 1;
	else if (a1->Priority < a2->Priority)
		return -1;
	else if (a1->Deny > a2->Deny)
		return 1;
	else if (a1->Deny < a2->Deny)
		return -1;
	else
		return 0;
}

CRL *CopyCrl(CRL *crl) {
	if (crl == NULL)
		return NULL;

	CRL *ret = ZeroMalloc(sizeof(CRL));

	if (crl->Serial != NULL)
		ret->Serial = NewXSerial(crl->Serial->data, crl->Serial->size);

	ret->Name = CopyName(crl->Name);

	Copy(ret->DigestMD5, crl->DigestMD5, MD5_SIZE);
	Copy(ret->DigestSHA1, crl->DigestSHA1, SHA1_SIZE);

	return ret;
}

void FreeCrl(CRL *crl) {
	if (crl == NULL)
		return;

	if (crl->Serial != NULL)
		FreeXSerial(crl->Serial);

	if (crl->Name != NULL)
		FreeName(crl->Name);

	Free(crl);
}

bool IsValidCertInHub(HUB *h, X *x) {
	bool ret;
	if (h == NULL || x == NULL)
		return false;

	LockList(h->HubDb->CrlList);
	{
		ret = IsCertMatchCrlList(x, h->HubDb->CrlList);
	}
	UnlockList(h->HubDb->CrlList);

	if (ret)
		return false;

	return true;
}

bool IsCertMatchCrlList(X *x, LIST *o) {
	if (x == NULL || o == NULL)
		return false;

	for (UINT i = 0; i < LIST_NUM(o); i++) {
		CRL *crl = LIST_DATA(o, i);

		if (IsCertMatchCrl(x, crl))
			return true;
	}

	return false;
}

wchar_t *GenerateCrlStr(CRL *crl) {
	wchar_t tmp[2048];
	if (crl == NULL)
		return NULL;

	UniStrCpy(tmp, sizeof(tmp), L"");

	if (crl->Name != NULL) {
		wchar_t name[MAX_SIZE];

		UniStrCat(tmp, sizeof(tmp), L"Subject=\"");

		GetAllNameFromName(name, sizeof(name), crl->Name);
		UniStrCat(tmp, sizeof(tmp), name);
		UniStrCat(tmp, sizeof(tmp), L"\", ");
	}

	if (crl->Serial != NULL) {
		char str[128];
		wchar_t uni[128];

		BinToStrEx(str, sizeof(str), crl->Serial->data, crl->Serial->size);
		StrToUni(uni, sizeof(uni), str);
		UniStrCat(tmp, sizeof(tmp), L"Serial=\"");
		UniStrCat(tmp, sizeof(tmp), uni);
		UniStrCat(tmp, sizeof(tmp), L"\", ");
	}

	if (IsZero(crl->DigestMD5, MD5_SIZE) == false) {
		char str[128];
		wchar_t uni[128];

		BinToStrEx(str, sizeof(str), crl->DigestMD5, MD5_SIZE);
		StrToUni(uni, sizeof(uni), str);
		UniStrCat(tmp, sizeof(tmp), L"MD5=\"");
		UniStrCat(tmp, sizeof(tmp), uni);
		UniStrCat(tmp, sizeof(tmp), L"\", ");
	}

	if (IsZero(crl->DigestSHA1, SHA1_SIZE) == false) {
		char str[128];
		wchar_t uni[128];

		BinToStrEx(str, sizeof(str), crl->DigestSHA1, SHA1_SIZE);
		StrToUni(uni, sizeof(uni), str);
		UniStrCat(tmp, sizeof(tmp), L"SHA1=\"");
		UniStrCat(tmp, sizeof(tmp), uni);
		UniStrCat(tmp, sizeof(tmp), L"\", ");
	}

	if (UniEndWith(tmp, L", "))
		tmp[UniStrLen(tmp) - 2] = 0;

	return CopyUniStr(tmp);
}

bool IsCertMatchCrl(X *x, CRL *crl) {
	bool b = true;
	if (x == NULL || crl == NULL)
		return false;

	if (crl->Serial != NULL) {
		if (x->serial == NULL || CompareXSerial(x->serial, crl->Serial) == false)
			b = false;
	}

	if (IsZero(crl->DigestMD5, sizeof(crl->DigestMD5)) == false) {
		UCHAR test[MD5_SIZE];
		GetXDigest(x, test, false);

		if (Cmp(test, crl->DigestMD5, MD5_SIZE) != 0)
			b = false;
	}

	if (IsZero(crl->DigestSHA1, sizeof(crl->DigestSHA1)) == false) {
		UCHAR test[SHA1_SIZE];
		GetXDigest(x, test, true);

		if (Cmp(test, crl->DigestSHA1, SHA1_SIZE) != 0)
			b = false;
	}

	if (crl->Name != NULL) {
		NAME *xn = x->subject_name;
		NAME *cn = crl->Name;

		if (cn->CommonName != NULL && (UniIsEmptyStr(cn->CommonName) == false)) {
			if (xn->CommonName == NULL || UniSoftStrCmp(xn->CommonName, cn->CommonName) != 0)
				b = false;
		}

		if (cn->Organization != NULL && (UniIsEmptyStr(cn->Organization) == false)) {
			if (xn->Organization == NULL || UniSoftStrCmp(xn->Organization, cn->Organization) != 0)
				b = false;
		}

		if (cn->Unit != NULL && (UniIsEmptyStr(cn->Unit) == false)) {
			if (xn->Unit == NULL || UniSoftStrCmp(xn->Unit, cn->Unit) != 0)
				b = false;
		}

		if (cn->Country != NULL && (UniIsEmptyStr(cn->Country) == false)) {
			if (xn->Country == NULL || UniSoftStrCmp(xn->Country, cn->Country) != 0)
				b = false;
		}

		if (cn->State != NULL && (UniIsEmptyStr(cn->State) == false)) {
			if (xn->State == NULL || UniSoftStrCmp(xn->State, cn->State) != 0)
				b = false;
		}

		if (cn->Local != NULL && (UniIsEmptyStr(cn->Local) == false)) {
			if (xn->Local == NULL || UniSoftStrCmp(xn->Local, cn->Local) != 0)
				b = false;
		}
	}

	return b;
}

void GetAccessListStr(char *str, UINT size, ACCESS *a) {
	char tmp[MAX_SIZE];
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	bool l3 = false;
	bool asterisk = false;
	if (str == NULL || a == NULL)
		return;

	StrCpy(str, size, "");

	if (a->IsIPv6 == false) {
		if (a->SrcIpAddress != 0 || a->SrcSubnetMask != 0) {
			IPToStr32(tmp1, sizeof(tmp1), a->SrcIpAddress);
			MaskToStr32(tmp2, sizeof(tmp2), a->SrcSubnetMask);
			Format(tmp, sizeof(tmp), "SrcIPv4=%s/%s, ", tmp1, tmp2);
			StrCat(str, size, tmp);

			l3 = true;
		}

		if (a->DestIpAddress != 0 || a->DestSubnetMask != 0) {
			IPToStr32(tmp1, sizeof(tmp1), a->DestIpAddress);
			MaskToStr32(tmp2, sizeof(tmp2), a->DestSubnetMask);
			Format(tmp, sizeof(tmp), "DstIPv4=%s/%s, ", tmp1, tmp2);
			StrCat(str, size, tmp);

			l3 = true;
		}
	} else {
		if (IsZeroIP6Addr(&a->SrcIpAddress6) == false || IsZeroIP6Addr(&a->SrcSubnetMask6) == false) {
			IP6AddrToStr(tmp1, sizeof(tmp1), &a->SrcIpAddress6);
			Mask6AddrToStr(tmp2, sizeof(tmp2), &a->SrcSubnetMask6);
			Format(tmp, sizeof(tmp), "SrcIPv6=%s/%s, ", tmp1, tmp2);
			StrCat(str, size, tmp);

			l3 = true;
		}

		if (IsZeroIP6Addr(&a->DestIpAddress6) == false || IsZeroIP6Addr(&a->DestSubnetMask6) == false) {
			IP6AddrToStr(tmp1, sizeof(tmp1), &a->DestIpAddress6);
			Mask6AddrToStr(tmp2, sizeof(tmp2), &a->DestSubnetMask6);
			Format(tmp, sizeof(tmp), "DstIPv6=%s/%s, ", tmp1, tmp2);
			StrCat(str, size, tmp);

			l3 = true;
		}
	}

	if (a->Protocol != 0) {
		StrCpy(tmp1, sizeof(tmp1), "");
		switch (a->Protocol) {
		case 1:
			StrCpy(tmp1, sizeof(tmp1), "ICMPv4");
			break;
		case 3:
			StrCpy(tmp1, sizeof(tmp1), "GGP");
			break;
		case 6:
			StrCpy(tmp1, sizeof(tmp1), "TCP");
			break;
		case 8:
			StrCpy(tmp1, sizeof(tmp1), "EGP");
			break;
		case 12:
			StrCpy(tmp1, sizeof(tmp1), "PUP");
			break;
		case 17:
			StrCpy(tmp1, sizeof(tmp1), "UDP");
			break;
		case 20:
			StrCpy(tmp1, sizeof(tmp1), "HMP");
			break;
		case 22:
			StrCpy(tmp1, sizeof(tmp1), "XNS-IDP");
			break;
		case 27:
			StrCpy(tmp1, sizeof(tmp1), "RDP");
			break;
		case 58:
			StrCpy(tmp1, sizeof(tmp1), "ICMPv6");
			break;
		case 66:
			StrCpy(tmp1, sizeof(tmp1), "RVD");
			break;
		}

		if (IsEmptyStr(tmp1))
			Format(tmp, sizeof(tmp), "Protocol=%s(%u), ", tmp1, a->Protocol);
		else
			Format(tmp, sizeof(tmp), "Protocol=%s, ", tmp1);

		StrCat(str, size, tmp);

		l3 = true;
	}

	if (a->SrcPortStart != 0) {
		if (a->SrcPortEnd == a->SrcPortStart) {
			Format(tmp, sizeof(tmp), "SrcPort=%u, ", a->SrcPortStart);
			StrCat(str, size, tmp);
		} else {
			Format(tmp, sizeof(tmp), "SrcPort=%u-%u, ", a->SrcPortStart, a->SrcPortEnd);
			StrCat(str, size, tmp);
		}

		l3 = true;
	}

	if (a->DestPortStart != 0) {
		if (a->DestPortEnd == a->DestPortStart) {
			Format(tmp, sizeof(tmp), "DstPort=%u, ", a->DestPortStart);
			StrCat(str, size, tmp);
		} else {
			Format(tmp, sizeof(tmp), "DstPort=%u-%u, ", a->DestPortStart, a->DestPortEnd);
			StrCat(str, size, tmp);
		}

		l3 = true;
	}

	if (StrLen(a->SrcUsername) != 0) {
		Format(tmp, sizeof(tmp), "SrcUser=%s, ", a->SrcUsername);
		StrCat(str, size, tmp);
	}

	if (StrLen(a->DestUsername) != 0) {
		Format(tmp, sizeof(tmp), "DstUser=%s, ", a->DestUsername);
		StrCat(str, size, tmp);
	}

	if (a->CheckSrcMac != false) {
		char mac[MAX_SIZE], mask[MAX_SIZE];
		MacToStr(mac, sizeof(mac), a->SrcMacAddress);
		MacToStr(mask, sizeof(mask), a->SrcMacMask);
		Format(tmp, sizeof(tmp), "SrcMac=%s/%s, ", mac, mask);
		StrCat(str, size, tmp);
	}
	if (a->CheckDstMac != false) {
		char mac[MAX_SIZE], mask[MAX_SIZE];
		MacToStr(mac, sizeof(mac), a->DstMacAddress);
		MacToStr(mask, sizeof(mask), a->DstMacMask);
		Format(tmp, sizeof(tmp), "DstMac=%s/%s, ", mac, mask);
		StrCat(str, size, tmp);
	}

	if (a->CheckTcpState) {
		if (a->Established)
			StrCat(str, size, "Established, ");
		else
			StrCat(str, size, "Unestablished, ");

		l3 = true;
	}

	if (a->Discard == false) {
		if (a->Delay >= 1) {
			Format(tmp, sizeof(tmp), "Delay=%u, ", a->Delay);
			StrCat(str, size, tmp);
		}

		if (a->Jitter >= 1) {
			Format(tmp, sizeof(tmp), "Jitter=%u, ", a->Jitter);
			StrCat(str, size, tmp);
		}

		if (a->Loss >= 1) {
			Format(tmp, sizeof(tmp), "Loss=%u, ", a->Loss);
			StrCat(str, size, tmp);
		}
	}

	if (IsEmptyStr(a->RedirectUrl) == false) {
		Format(tmp, sizeof(tmp), "RedirectUrl=%s, ", a->RedirectUrl);
		StrCat(str, size, tmp);
	}

	if (StrLen(str) == 0)
		asterisk = true;

	if (l3)
		if (a->IsIPv6)
			StrCatLeft(str, size, "(ipv6) ");
		else
			StrCatLeft(str, size, "(ipv4) ");
	else
		StrCatLeft(str, size, "(ether) ");

	if (EndWith(str, ", "))
		str[StrLen(str) - 2] = 0;

	if (asterisk)
		StrCat(str, size, "*");
}

void AddAccessListEx(HUB *hub, ACCESS *a, bool no_sort, bool no_reassign_id) {
	if (hub == NULL || a == NULL)
		return;

	LockList(hub->AccessList);
	{
		if (LIST_NUM(hub->AccessList) >= MAX_ACCESSLISTS) {
			UnlockList(hub->AccessList);
			return;
		}

		ACCESS *access = Malloc(sizeof(ACCESS));
		Copy(access, a, sizeof(ACCESS));

		access->IsSrcUsernameIncludeOrExclude = false;
		access->IsDestUsernameIncludeOrExclude = false;

		if (IsEmptyStr(access->SrcUsername) == false) {
			if (StartWith(access->SrcUsername, ACCESS_LIST_INCLUDED_PREFIX) == false && StartWith(access->SrcUsername, ACCESS_LIST_EXCLUDED_PREFIX) == false)
				MakeSimpleUsernameRemoveNtDomain(access->SrcUsername, sizeof(access->SrcUsername), access->SrcUsername);
			else
				access->IsSrcUsernameIncludeOrExclude = true;
		}
		if (IsEmptyStr(access->DestUsername) == false) {
			if (StartWith(access->DestUsername, ACCESS_LIST_INCLUDED_PREFIX) == false && StartWith(access->DestUsername, ACCESS_LIST_EXCLUDED_PREFIX) == false)
				MakeSimpleUsernameRemoveNtDomain(access->DestUsername, sizeof(access->DestUsername), access->DestUsername);
			else
				access->IsDestUsernameIncludeOrExclude = true;
		}

		access->SrcUsernameHash = UsernameToInt64(access->SrcUsername);
		access->DestUsernameHash = UsernameToInt64(access->DestUsername);

		if (access->SrcPortStart != 0)
			access->SrcPortEnd = MAX(access->SrcPortEnd, access->SrcPortStart);
		if (access->DestPortStart != 0)
			access->DestPortEnd = MAX(access->DestPortEnd, access->DestPortStart);

		access->Delay = MAKESURE(access->Delay, 0, HUB_ACCESSLIST_DELAY_MAX);
		access->Jitter = MAKESURE(access->Jitter, 0, HUB_ACCESSLIST_JITTER_MAX);
		access->Loss = MAKESURE(access->Loss, 0, HUB_ACCESSLIST_LOSS_MAX);

		if (no_sort == false)
			Insert(hub->AccessList, access);
		else
			Add(hub->AccessList, access);

		if (no_reassign_id == false) {
			for (UINT i = 0; i < LIST_NUM(hub->AccessList); i++) {
				ACCESS *a = LIST_DATA(hub->AccessList, i);
				a->Id = (i + 1);
			}
		}
	}
	UnlockList(hub->AccessList);
}

int CmpAccessList(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL)
		return 0;
	ACCESS *a1 = *(ACCESS **)p1;
	ACCESS *a2 = *(ACCESS **)p2;
	if (a1 == NULL || a2 == NULL)
		return 0;
	if (a1->Priority > a2->Priority) {
		return 1;
	} else if (a1->Priority < a2->Priority) {
		return -1;
	} else if (a1->Discard > a2->Discard) {
		return 1;
	} else if (a1->Discard < a2->Discard) {
		return -1;
	} else {
		UINT64 size64 = ((UINT64)(&a1->UniqueId) - (UINT64)(&a1->Active));
		UINT size32 = (UINT)size64;

		return Cmp(&a1->Active, &a2->Active, size32);
	}
}

// The MAC table and the IP table of a hub. One lock guards both: the lock of MacHashTable. The functions below
// that take no lock themselves expect the caller to hold it (HubLockTables).
void HubLockTables(HUB *h) {
	LockHashList(h->MacHashTable);
}

void HubUnlockTables(HUB *h) {
	UnlockHashList(h->MacHashTable);
}

// Entry counts for status RPCs. Without the table lock the count may be stale, as it always was.
UINT HubMacTableNum(HUB *h) {
	return HASH_LIST_NUM(h->MacHashTable);
}

UINT HubIpTableNum(HUB *h) {
	return LIST_NUM(h->IpTable);
}

MAC_TABLE_ENTRY *MacTableLookup(HUB *h, UCHAR *mac, UINT vlan_id) {
	MAC_TABLE_ENTRY t;

	Copy(t.MacAddress, mac, 6);
	t.VlanId = vlan_id;

	return SearchHash(h->MacHashTable, &t);
}

// Learn mac on vlan_id for session s, which has no entry for it yet. NULL when the table is full (MAX_MAC_TABLES)
MAC_TABLE_ENTRY *MacTableLearn(HUB *h, SESSION *s, UCHAR *mac, UINT vlan_id, UINT64 now) {
	if (HASH_LIST_NUM(h->MacHashTable) >= MAX_MAC_TABLES)
		return NULL;

	MAC_TABLE_ENTRY *e = ZeroMalloc(sizeof(MAC_TABLE_ENTRY));
	e->HubPa = (HUB_PA *)s->PacketAdapter->Param;
	Copy(e->MacAddress, mac, 6);
	e->VlanId = vlan_id;
	e->Session = s;
	e->UpdatedTime = e->CreatedTime = now;

	AddHash(h->MacHashTable, e);

	return e;
}

static bool MacTableTakeSessionEntry(void *p, void *param) {
	MAC_TABLE_ENTRY *e = (MAC_TABLE_ENTRY *)p;

	if (e->Session != (SESSION *)param)
		return false;

	Free(e);

	return true;
}

// Drop every MAC table entry of session s, in one walk over the hash buckets
void MacTableFlushSession(HUB *h, SESSION *s) {
	DeleteHashIf(h->MacHashTable, MacTableTakeSessionEntry, s);
}

// All MAC table entries; Free() the array. The entries stay valid while the caller holds the table lock
MAC_TABLE_ENTRY **MacTableEnum(HUB *h, UINT *num) {
	return (MAC_TABLE_ENTRY **)HashListToArray(h->MacHashTable, num);
}

// Drop the MAC table entry of an admin RPC key (POINTER_TO_KEY). Takes the table lock. False when no entry has it
bool MacTableDeleteByKey(HUB *h, UINT key) {
	bool ret = false;

	HubLockTables(h);
	{
		if (IsInHashListKey(h->MacHashTable, key)) {
			MAC_TABLE_ENTRY *e = HashListKeyToPointer(h->MacHashTable, key);
			DeleteHash(h->MacHashTable, e);
			Free(e);
			ret = true;
		}
	}
	HubUnlockTables(h);

	return ret;
}

IP_TABLE_ENTRY *IpTableLookup(HUB *h, IP *ip) {
	IP_TABLE_ENTRY t;

	Copy(&t.Ip, ip, sizeof(IP));

	return Search(h->IpTable, &t);
}

// Entry index of the IP table, sorted by address (0 to HubIpTableNum - 1)
IP_TABLE_ENTRY *IpTableGet(HUB *h, UINT index) {
	return LIST_DATA(h->IpTable, index);
}

// IPv6 (v6) or IPv4 addresses that session s holds in the IP table
UINT CountSessionIps(HUB *h, SESSION *s, bool v6) {
	UINT num = 0;

	for (UINT i = 0; i < LIST_NUM(h->IpTable); i++) {
		IP_TABLE_ENTRY *e = LIST_DATA(h->IpTable, i);

		if (e->Session == s && (v6 ? IsIP6(&e->Ip) : IsIP4(&e->Ip)))
			num++;
	}

	return num;
}

// Session s sent from ip while the IP table gives ip to the other session of entry e
void LogIpConflict(HUB *h, SESSION *s, IP *ip, IP_TABLE_ENTRY *e, UINT64 now) {
	char ip_address[32];
	char mac_str[48];

	IPToStr(ip_address, sizeof(ip_address), ip);
	MacToStr(mac_str, sizeof(mac_str), e->MacAddress);

	HLog(h, "LH_IP_CONFLICT", s->Name, ip_address, e->Session->Name, mac_str,
	     e->CreatedTime, e->UpdatedTime, e->DhcpAllocated, now);
}

// Drop every IP table entry of session s in one pass that keeps the order of the others
void IpTableFlushSession(HUB *h, SESSION *s) {
	LIST *o = h->IpTable;
	UINT num_kept = 0;

	for (UINT i = 0; i < LIST_NUM(o); i++) {
		IP_TABLE_ENTRY *e = LIST_DATA(o, i);

		if (e->Session == s)
			Free(e);
		else
			o->p[num_kept++] = e;
	}

	o->num_item = num_kept;
}

// Drop the IP table entry of an admin RPC key (POINTER_TO_KEY). Takes the table lock. False when no entry has it
bool IpTableDeleteByKey(HUB *h, UINT key) {
	bool ret = false;

	HubLockTables(h);
	{
		IP_TABLE_ENTRY *e = ListKeyToPointer(h->IpTable, key);

		if (e != NULL) {
			Delete(h->IpTable, e);
			Free(e);
			ret = true;
		}
	}
	HubUnlockTables(h);

	return ret;
}

void DeleteExpiredMacTableEntry(HASH_LIST *h) {
	UINT num;
	if (h == NULL)
		return;

	LIST *o2 = NewListFast(NULL);

	MAC_TABLE_ENTRY **pp = (MAC_TABLE_ENTRY **)HashListToArray(h, &num);

	for (UINT i = 0; i < num; i++) {
		MAC_TABLE_ENTRY *e = pp[i];
		if ((e->UpdatedTime + (UINT64)MAC_TABLE_EXPIRE_TIME) <= Tick64())
			Add(o2, e);
	}

	for (UINT i = 0; i < LIST_NUM(o2); i++) {
		MAC_TABLE_ENTRY *e = LIST_DATA(o2, i);
		DeleteHash(h, e);
		Free(e);
	}

	ReleaseList(o2);

	Free(pp);
}

// The expiry state of an IP table without entries
void IpTableExpiryInit(IP_TABLE_EXPIRY *x) {
	if (x == NULL)
		return;

	x->Oldest = x->OldestDhcp = IP_TABLE_NO_ENTRY;
	x->Expired = NULL;
}

// Entry e of the table got a new UpdatedTime or became DhcpAllocated: lower the bound of its kind to its time. A
// frame reads the clock before it takes the table lock, so the time it gives an entry can be older than the bound
void IpTableExpiryNote(IP_TABLE_EXPIRY *x, IP_TABLE_ENTRY *e) {
	UINT64 *oldest = (e->DhcpAllocated ? &x->OldestDhcp : &x->Oldest);

	if (e->UpdatedTime < *oldest)
		*oldest = e->UpdatedTime;
}

// Whether an entry of the table can have expired by now. False means that an expiry pass would delete nothing:
// every entry of a kind was updated at the bound of its kind or later, and the bound plus the expiry time of the
// kind is still ahead
bool IpTableExpiryDue(IP_TABLE_EXPIRY *x, UINT64 now) {
	if (x->Oldest != IP_TABLE_NO_ENTRY && (x->Oldest + (UINT64)IP_TABLE_EXPIRE_TIME) <= now)
		return true;

	if (x->OldestDhcp != IP_TABLE_NO_ENTRY && (x->OldestDhcp + (UINT64)IP_TABLE_EXPIRE_TIME_DHCP) <= now)
		return true;

	return false;
}

void DeleteExpiredIpTableEntry(LIST *o, IP_TABLE_EXPIRY *x, UINT64 now) {
	UINT num_kept = 0;
	if (o == NULL || x == NULL)
		return;

	// This runs under the hub-wide MacHashTable lock, so it only moves pointers. It compacts the array in one pass:
	// a Delete per expired entry searched and shifted the whole array each time, O(n * expired). The kept entries
	// keep their order, so a sorted table stays sorted and DeleteHighestIpTableEntry still evicts the same entry.
	// The expired entries go on x->Expired, which the caller frees after the lock (FreeIpTableEntries): a Free per
	// entry under the lock made a mass expiry hold up every session of the hub. The pass also takes the bounds of x
	// from the kept entries, so that IpTableExpiryDue holds the next pass back until an entry can have expired.
	// The expiry times are read once; an entry expires as before when its UpdatedTime plus the time of its kind
	// has come.
	UINT64 expire_time = (UINT64)IP_TABLE_EXPIRE_TIME;
	UINT64 expire_time_dhcp = (UINT64)IP_TABLE_EXPIRE_TIME_DHCP;

	x->Oldest = x->OldestDhcp = IP_TABLE_NO_ENTRY;

	for (UINT i = 0; i < LIST_NUM(o); i++) {
		IP_TABLE_ENTRY *e = LIST_DATA(o, i);
		if ((e->UpdatedTime + (e->DhcpAllocated ? expire_time_dhcp : expire_time)) <= now) {
			e->NextExpired = x->Expired;
			x->Expired = e;
		} else {
			IpTableExpiryNote(x, e);
			o->p[num_kept++] = e;
		}
	}

	o->num_item = num_kept;
}

// Free a chain of IP table entries that an expiry pass took out of the table (IP_TABLE_EXPIRY.Expired). Needs no
// lock: no table holds them any more
void FreeIpTableEntries(IP_TABLE_ENTRY *e) {
	while (e != NULL) {
		IP_TABLE_ENTRY *next = e->NextExpired;
		Free(e);
		e = next;
	}
}

int CompareIpTable(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL)
		return 0;
	IP_TABLE_ENTRY *e1 = *(IP_TABLE_ENTRY **)p1;
	IP_TABLE_ENTRY *e2 = *(IP_TABLE_ENTRY **)p2;
	if (e1 == NULL || e2 == NULL)
		return 0;
	return CmpIpAddr(&e1->Ip, &e2->Ip);
}

// Add a trusted root certificate to the hub; false when the hub already trusts it or holds MAX_HUB_CERTS
bool AddRootCert(HUB *hub, X *x) {
	bool added = false;
	if (hub == NULL || x == NULL)
		return false;

	HUBDB *db = hub->HubDb;
	if (db != NULL) {
		LockList(db->RootCertList);
		{
			if (LIST_NUM(db->RootCertList) < MAX_HUB_CERTS) {
				bool ok = true;

				for (UINT i = 0; i < LIST_NUM(db->RootCertList); i++) {
					X *exist_x = LIST_DATA(db->RootCertList, i);
					if (CompareX(exist_x, x)) {
						ok = false;
						break;
					}
				}

				if (ok) {
					Insert(db->RootCertList, CloneX(x));
					added = true;
				}
			}
		}
		UnlockList(db->RootCertList);
	}

	return added;
}

int CompareCert(void *p1, void *p2) {
	wchar_t tmp1[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	if (p1 == NULL || p2 == NULL)
		return 0;
	X *x1 = *(X **)p1;
	X *x2 = *(X **)p2;
	if (x1 == NULL || x2 == NULL)
		return 0;

	GetPrintNameFromX(tmp1, sizeof(tmp1), x1);
	GetPrintNameFromX(tmp2, sizeof(tmp2), x2);

	return UniStrCmpi(tmp1, tmp2);
}
