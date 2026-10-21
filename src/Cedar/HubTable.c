// HubTable.c
// Virtual Hub tables: user list cache, IP access control list, CRL, access list, trusted certificates, MAC and IP tables

#include "Hub.h"

#include "Admin.h"
#include "Bridge.h"
#include "Connection.h"
#include "Protocol.h"
#include "Server.h"

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

bool IsUserMatchInUserList(LIST *o, char *filename, UINT64 user_hash)
{
	USERLIST *u;
	bool ret = false;
	if (o == NULL || filename == NULL || user_hash == 0)
	{
		return false;
	}

	LockList(o);
	{
		u = FindUserList(o, filename);
		if (u == NULL)
		{
			u = LoadUserList(o, filename);
		}

		if (u != NULL)
		{
			ret = IsInt64InList(u->UserHashList, user_hash);
		}
	}
	UnlockList(o);

	return ret;
}

USERLIST *LoadUserList(LIST *o, char *filename)
{
	USERLIST *u;
	BUF *b;
	if (o == NULL || filename == NULL)
	{
		return NULL;
	}

	u = ZeroMalloc(sizeof(USERLIST));

	StrCpy(u->Filename, sizeof(u->Filename), filename);

	u->UserHashList = NewInt64List();

	b = ReadDumpWithMaxSize(filename, ACCESS_LIST_INCLUDE_FILE_MAX_SIZE);
	if (b != NULL)
	{
		while (true)
		{
			char *line = CfgReadNextLine(b);
			UINT64 ui;
			if (line == NULL)
			{
				break;
			}

			Trim(line);

			if (IsEmptyStr(line) == false)
			{
				if (StartWith(line, "#") == false &&
					StartWith(line, "//") == false &&
					StartWith(line, ";") == false)
				{
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

void FreeUserListEntry(USERLIST *u)
{
	if (u == NULL)
	{
		return;
	}

	ReleaseInt64List(u->UserHashList);

	Free(u);
}

USERLIST *FindUserList(LIST *o, char *filename)
{
	USERLIST t, *u;
	if (o == NULL || filename == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Filename, sizeof(t.Filename), filename);

	u = Search(o, &t);

	return u;
}

int CompareUserList(void *p1, void *p2)
{
	USERLIST *u1, *u2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	u1 = *(USERLIST **)p1;
	u2 = *(USERLIST **)p2;
	if (u1 == NULL || u2 == NULL)
	{
		return 0;
	}

	return StrCmpi(u1->Filename, u2->Filename);
}

void DeleteAllUserListCache(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	LockList(o);
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			USERLIST *u = LIST_DATA(o, i);

			FreeUserListEntry(u);
		}

		DeleteAll(o);
	}
	UnlockList(o);
}

void SetAcList(LIST *o, LIST *src)
{
	UINT i;
	if (o == NULL || src == NULL)
	{
		return;
	}

	DelAllAc(o);

	for (i = 0;i < LIST_NUM(src);i++)
	{
		AC *ac = LIST_DATA(src, i);

		AddAc(o, ac);
	}
}

void DelAllAc(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		AC *ac = LIST_DATA(o, i);

		Free(ac);
	}

	DeleteAll(o);
}

void FreeAcList(LIST *o)
{
	if (o == NULL)
	{
		return;
	}

	DelAllAc(o);

	ReleaseList(o);
}

char *GenerateAcStr(AC *ac)
{
	char tmp[MAX_SIZE];
	char ip[64], mask[64];

	if (ac == NULL)
	{
		return NULL;
	}

	IPToStr(ip, sizeof(ip), &ac->IpAddress);
	MaskToStr(mask, sizeof(mask), &ac->SubnetMask);

	if (ac->Masked == false)
	{
		Format(tmp, sizeof(tmp), "%s", ip);
	}
	else
	{
		Format(tmp, sizeof(tmp), "%s/%s", ip, mask);
	}

	return CopyStr(tmp);
}

bool IsIpDeniedByAcList(IP *ip, LIST *o)
{
	UINT i;
	if (ip == NULL || o == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		AC *ac = LIST_DATA(o, i);

		if (IsIpMaskedByAc(ip, ac))
		{
			if (ac->Deny == false)
			{
				return false;
			}
			else
			{
				return true;
			}
		}
	}

	return false;
}

bool IsIpMaskedByAc(IP *ip, AC *ac)
{
	UINT uip, net, mask;
	if (ip == NULL || ac == NULL)
	{
		return false;
	}

	if (IsIP4(ip))
	{
		uip = IPToUINT(ip);
		net = IPToUINT(&ac->IpAddress);
		mask = IPToUINT(&ac->SubnetMask);

		if (ac->Masked == false)
		{
			if (uip == net)
			{
				return true;
			}
		}
		else
		{
			if ((uip & mask) == (net & mask))
			{
				return true;
			}
		}

		return false;
	}
	else
	{
		if (ac->Masked == false)
		{
			if (CmpIpAddr(ip, &ac->IpAddress) == 0)
			{
				return true;
			}
		}
		else
		{
			IP and1, and2;

			IPAnd6(&and1, ip, &ac->SubnetMask);
			IPAnd6(&and2, &ac->IpAddress, &ac->SubnetMask);

			if (CmpIpAddr(&and1, &and2) == 0)
			{
				return true;
			}
		}

		return false;
	}
}

void AddAc(LIST *o, AC *ac)
{
	if (o == NULL || ac == NULL)
	{
		return;
	}

	if (LIST_NUM(o) < MAX_HUB_ACS)
	{
		Insert(o, Clone(ac, sizeof(AC)));

		NormalizeAcList(o);
	}
}

void NormalizeAcList(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		AC *ac = LIST_DATA(o, i);

		if (IsIP6(&ac->IpAddress))
		{
			ac->IpAddress.ipv6_scope_id = 0;
		}

		ac->Id = (i + 1);
	}
}

int CmpAc(void *p1, void *p2)
{
	AC *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(AC **)p1;
	a2 = *(AC **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}
	if (a1->Priority > a2->Priority)
	{
		return 1;
	}
	else if (a1->Priority < a2->Priority)
	{
		return -1;
	}
	else if (a1->Deny > a2->Deny)
	{
		return 1;
	}
	else if (a1->Deny < a2->Deny)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

CRL *CopyCrl(CRL *crl)
{
	CRL *ret;
	if (crl == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(CRL));

	if (crl->Serial != NULL)
	{
		ret->Serial = NewXSerial(crl->Serial->data, crl->Serial->size);
	}

	ret->Name = CopyName(crl->Name);

	Copy(ret->DigestMD5, crl->DigestMD5, MD5_SIZE);
	Copy(ret->DigestSHA1, crl->DigestSHA1, SHA1_SIZE);

	return ret;
}

void FreeCrl(CRL *crl)
{
	if (crl == NULL)
	{
		return;
	}

	if (crl->Serial != NULL)
	{
		FreeXSerial(crl->Serial);
	}

	if (crl->Name != NULL)
	{
		FreeName(crl->Name);
	}

	Free(crl);
}

bool IsValidCertInHub(HUB *h, X *x)
{
	bool ret;
	if (h == NULL || x == NULL)
	{
		return false;
	}

	LockList(h->HubDb->CrlList);
	{
		ret = IsCertMatchCrlList(x, h->HubDb->CrlList);
	}
	UnlockList(h->HubDb->CrlList);

	if (ret)
	{
		return false;
	}

	return true;
}

bool IsCertMatchCrlList(X *x, LIST *o)
{
	UINT i;
	if (x == NULL || o == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		CRL *crl = LIST_DATA(o, i);

		if (IsCertMatchCrl(x, crl))
		{
			return true;
		}
	}

	return false;
}

wchar_t *GenerateCrlStr(CRL *crl)
{
	wchar_t tmp[2048];
	if (crl == NULL)
	{
		return NULL;
	}

	UniStrCpy(tmp, sizeof(tmp), L"");

	if (crl->Name != NULL)
	{
		wchar_t name[MAX_SIZE];

		UniStrCat(tmp, sizeof(tmp), L"Subject=\"");

		GetAllNameFromName(name, sizeof(name), crl->Name);
		UniStrCat(tmp, sizeof(tmp), name);
		UniStrCat(tmp, sizeof(tmp), L"\", ");
	}

	if (crl->Serial != NULL)
	{
		char str[128];
		wchar_t uni[128];

		BinToStrEx(str, sizeof(str), crl->Serial->data, crl->Serial->size);
		StrToUni(uni, sizeof(uni), str);
		UniStrCat(tmp, sizeof(tmp), L"Serial=\"");
		UniStrCat(tmp, sizeof(tmp), uni);
		UniStrCat(tmp, sizeof(tmp), L"\", ");
	}

	if (IsZero(crl->DigestMD5, MD5_SIZE) == false)
	{
		char str[128];
		wchar_t uni[128];

		BinToStrEx(str, sizeof(str), crl->DigestMD5, MD5_SIZE);
		StrToUni(uni, sizeof(uni), str);
		UniStrCat(tmp, sizeof(tmp), L"MD5=\"");
		UniStrCat(tmp, sizeof(tmp), uni);
		UniStrCat(tmp, sizeof(tmp), L"\", ");
	}

	if (IsZero(crl->DigestSHA1, SHA1_SIZE) == false)
	{
		char str[128];
		wchar_t uni[128];

		BinToStrEx(str, sizeof(str), crl->DigestSHA1, SHA1_SIZE);
		StrToUni(uni, sizeof(uni), str);
		UniStrCat(tmp, sizeof(tmp), L"SHA1=\"");
		UniStrCat(tmp, sizeof(tmp), uni);
		UniStrCat(tmp, sizeof(tmp), L"\", ");
	}

	if (UniEndWith(tmp, L", "))
	{
		tmp[UniStrLen(tmp) - 2] = 0;
	}

	return CopyUniStr(tmp);
}

bool IsCertMatchCrl(X *x, CRL *crl)
{
	bool b = true;
	if (x == NULL || crl == NULL)
	{
		return false;
	}

	if (crl->Serial != NULL)
	{
		if (x->serial == NULL || CompareXSerial(x->serial, crl->Serial) == false)
		{
			b = false;
		}
	}

	if (IsZero(crl->DigestMD5, sizeof(crl->DigestMD5)) == false)
	{
		UCHAR test[MD5_SIZE];
		GetXDigest(x, test, false);

		if (Cmp(test, crl->DigestMD5, MD5_SIZE) != 0)
		{
			b = false;
		}
	}

	if (IsZero(crl->DigestSHA1, sizeof(crl->DigestSHA1)) == false)
	{
		UCHAR test[SHA1_SIZE];
		GetXDigest(x, test, true);

		if (Cmp(test, crl->DigestSHA1, SHA1_SIZE) != 0)
		{
			b = false;
		}
	}

	if (crl->Name != NULL)
	{
		NAME *xn, *cn;
		xn = x->subject_name;
		cn = crl->Name;

		if (cn->CommonName != NULL && (UniIsEmptyStr(cn->CommonName) == false))
		{
			if (xn->CommonName == NULL || UniSoftStrCmp(xn->CommonName, cn->CommonName) != 0)
			{
				b = false;
			}
		}

		if (cn->Organization != NULL && (UniIsEmptyStr(cn->Organization) == false))
		{
			if (xn->Organization == NULL || UniSoftStrCmp(xn->Organization, cn->Organization) != 0)
			{
				b = false;
			}
		}

		if (cn->Unit != NULL && (UniIsEmptyStr(cn->Unit) == false))
		{
			if (xn->Unit == NULL || UniSoftStrCmp(xn->Unit, cn->Unit) != 0)
			{
				b = false;
			}
		}

		if (cn->Country != NULL && (UniIsEmptyStr(cn->Country) == false))
		{
			if (xn->Country == NULL || UniSoftStrCmp(xn->Country, cn->Country) != 0)
			{
				b = false;
			}
		}

		if (cn->State != NULL && (UniIsEmptyStr(cn->State) == false))
		{
			if (xn->State == NULL || UniSoftStrCmp(xn->State, cn->State) != 0)
			{
				b = false;
			}
		}

		if (cn->Local != NULL && (UniIsEmptyStr(cn->Local) == false))
		{
			if (xn->Local == NULL || UniSoftStrCmp(xn->Local, cn->Local) != 0)
			{
				b = false;
			}
		}
	}

	return b;
}

void GetAccessListStr(char *str, UINT size, ACCESS *a)
{
	char tmp[MAX_SIZE];
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	bool l3 = false;
	bool asterisk = false;
	if (str == NULL || a == NULL)
	{
		return;
	}

	StrCpy(str, size, "");

	if (a->IsIPv6 == false)
	{
		if (a->SrcIpAddress != 0 || a->SrcSubnetMask != 0)
		{
			IPToStr32(tmp1, sizeof(tmp1), a->SrcIpAddress);
			MaskToStr32(tmp2, sizeof(tmp2), a->SrcSubnetMask);
			Format(tmp, sizeof(tmp), "SrcIPv4=%s/%s, ", tmp1, tmp2);
			StrCat(str, size, tmp);

			l3 = true;
		}

		if (a->DestIpAddress != 0 || a->DestSubnetMask != 0)
		{
			IPToStr32(tmp1, sizeof(tmp1), a->DestIpAddress);
			MaskToStr32(tmp2, sizeof(tmp2), a->DestSubnetMask);
			Format(tmp, sizeof(tmp), "DstIPv4=%s/%s, ", tmp1, tmp2);
			StrCat(str, size, tmp);

			l3 = true;
		}
	}
	else
	{
		if (IsZeroIP6Addr(&a->SrcIpAddress6) == false || IsZeroIP6Addr(&a->SrcSubnetMask6) == false)
		{
			IP6AddrToStr(tmp1, sizeof(tmp1), &a->SrcIpAddress6);
			Mask6AddrToStr(tmp2, sizeof(tmp2), &a->SrcSubnetMask6);
			Format(tmp, sizeof(tmp), "SrcIPv6=%s/%s, ", tmp1, tmp2);
			StrCat(str, size, tmp);

			l3 = true;
		}

		if (IsZeroIP6Addr(&a->DestIpAddress6) == false || IsZeroIP6Addr(&a->DestSubnetMask6) == false)
		{
			IP6AddrToStr(tmp1, sizeof(tmp1), &a->DestIpAddress6);
			Mask6AddrToStr(tmp2, sizeof(tmp2), &a->DestSubnetMask6);
			Format(tmp, sizeof(tmp), "DstIPv6=%s/%s, ", tmp1, tmp2);
			StrCat(str, size, tmp);

			l3 = true;
		}
	}

	if (a->Protocol != 0)
	{
		StrCpy(tmp1, sizeof(tmp1), "");
		switch (a->Protocol)
		{
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
		{
			Format(tmp, sizeof(tmp), "Protocol=%s(%u), ", tmp1, a->Protocol);
		}
		else
		{
			Format(tmp, sizeof(tmp), "Protocol=%s, ", tmp1);
		}

		StrCat(str, size, tmp);

		l3 = true;
	}

	if (a->SrcPortStart != 0)
	{
		if (a->SrcPortEnd == a->SrcPortStart)
		{
			Format(tmp, sizeof(tmp), "SrcPort=%u, ", a->SrcPortStart);
			StrCat(str, size, tmp);
		}
		else
		{
			Format(tmp, sizeof(tmp), "SrcPort=%u-%u, ", a->SrcPortStart, a->SrcPortEnd);
			StrCat(str, size, tmp);
		}

		l3 = true;
	}

	if (a->DestPortStart != 0)
	{
		if (a->DestPortEnd == a->DestPortStart)
		{
			Format(tmp, sizeof(tmp), "DstPort=%u, ", a->DestPortStart);
			StrCat(str, size, tmp);
		}
		else
		{
			Format(tmp, sizeof(tmp), "DstPort=%u-%u, ", a->DestPortStart, a->DestPortEnd);
			StrCat(str, size, tmp);
		}

		l3 = true;
	}

	if (StrLen(a->SrcUsername) != 0)
	{
		Format(tmp, sizeof(tmp), "SrcUser=%s, ", a->SrcUsername);
		StrCat(str, size, tmp);
	}

	if (StrLen(a->DestUsername) != 0)
	{
		Format(tmp, sizeof(tmp), "DstUser=%s, ", a->DestUsername);
		StrCat(str, size, tmp);
	}

	if (a->CheckSrcMac != false)
	{
		char mac[MAX_SIZE], mask[MAX_SIZE];
		MacToStr(mac, sizeof(mac), a->SrcMacAddress);
		MacToStr(mask, sizeof(mask), a->SrcMacMask);
		Format(tmp, sizeof(tmp), "SrcMac=%s/%s, ", mac, mask);
		StrCat(str, size, tmp);
	}
	if (a->CheckDstMac != false)
	{
		char mac[MAX_SIZE], mask[MAX_SIZE];
		MacToStr(mac, sizeof(mac), a->DstMacAddress);
		MacToStr(mask, sizeof(mask), a->DstMacMask);
		Format(tmp, sizeof(tmp), "DstMac=%s/%s, ", mac, mask);
		StrCat(str, size, tmp);
	}

	if (a->CheckTcpState)
	{
		if(a->Established)
		{
			StrCat(str, size, "Established, ");
		}
		else
		{
			StrCat(str, size, "Unestablished, ");
		}

		l3 = true;
	}

	if (a->Discard == false)
	{
		if (a->Delay >= 1)
		{
			Format(tmp, sizeof(tmp), "Delay=%u, ", a->Delay);
			StrCat(str, size, tmp);
		}

		if (a->Jitter >= 1)
		{
			Format(tmp, sizeof(tmp), "Jitter=%u, ", a->Jitter);
			StrCat(str, size, tmp);
		}

		if (a->Loss >= 1)
		{
			Format(tmp, sizeof(tmp), "Loss=%u, " , a->Loss);
			StrCat(str, size, tmp);
		}
	}

	if (IsEmptyStr(a->RedirectUrl) == false)
	{
		Format(tmp, sizeof(tmp), "RedirectUrl=%s, ", a->RedirectUrl);
		StrCat(str, size, tmp);
	}

	if (StrLen(str) == 0)
	{
		asterisk = true;
	}

	if (l3)
	{
		if (a->IsIPv6)
		{
			StrCatLeft(str, size, "(ipv6) ");
		}
		else
		{
			StrCatLeft(str, size, "(ipv4) ");
		}
	}
	else
	{
		StrCatLeft(str, size, "(ether) ");
	}

	if (EndWith(str, ", "))
	{
		str[StrLen(str) - 2] = 0;
	}

	if (asterisk)
	{
		StrCat(str, size, "*");
	}
}
