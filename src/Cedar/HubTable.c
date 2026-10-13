// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// HubTable.c
// Virtual Hub tables: user list cache, IP access control list, CRL, access list, trusted certificates, MAC and IP tables

#include "Hub.h"

#include "Admin.h"
#include "Bridge.h"
#include "Connection.h"
#include "Link.h"
#include "Protocol.h"
#include "Server.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/DNS.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"
#include "HubInternal.h"

// Create a user list
LIST *NewUserList()
{
	LIST *o = NewList(CompareUserList);

	return o;
}

// Search whether the specified user matches to the user list (with cache expiration)
bool IsUserMatchInUserListWithCacheExpires(LIST *o, char *filename, UINT64 user_hash, UINT64 lifetime)
{
	bool ret = false;
	UINT64 now = Tick64();
	// Validate arguments
	if (o == NULL || filename == NULL || user_hash == 0)
	{
		return false;
	}

	LockList(o);
	{
		if (lifetime != 0)
		{
			if (o->Param1 == 0 || (now >= (o->Param1 + lifetime)))
			{
				DeleteAllUserListCache(o);

				o->Param1 = now;
			}
		}

		ret = IsUserMatchInUserList(o, filename, user_hash);
	}
	UnlockList(o);

	return ret;
}

bool IsUserMatchInUserListWithCacheExpiresAcl(LIST *o, char *name_in_acl, UINT64 user_hash, UINT64 lifetime)
{
	char tmp[16];
	bool exclude = false;
	char filename[MAX_SIZE];
	char filename2[MAX_SIZE];
	bool is_full_path = false;
	bool ret = false;
	// Validate arguments
	if (o == NULL || name_in_acl == NULL || user_hash == 0 || StrLen(name_in_acl) < 9)
	{
		return false;
	}

	StrCpy(tmp, sizeof(tmp), name_in_acl);
	StrLower(tmp);

	tmp[8] = 0;

	if (Cmp(tmp, ACCESS_LIST_INCLUDED_PREFIX, 8) == 0)
	{
		// include
		exclude = false;
	}
	else
	{
		// exclude
		exclude = true;
	}

	// Extract the file name
	StrCpy(filename, sizeof(filename), name_in_acl + 8);
	Trim(filename);

	// Identify whether the file name is an absolute path
	if (filename[0] == '\\' || filename[0] == '/' || (filename[1] == ':' && filename[2] == '\\'))
	{
		is_full_path = true;
	}

	if (is_full_path == false)
	{
		// Prepend a '@' if the file name is a relative path
		StrCpy(filename2, sizeof(filename2), "@");
		StrCat(filename2, sizeof(filename2), filename);
		StrCpy(filename, sizeof(filename), filename2);
	}

	ret = IsUserMatchInUserListWithCacheExpires(o, filename, user_hash, lifetime);

	if (exclude)
	{
		ret = NEGATIVE_BOOL(ret);
	}

	return ret;
}

// Search whether the specified user matches to the user list
bool IsUserMatchInUserList(LIST *o, char *filename, UINT64 user_hash)
{
	USERLIST *u;
	bool ret = false;
	// Validate arguments
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

// Read the user list
USERLIST *LoadUserList(LIST *o, char *filename)
{
	USERLIST *u;
	BUF *b;
	// Validate arguments
	if (o == NULL || filename == NULL)
	{
		return NULL;
	}

	u = FindUserList(o, filename);

	if (u != NULL)
	{
		Delete(o, u);

		FreeUserListEntry(u);
	}

	u = ZeroMalloc(sizeof(USERLIST));

	StrCpy(u->Filename, sizeof(u->Filename), filename);

	u->UserHashList = NewInt64List(false);

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

// Release the user list entry
void FreeUserListEntry(USERLIST *u)
{
	// Validate arguments
	if (u == NULL)
	{
		return;
	}

	ReleaseInt64List(u->UserHashList);

	Free(u);
}

// Search in user list
USERLIST *FindUserList(LIST *o, char *filename)
{
	USERLIST t, *u;
	// Validate arguments
	if (o == NULL || filename == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Filename, sizeof(t.Filename), filename);

	u = Search(o, &t);

	return u;
}

// User list entry comparison function
int CompareUserList(void *p1, void *p2)
{
	USERLIST *u1, *u2;
	// Validate arguments
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

// Delete the cache of the all user list
void DeleteAllUserListCache(LIST *o)
{
	UINT i;
	// Validate arguments
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

// Release the user list
void FreeUserList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		USERLIST *u = LIST_DATA(o, i);

		FreeUserListEntry(u);
	}

	ReleaseList(o);
}

// Set all the AC list
void SetAcList(LIST *o, LIST *src)
{
	UINT i;
	// Validate arguments
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

// Remove all AC from the AC list
void DelAllAc(LIST *o)
{
	UINT i;
	// Validate arguments
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

// Release the AC list
void FreeAcList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		AC *ac = LIST_DATA(o, i);

		Free(ac);
	}

	ReleaseList(o);
}

// Generate a string that indicates the contents of the AC
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

// Calculate whether the specified IP address is rejected by the access list
bool IsIpDeniedByAcList(IP *ip, LIST *o)
{
	UINT i;
	// Validate arguments
	if (ip == NULL || o == NULL)
	{
		return false;
	}

	if (GetGlobalServerFlag(GSF_DISABLE_AC) != 0)
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

// Calculate whether the specified IP address is masked by the AC
bool IsIpMaskedByAc(IP *ip, AC *ac)
{
	UINT uip, net, mask;
	// Validate arguments
	if (ip == NULL || ac == NULL)
	{
		return false;
	}

	if (GetGlobalServerFlag(GSF_DISABLE_AC) != 0)
	{
		return false;
	}

	if (IsIP4(ip))
	{
		// IPv4
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
		// IPv6
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

// Add an AC to the list
void AddAc(LIST *o, AC *ac)
{
	// Validate arguments
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

// Normalize the AC list
void NormalizeAcList(LIST *o)
{
	UINT i;
	// Validate arguments
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

// Create a new AC list
LIST *NewAcList()
{
	return NewList(CmpAc);
}

// AC comparison
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

// Copy the CRL
CRL *CopyCrl(CRL *crl)
{
	CRL *ret;
	// Validate arguments
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

// Release the CRL
void FreeCrl(CRL *crl)
{
	// Validate arguments
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

// Check whether the certificate has been disabled by searching the CRL list of Virtual HUB
bool IsValidCertInHub(HUB *h, X *x)
{
	bool ret;
	// Validate arguments
	if (h == NULL || x == NULL)
	{
		return false;
	}

	if (h->HubDb == NULL)
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
		// This is invalid because it was matched
		return false;
	}

	// This is valid because it wasn't matched
	return true;
}

// Search whether the certificate matches the CRL list
bool IsCertMatchCrlList(X *x, LIST *o)
{
	UINT i;
	// Validate arguments
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

// Convert the CRL to a string
wchar_t *GenerateCrlStr(CRL *crl)
{
	wchar_t tmp[2048];
	// Validate arguments
	if (crl == NULL)
	{
		return NULL;
	}

	UniStrCpy(tmp, sizeof(tmp), L"");

	if (crl->Name != NULL)
	{
		// Name information
		wchar_t name[MAX_SIZE];

		UniStrCat(tmp, sizeof(tmp), L"Subject=\"");

		GetAllNameFromName(name, sizeof(name), crl->Name);
		UniStrCat(tmp, sizeof(tmp), name);
		UniStrCat(tmp, sizeof(tmp), L"\", ");
	}

	if (crl->Serial != NULL)
	{
		// Serial information
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
		// MD5
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
		// MD5
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

// Check whether it matches the Certificate Revocation List entry
bool IsCertMatchCrl(X *x, CRL *crl)
{
	bool b = true;
	// Validate arguments
	if (x == NULL || crl == NULL)
	{
		return false;
	}

	if (crl->Serial != NULL)
	{
		// If a serial number is defined in the CRL
		if (x->serial == NULL || CompareXSerial(x->serial, crl->Serial) == false)
		{
			// Serial number mismatch
			b = false;
		}
	}

	if (IsZero(crl->DigestMD5, sizeof(crl->DigestMD5)) == false)
	{
		UCHAR test[MD5_SIZE];
		// If a DigestMD5 is defined in the CRL
		GetXDigest(x, test, false);

		if (Cmp(test, crl->DigestMD5, MD5_SIZE) != 0)
		{
			b = false;
		}
	}

	if (IsZero(crl->DigestSHA1, sizeof(crl->DigestSHA1)) == false)
	{
		UCHAR test[SHA1_SIZE];
		// If a DigestSHA1 is defined in the CRL
		GetXDigest(x, test, true);

		if (Cmp(test, crl->DigestSHA1, SHA1_SIZE) != 0)
		{
			b = false;
		}
	}

	if (crl->Name != NULL)
	{
		// If a name is defined in the CRL
		NAME *xn, *cn;
		xn = x->subject_name;
		cn = crl->Name;

		if (cn->CommonName != NULL && (UniIsEmptyStr(cn->CommonName) == false))
		{
			if (xn->CommonName == NULL || UniSoftStrCmp(xn->CommonName, cn->CommonName) != 0)
			{
				// CommonName mismatch
				b = false;
			}
		}

		if (cn->Organization != NULL && (UniIsEmptyStr(cn->Organization) == false))
		{
			if (xn->Organization == NULL || UniSoftStrCmp(xn->Organization, cn->Organization) != 0)
			{
				// Organization mismatch
				b = false;
			}
		}

		if (cn->Unit != NULL && (UniIsEmptyStr(cn->Unit) == false))
		{
			if (xn->Unit == NULL || UniSoftStrCmp(xn->Unit, cn->Unit) != 0)
			{
				// Unit mismatch
				b = false;
			}
		}

		if (cn->Country != NULL && (UniIsEmptyStr(cn->Country) == false))
		{
			if (xn->Country == NULL || UniSoftStrCmp(xn->Country, cn->Country) != 0)
			{
				// Country mismatch
				b = false;
			}
		}

		if (cn->State != NULL && (UniIsEmptyStr(cn->State) == false))
		{
			if (xn->State == NULL || UniSoftStrCmp(xn->State, cn->State) != 0)
			{
				// State mismatch
				b = false;
			}
		}

		if (cn->Local != NULL && (UniIsEmptyStr(cn->Local) == false))
		{
			if (xn->Local == NULL || UniSoftStrCmp(xn->Local, cn->Local) != 0)
			{
				// Local mismatch
				b = false;
			}
		}
	}

	return b;
}

// Convert an access list to a string
void GetAccessListStr(char *str, UINT size, ACCESS *a)
{
	char tmp[MAX_SIZE];
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	bool l3 = false;
	bool asterisk = false;
	// Validate arguments
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

// Adding Access List
void AddAccessList(HUB *hub, ACCESS *a)
{
	AddAccessListEx(hub, a, false, false);
}

void AddAccessListEx(HUB *hub, ACCESS *a, bool no_sort, bool no_reassign_id)
{
	// Validate arguments
	if (hub == NULL || a == NULL)
	{
		return;
	}

	LockList(hub->AccessList);
	{
		ACCESS *access;
		UINT i;

		// Check the number of items
		if (LIST_NUM(hub->AccessList) >= MAX_ACCESSLISTS)
		{
			UnlockList(hub->AccessList);
			return;
		}

		access = Malloc(sizeof(ACCESS));
		Copy(access, a, sizeof(ACCESS));

		access->IsSrcUsernameIncludeOrExclude = false;
		access->IsDestUsernameIncludeOrExclude = false;

		// User name correction
		if (IsEmptyStr(access->SrcUsername) == false)
		{
			if (StartWith(access->SrcUsername, ACCESS_LIST_INCLUDED_PREFIX) == false && StartWith(access->SrcUsername, ACCESS_LIST_EXCLUDED_PREFIX) == false)
			{
				MakeSimpleUsernameRemoveNtDomain(access->SrcUsername, sizeof(access->SrcUsername), access->SrcUsername);
			}
			else
			{
				access->IsSrcUsernameIncludeOrExclude = true;
			}
		}
		if (IsEmptyStr(access->DestUsername) == false)
		{
			if (StartWith(access->DestUsername, ACCESS_LIST_INCLUDED_PREFIX) == false && StartWith(access->DestUsername, ACCESS_LIST_EXCLUDED_PREFIX) == false)
			{
				MakeSimpleUsernameRemoveNtDomain(access->DestUsername, sizeof(access->DestUsername), access->DestUsername);
			}
			else
			{
				access->IsDestUsernameIncludeOrExclude = true;
			}
		}

		access->SrcUsernameHash = UsernameToInt64(access->SrcUsername);
		access->DestUsernameHash = UsernameToInt64(access->DestUsername);

		// Port number correction
		if (access->SrcPortStart != 0)
		{
			access->SrcPortEnd = MAX(access->SrcPortEnd, access->SrcPortStart);
		}
		if (access->DestPortStart != 0)
		{
			access->DestPortEnd = MAX(access->DestPortEnd, access->DestPortStart);
		}

		// Correct delay, jitter, and packet loss
		access->Delay = MAKESURE(access->Delay, 0, HUB_ACCESSLIST_DELAY_MAX);
		access->Jitter = MAKESURE(access->Jitter, 0, HUB_ACCESSLIST_JITTER_MAX);
		access->Loss = MAKESURE(access->Loss, 0, HUB_ACCESSLIST_LOSS_MAX);

		if (no_sort == false)
		{
			Insert(hub->AccessList, access);
		}
		else
		{
			Add(hub->AccessList, access);
		}

		// Reassign the ID
		if (no_reassign_id == false)
		{
			for (i = 0;i < LIST_NUM(hub->AccessList);i++)
			{
				ACCESS *a = LIST_DATA(hub->AccessList, i);
				a->Id = (i + 1);
			}
		}
	}
	UnlockList(hub->AccessList);
}

// Initialize the access list
void InitAccessList(HUB *hub)
{
	// Validate arguments
	if (hub == NULL)
	{
		return;
	}

	hub->AccessList = NewList(CmpAccessList);
}

// Release the access list
void FreeAccessList(HUB *hub)
{
	UINT i;
	// Validate arguments
	if (hub == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(hub->AccessList);i++)
	{
		ACCESS *a = LIST_DATA(hub->AccessList, i);
		Free(a);
	}

	ReleaseList(hub->AccessList);
	hub->AccessList = NULL;
}

// Comparison of the access list entry
int CmpAccessList(void *p1, void *p2)
{
	ACCESS *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(ACCESS **)p1;
	a2 = *(ACCESS **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}
	// Sort by priority
	if (a1->Priority > a2->Priority)
	{
		return 1;
	}
	else if (a1->Priority < a2->Priority)
	{
		return -1;
	}
	else if (a1->Discard > a2->Discard)
	{
		return 1;
	}
	else if (a1->Discard < a2->Discard)
	{
		return -1;
	}
	else
	{
		UINT64 size64 = ((UINT64)(&a1->UniqueId) - (UINT64)(&a1->Active));
		UINT size32 = (UINT)size64;

		return Cmp(&a1->Active, &a2->Active, size32);
	}
}

// Delete old IP table entries
void DeleteOldIpTableEntry(LIST *o)
{
	UINT i;
	IP_TABLE_ENTRY *old = NULL;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IP_TABLE_ENTRY *e = LIST_DATA(o, i);
		old = e;
	}

	if (old != NULL)
	{
		Delete(o, old);
		Free(old);
	}
}

// Delete the expired MAC table entries
void DeleteExpiredMacTableEntry(HASH_LIST *h)
{
	LIST *o2;
	UINT i;
	MAC_TABLE_ENTRY **pp;
	UINT num;
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	o2 = NewListFast(NULL);

	pp = (MAC_TABLE_ENTRY **)HashListToArray(h, &num);

	for (i = 0;i < num;i++)
	{
		MAC_TABLE_ENTRY *e = pp[i];
		if ((e->UpdatedTime + (UINT64)MAC_TABLE_EXPIRE_TIME) <= Tick64())
		{
			Add(o2, e);
		}
	}

	for (i = 0;i < LIST_NUM(o2);i++)
	{
		MAC_TABLE_ENTRY *e = LIST_DATA(o2, i);
		DeleteHash(h, e);
		Free(e);
	}

	ReleaseList(o2);

	Free(pp);
}

// Delete the expired IP table entries
void DeleteExpiredIpTableEntry(LIST *o)
{
	LIST *o2;
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	o2 = NewListFast(NULL);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IP_TABLE_ENTRY *e = LIST_DATA(o, i);
		if ((e->UpdatedTime + (UINT64)(e->DhcpAllocated ? IP_TABLE_EXPIRE_TIME_DHCP : IP_TABLE_EXPIRE_TIME)) <= Tick64())
		{
			Add(o2, e);
		}
	}

	for (i = 0;i < LIST_NUM(o2);i++)
	{
		IP_TABLE_ENTRY *e = LIST_DATA(o2, i);
		Delete(o, e);
		Free(e);
	}

	ReleaseList(o2);
}

// Comparison function of IP table entries
int CompareIpTable(void *p1, void *p2)
{
	IP_TABLE_ENTRY *e1, *e2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	e1 = *(IP_TABLE_ENTRY **)p1;
	e2 = *(IP_TABLE_ENTRY **)p2;
	if (e1 == NULL || e2 == NULL)
	{
		return 0;
	}
	return CmpIpAddr(&e1->Ip, &e2->Ip);
}

// Get hash of MAC table entry
UINT GetHashOfMacTable(void *p)
{
	UINT v;
	MAC_TABLE_ENTRY *e = p;

	if (e == NULL)
	{
		return 0;
	}

	v = e->MacAddress[0] + e->MacAddress[1] + e->MacAddress[2] + 
		e->MacAddress[3] + e->MacAddress[4] + e->MacAddress[5] + 
		e->VlanId;

	return v;
}

// Comparison function of the MAC table entries
int CompareMacTable(void *p1, void *p2)
{
	int r;
	MAC_TABLE_ENTRY *e1, *e2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	e1 = *(MAC_TABLE_ENTRY **)p1;
	e2 = *(MAC_TABLE_ENTRY **)p2;
	if (e1 == NULL || e2 == NULL)
	{
		return 0;
	}
	r = Cmp(e1->MacAddress, e2->MacAddress, 6);
	if (r != 0)
	{
		return r;
	}
	if (e1->VlanId > e2->VlanId)
	{
		return 1;
	}
	else if (e1->VlanId < e2->VlanId)
	{
		return -1;
	}
	return 0;
}

// Add the trusted root certificate to the HUB
void AddRootCert(HUB *hub, X *x)
{
	HUBDB *db;
	// Validate arguments
	if (hub == NULL || x == NULL)
	{
		return;
	}

	db = hub->HubDb;
	if (db != NULL)
	{
		LockList(db->RootCertList);
		{
			if (LIST_NUM(db->RootCertList) < MAX_HUB_CERTS)
			{
				UINT i;
				bool ok = true;

				for (i = 0;i < LIST_NUM(db->RootCertList);i++)
				{
					X *exist_x = LIST_DATA(db->RootCertList, i);
					if (CompareX(exist_x, x))
					{
						ok = false;
						break;
					}
				}

				if (ok)
				{
					Insert(db->RootCertList, CloneX(x));
				}
			}
		}
		UnlockList(db->RootCertList);
	}
}

// Compare the list of certificates
int CompareCert(void *p1, void *p2)
{
	X *x1, *x2;
	wchar_t tmp1[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	x1 = *(X **)p1;
	x2 = *(X **)p2;
	if (x1 == NULL || x2 == NULL)
	{
		return 0;
	}

	GetPrintNameFromX(tmp1, sizeof(tmp1), x1);
	GetPrintNameFromX(tmp2, sizeof(tmp2), x2);

	return UniStrCmpi(tmp1, tmp2);
}
