// ConfigStoreImport.c
// The one-time import of the fork's Config file (ranz_server.config) into an empty configuration store (ADR-0022,
// Configuration store). Since the 2026-10-19 amendment there are no deployed configurations, so the import serves
// development and test configurations. It reads the file through Cfg and writes, in one transaction: the hubs as L2
// networks with their CAs, groups and users (user certificates included), the TCP listeners as TLS listeners, the
// server certificate with its chain, the server and hub administrators as owner and hub-admin accounts, and the policy
// of each hub (CORE-S4-3, #76): the VLANs of its users and groups, its TPID, and its access list as rules of the policy
// engine of the new core. It leaves out what the new core does not take: the SHA-0 password hashes (ADR-0022
// 2026-10-19: those accounts need a new password), the server key (it belongs in a CNG KSP), the cascades, which come
// with the client role (CORE-S3), and the items of the policies of users and groups other than their VLAN.
//
// The access list. The fork judges each frame by the first active entry in the order of the priorities, a pass entry
// before a discard entry of the same priority, and lets through what no entry matches. The policy engine judges the
// first frame of a flow by the first active rule in the order of priority and position, and denies what no rule matches
// (ADR-0019 amendment of 2026-10-21). So the entries become rules of their network in the fork's order, at the fork's
// priorities, or at their ranks when one is beyond what the engine takes, followed by <network>.default-allow, which
// lets through what no entry matches, as the fork does. Entry n of the fork's order (its Id in vpncmd) becomes the rule
// <network>.acl-<n>, or one rule for each identity and protocol that its match takes, <network>.acl-<n>.<k>: a user and
// a group, where the hub has both of the name, since the fork matches the name of an entry against the user and the
// group of a session; and TCP and UDP, for ports without a protocol. An entry with a protocol, ports or the TCP state
// and without addresses takes every address of its family, as the fork matches those of one family only.
//
// What the engine has no match for (MAC addresses, source ports, the TCP state, user list files, masks that are no
// prefix, names it cannot hold) never lets a frame through that the fork dropped: a deny entry is carried without it, so
// that it denies more than the fork did (a mask that is no prefix becomes the longest prefix that holds it), and an allow
// entry is carried inactive, so that it lets nothing through. An entry with a redirect URL is carried as a deny entry,
// as the fork drops the TCP data that it redirects; delays, jitter and losses are left out. Three things the engine does
// otherwise by its design (Core/Policy.h), not by the import: the replies of a flow that a rule allowed pass on its
// conntrack table; ARP, IPv6 neighbour discovery and DHCP pass without rules; and a frame to a group address is judged
// once, before the switch delivers it, so that a rule naming the receiving end does not judge it.
//
// The VLANs. A session of the fork has the VLanId of its user's policy, else of its group's; a session without one gets
// every frame of the hub as it is, tagged or not, and its untagged frames reach the sessions without one only. So the
// user or group of a policy gets the VLAN row of its VLanId, and the network gets the TPID of the hub (VlanTypeId) and an
// untagged VLAN that no user or group of it has, the native VLAN of a member without a VLAN (CsGetPort).

#include "ConfigStore.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "ConfigStoreInternal.h"

#include <ws2tcpip.h>

#define CS_IMPORT_VLANS   4096       // The 12-bit VLAN ids
#define CS_IMPORT_INCLUDE "include:" // The user item of an entry that names a list file of users (Hub.h)
#define CS_IMPORT_EXCLUDE "exclude:"

// The policy of one hub on its way into the store
typedef struct CS_IMPORT_HUB {
	char *Network;                     // The name of the hub, which is that of its network
	char Prefix[CS_MAX_RULE_NAME + 1]; // The name of the network in the document of the policy engine, before the names of its rules
	UCHAR Vlans[CS_IMPORT_VLANS / 8];  // The VLANs of the users and groups of the hub
} CS_IMPORT_HUB;

// What the import reads of an entry of the access list of a hub, as the server of the fork loaded one (SiLoadHubAccessCfg
// of the frozen Cedar, with the port ranges that AddAccessListEx of HubTable.c completes)
typedef struct CS_IMPORT_ACCESS {
	UINT Index;                         // Its place in the folder of the access list
	bool Active;                        // Active
	UINT Priority;                      // Priority
	bool Discard;                       // Discard: a deny entry, else an allow entry
	bool IsIPv6;                        // IsIPv6: its addresses, protocol and ports are those of IPv6, else of IPv4
	UCHAR Src[16];                      // SrcIpAddress or SrcIpAddress6, IPv4 in the first 4 bytes
	UCHAR SrcMask[16];                  // SrcSubnetMask or SrcSubnetMask6
	UCHAR Dst[16];                      // DestIpAddress or DestIpAddress6
	UCHAR DstMask[16];                  // DestSubnetMask or DestSubnetMask6
	UINT Protocol;                      // Protocol, 0 for any
	UINT SrcPortStart;                  // SrcPortStart and SrcPortEnd, both 0 for any port
	UINT SrcPortEnd;                    // ...
	UINT DstPortStart;                  // DestPortStart and DestPortEnd, both 0 for any port
	UINT DstPortEnd;                    // ...
	char SrcUser[MAX_USERNAME_LEN + 1]; // SrcUsername
	char DstUser[MAX_USERNAME_LEN + 1]; // DestUsername
	bool CheckSrcMac;                   // CheckSrcMac, with an address and a mask that the fork reads
	bool CheckDstMac;                   // CheckDstMac, likewise
	bool CheckTcpState;                 // CheckTcpState
	bool Effects;                       // A Delay, Jitter or Loss
	bool Redirect;                      // A RedirectUrl
	wchar_t Note[MAX_SIZE];             // Note
} CS_IMPORT_ACCESS;

// Count the result of writing one row and tell whether the import goes on: a row that the store refuses (not
// valid, or not unique) is skipped, a failure of the store itself stops the import
static bool CsImportCount(CS_IMPORT *r, UINT err, UINT *num) {
	if (err == ERR_NO_ERROR) {
		(*num)++;
		return true;
	}

	if (err == ERR_INTERNAL_ERROR)
		return false;

	r->NumSkipped++;

	return true;
}

// Whether the administrator password item name of the fork (Sha0 of the password) holds a password: the item is
// there and is not the hash of the empty password, which the fork writes when no password is set
static bool CsImportHasPassword(FOLDER *f, char *name) {
	UCHAR hash[SHA1_SIZE];
	UCHAR empty[SHA1_SIZE];

	if (CfgGetByte(f, name, hash, sizeof(hash)) != sizeof(hash))
		return false;

	Sha0(empty, "", 0);

	return (Cmp(hash, empty, sizeof(hash)) != 0);
}

// The certificate item name of f (DER bytes) for usage
static bool CsImportCert(CONFIG_STORE *s, CS_IMPORT *r, UINT usage, char *network, char *user, FOLDER *f, char *name) {
	BUF *b = CfgGetBuf(f, name);
	if (b == NULL)
		return true;

	bool ret = CsImportCount(r, CsAddCert(s, usage, network, user, b->Buf, b->Size), &r->NumCerts);

	FreeBuf(b);

	return ret;
}

// Each certificate of a certificate list folder (CertList, ServerChain: Cert0, Cert1, ... with an X509 item)
static bool CsImportCertList(CONFIG_STORE *s, CS_IMPORT *r, UINT usage, char *network, FOLDER *f) {
	bool ok = true;

	TOKEN_LIST *t = CfgEnumFolderToTokenList(f);

	for (UINT i = 0; ok && t != NULL && i < t->NumTokens; i++)
		ok = CsImportCert(s, r, usage, network, NULL, CfgFindFolder(f, t->Token[i]), "X509");

	FreeToken(t);

	return ok;
}

// The VLAN of the user or group name (kind CS_VLAN_*) of the folder f, when it has a policy: the VLanId of its policy,
// which the hub h then has
static bool CsImportVlan(CONFIG_STORE *s, CS_IMPORT *r, CS_IMPORT_HUB *h, UINT kind, char *name, FOLDER *f) {
	FOLDER *policy = CfgFindFolder(f, "Policy");
	if (policy == NULL)
		return true;

	UINT vlan = CfgGetInt(policy, "VLanId");

	UINT num_vlans = r->NumVlans;
	if (CsImportCount(r, CsSetVlan(s, h->Network, kind, name, vlan), &r->NumVlans) == false)
		return false;

	if (r->NumVlans != num_vlans && vlan < CS_IMPORT_VLANS)
		h->Vlans[vlan / 8] |= (UCHAR)(1 << (vlan % 8));

	return true;
}

// One group folder of a hub, with its VLAN
static bool CsImportGroup(CONFIG_STORE *s, CS_IMPORT *r, CS_IMPORT_HUB *h, FOLDER *f) {
	CS_GROUP g;
	if (f == NULL)
		return true;

	Zero(&g, sizeof(g));
	StrCpy(g.Network, sizeof(g.Network), h->Network);
	StrCpy(g.Name, sizeof(g.Name), f->Name);
	CfgGetUniStr(f, "RealName", g.RealName, sizeof(g.RealName));
	CfgGetUniStr(f, "Note", g.Note, sizeof(g.Note));

	UINT num_groups = r->NumGroups;
	if (CsImportCount(r, CsAddGroup(s, &g), &r->NumGroups) == false)
		return false;

	if (r->NumGroups == num_groups)
		return true;

	return CsImportVlan(s, r, h, CS_VLAN_GROUP, g.Name, f);
}

// One user folder of a hub, with its user certificate and its VLAN
static bool CsImportUser(CONFIG_STORE *s, CS_IMPORT *r, CS_IMPORT_HUB *h, FOLDER *f) {
	CS_USER u;
	if (f == NULL)
		return true;

	char *network = h->Network;

	Zero(&u, sizeof(u));
	StrCpy(u.Network, sizeof(u.Network), network);
	StrCpy(u.Name, sizeof(u.Name), f->Name);
	CfgGetUniStr(f, "RealName", u.RealName, sizeof(u.RealName));
	CfgGetUniStr(f, "Note", u.Note, sizeof(u.Note));
	CfgGetStr(f, "GroupName", u.Group, sizeof(u.Group));
	u.ExpireTime = CfgGetInt64(f, "ExpireTime");
	u.AuthType = CfgGetInt(f, "AuthType");

	if (u.AuthType == AUTHTYPE_NT)
		CfgGetUniStr(f, "AuthNtUserName", u.AuthName, sizeof(u.AuthName));

	if (u.AuthType == AUTHTYPE_ROOTCERT) {
		CfgGetUniStr(f, "AuthCommonName", u.AuthName, sizeof(u.AuthName));

		// A serial number longer than the store keeps makes the user invalid, so it is skipped
		BUF *serial = CfgGetBuf(f, "AuthSerial");
		if (serial != NULL) {
			u.AuthSerialSize = serial->Size;
			if (serial->Size <= sizeof(u.AuthSerial))
				Copy(u.AuthSerial, serial->Buf, serial->Size);
			FreeBuf(serial);
		}
	}

	UINT num_users = r->NumUsers;
	if (CsImportCount(r, CsAddUser(s, &u), &r->NumUsers) == false)
		return false;

	if (r->NumUsers == num_users)
		return true;

	if (u.AuthType == AUTHTYPE_PASSWORD && CfgIsItem(f, "AuthPassword"))
		r->NumPasswordsDropped++;

	if (CsImportVlan(s, r, h, CS_VLAN_USER, u.Name, f) == false)
		return false;

	if (u.AuthType == AUTHTYPE_USERCERT)
		return CsImportCert(s, r, CS_CERT_USER, network, u.Name, f, "AuthUserCert");

	return true;
}

// The IPv4 or IPv6 address item name of f into addr (16 bytes, IPv4 in the first 4), as the fork reads one (CfgGetIp32,
// CfgGetIp6Addr): all 0 when it has none
static void CsImportIp(FOLDER *f, char *name, bool ipv6, UCHAR *addr) {
	char tmp[MAX_SIZE];

	Zero(addr, 16);

	if (ipv6 == false) {
		UINT ip = CfgGetIp32(f, name);
		Copy(addr, &ip, 4);
	} else if (CfgGetStr(f, name, tmp, sizeof(tmp)) && InetPtonA(AF_INET6, tmp, addr) != 1) {
		Zero(addr, 16);
	}
}

// Whether the MAC address item name of f reads as one, as the fork reads it: 6 bytes, or the text of one
static bool CsImportMac(FOLDER *f, char *name) {
	UCHAR mac[6];
	char tmp[MAX_PATH];

	if (CfgGetByte(f, name, mac, sizeof(mac)) != 0)
		return true;

	return CfgGetStr(f, name, tmp, sizeof(tmp)) && StrToMac(mac, tmp);
}

// The entry folder f of an access list, the index-th of the folder, into a
static void CsImportReadAccess(FOLDER *f, UINT index, CS_IMPORT_ACCESS *a) {
	char tmp[MAX_SIZE];

	Zero(a, sizeof(CS_IMPORT_ACCESS));
	a->Index = index;
	CfgGetUniStr(f, "Note", a->Note, sizeof(a->Note));
	a->Active = CfgGetBool(f, "Active");
	a->Priority = CfgGetInt(f, "Priority");
	a->Discard = CfgGetBool(f, "Discard");
	a->IsIPv6 = CfgGetBool(f, "IsIPv6");

	CsImportIp(f, a->IsIPv6 ? "SrcIpAddress6" : "SrcIpAddress", a->IsIPv6, a->Src);
	CsImportIp(f, a->IsIPv6 ? "SrcSubnetMask6" : "SrcSubnetMask", a->IsIPv6, a->SrcMask);
	CsImportIp(f, a->IsIPv6 ? "DestIpAddress6" : "DestIpAddress", a->IsIPv6, a->Dst);
	CsImportIp(f, a->IsIPv6 ? "DestSubnetMask6" : "DestSubnetMask", a->IsIPv6, a->DstMask);

	a->Protocol = CfgGetInt(f, "Protocol");
	a->SrcPortStart = CfgGetInt(f, "SrcPortStart");
	a->SrcPortEnd = CfgGetInt(f, "SrcPortEnd");
	a->DstPortStart = CfgGetInt(f, "DestPortStart");
	a->DstPortEnd = CfgGetInt(f, "DestPortEnd");

	// A range with a first port ends at it at least
	if (a->SrcPortStart != 0)
		a->SrcPortEnd = MAX(a->SrcPortEnd, a->SrcPortStart);

	if (a->DstPortStart != 0)
		a->DstPortEnd = MAX(a->DstPortEnd, a->DstPortStart);

	CfgGetStr(f, "SrcUsername", a->SrcUser, sizeof(a->SrcUser));
	CfgGetStr(f, "DestUsername", a->DstUser, sizeof(a->DstUser));

	a->CheckSrcMac = (CfgGetBool(f, "CheckSrcMac") && CsImportMac(f, "SrcMacAddress") && CsImportMac(f, "SrcMacMask"));
	a->CheckDstMac = (CfgGetBool(f, "CheckDstMac") && CsImportMac(f, "DstMacAddress") && CsImportMac(f, "DstMacMask"));
	a->CheckTcpState = CfgGetBool(f, "CheckTcpState");
	a->Effects = (CfgGetInt(f, "Delay") != 0 || CfgGetInt(f, "Jitter") != 0 || CfgGetInt(f, "Loss") != 0);
	a->Redirect = (CfgGetStr(f, "RedirectUrl", tmp, sizeof(tmp)) && IsEmptyStr(tmp) == false);
}

// The order of the fork's access list (CmpAccessList of HubTable.c): by priority, a pass entry before a discard entry
// of the same priority, then in the order of the folder, which leaves the verdicts as they are: two entries of one
// priority and one action give the same verdict whichever comes first
static int CsImportCompareAccess(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL)
		return 0;

	CS_IMPORT_ACCESS *a1 = *(CS_IMPORT_ACCESS **)p1;
	CS_IMPORT_ACCESS *a2 = *(CS_IMPORT_ACCESS **)p2;

	if (a1->Priority != a2->Priority)
		return (a1->Priority > a2->Priority ? 1 : -1);

	if (a1->Discard != a2->Discard)
		return (a1->Discard ? 1 : -1);

	if (a1->Index != a2->Index)
		return (a1->Index > a2->Index ? 1 : -1);

	return 0;
}

// The name that the user item src of an entry (SrcUsername, DestUsername) matches, as the fork matches it
// (MakeSimpleUsernameRemoveNtDomain and UsernameToInt64 of Hub.c): what comes before an '@', the part after a domain
// and its '\', without spaces at either end; empty for none. *file: an include: or exclude: list of a file of users.
static void CsImportAclName(char *dst, UINT size, char *src, bool *file) {
	char tmp[MAX_SIZE];

	StrCpy(dst, size, "");
	*file = (StartWith(src, CS_IMPORT_INCLUDE) || StartWith(src, CS_IMPORT_EXCLUDE));
	if (*file || IsEmptyStr(src))
		return;

	StrCpy(tmp, sizeof(tmp), src);

	char *at = strchr(tmp, '@');
	if (at != NULL)
		*at = 0;

	char *name = tmp;
	char *domain = strchr(tmp, '\\');
	if (domain != NULL) {
		name = domain + 1;

		char *end = strchr(name, '\\');
		if (end != NULL)
			*end = 0;
	}

	StrCpy(dst, size, name);
	Trim(dst);
}

// Whether name is a name that the policy engine holds for a user or a group: 1 to CS_MAX_VALUE_LEN printable characters
// other than a space (PolicyNameOk of Core/PolicyRules.c)
static bool CsImportIdentityOk(char *name) {
	UINT len = StrLen(name);
	if (len == 0 || len > CS_MAX_VALUE_LEN)
		return false;

	for (UINT i = 0; i < len; i++) {
		UCHAR c = (UCHAR)name[i];

		if (c <= ' ' || c > '~')
			return false;
	}

	return true;
}

// The address match of one side of an entry, of its address addr and its mask: false when the side has none, as the
// fork skips a side whose address and mask are both 0. Else the text of the prefix of the leading ones of the mask in
// text, and *exact false when the mask is no prefix, so that the prefix holds more addresses than the mask matches.
static bool CsImportPrefix(UCHAR *addr, UCHAR *mask, bool ipv6, char *text, UINT size, bool *exact) {
	UCHAR prefix[16];
	char tmp[MAX_SIZE];
	UINT bytes = (ipv6 ? 16 : 4);
	UINT len = 0;
	bool zero = false;

	*exact = true;
	StrCpy(text, size, "");

	if (IsZero(addr, bytes) && IsZero(mask, bytes))
		return false;

	for (UINT i = 0; i < bytes * 8; i++) {
		if (((mask[i / 8] >> (7 - i % 8)) & 1) == 0)
			zero = true;
		else if (zero)
			*exact = false;
		else
			len++;
	}

	Zero(prefix, sizeof(prefix));
	for (UINT i = 0; i < bytes; i++) {
		UINT bits = (len > i * 8 ? len - i * 8 : 0);

		prefix[i] = (UCHAR)(bits >= 8 ? addr[i] : (addr[i] & (0xFF << (8 - bits)) & 0xFF));
	}

	if (InetNtopA(ipv6 ? AF_INET6 : AF_INET, prefix, tmp, sizeof(tmp)) == NULL)
		StrCpy(tmp, sizeof(tmp), ipv6 ? "::" : "0.0.0.0");

	Format(text, size, "%s/%u", tmp, len);

	return true;
}

// Add what the policy engine has no match for to the list text
static void CsImportLack(char *text, UINT size, char *what) {
	if (IsEmptyStr(text) == false)
		StrCat(text, size, ", ");

	StrCat(text, size, what);
}

// The lists of one end (from, else to) that the name of an entry takes into keys: the users, the groups, or both where
// the hub has a user and a group of the name, as the fork matches the name against the user and the group of a
// session; INFINITE for no name. The number of keys.
static UINT CsImportIdentities(CONFIG_STORE *s, CS_IMPORT_HUB *h, char *name, bool from, UINT *keys) {
	CS_USER u;
	CS_GROUP g;
	UINT num = 0;

	if (IsEmptyStr(name)) {
		keys[0] = INFINITE;
		return 1;
	}

	bool user = CsGetUser(s, h->Network, name, &u);
	bool group = CsGetGroup(s, h->Network, name, &g);

	if (user || group == false)
		keys[num++] = (from ? CS_KEY_FROM_USERS : CS_KEY_TO_USERS);

	if (group)
		keys[num++] = (from ? CS_KEY_FROM_GROUPS : CS_KEY_TO_GROUPS);

	return num;
}

// The rules of entry a of the access list of the hub h, the n-th in the fork's order, at priority priority (the comment
// of this file). False when the store fails.
static bool CsImportEntry(CONFIG_STORE *s, CS_IMPORT *r, CS_IMPORT_HUB *h, CS_IMPORT_ACCESS *a, UINT n, UINT priority) {
	CS_RULE rule;
	char src_name[MAX_SIZE];
	char dst_name[MAX_SIZE];
	char src_prefix[MAX_SIZE];
	char dst_prefix[MAX_SIZE];
	char ports[MAX_SIZE];
	char lacks[MAX_SIZE];
	wchar_t why[MAX_SIZE * 2];
	bool src_file;
	bool dst_file;
	bool src_exact;
	bool dst_exact;
	UINT src_keys[2];
	UINT dst_keys[2];
	UINT protocols[2];
	UINT num_protocols = 0;
	bool dead = false;

	StrCpy(lacks, sizeof(lacks), "");

	if (a->CheckSrcMac)
		CsImportLack(lacks, sizeof(lacks), "source MAC addresses");

	if (a->CheckDstMac)
		CsImportLack(lacks, sizeof(lacks), "destination MAC addresses");

	if (a->SrcPortStart != 0 || a->SrcPortEnd != 0)
		CsImportLack(lacks, sizeof(lacks), "source ports");

	if (a->CheckTcpState)
		CsImportLack(lacks, sizeof(lacks), "the TCP state");

	// The identities, which the engine matches without case, as the fork does
	CsImportAclName(src_name, sizeof(src_name), a->SrcUser, &src_file);
	CsImportAclName(dst_name, sizeof(dst_name), a->DstUser, &dst_file);

	if (src_file || dst_file)
		CsImportLack(lacks, sizeof(lacks), "user list files");

	if ((IsEmptyStr(src_name) == false && CsImportIdentityOk(src_name) == false) || (IsEmptyStr(dst_name) == false && CsImportIdentityOk(dst_name) == false)) {
		CsImportLack(lacks, sizeof(lacks), "user names that it cannot hold");

		if (CsImportIdentityOk(src_name) == false)
			StrCpy(src_name, sizeof(src_name), "");

		if (CsImportIdentityOk(dst_name) == false)
			StrCpy(dst_name, sizeof(dst_name), "");
	}

	// The addresses
	bool src_addr = CsImportPrefix(a->Src, a->SrcMask, a->IsIPv6, src_prefix, sizeof(src_prefix), &src_exact);
	bool dst_addr = CsImportPrefix(a->Dst, a->DstMask, a->IsIPv6, dst_prefix, sizeof(dst_prefix), &dst_exact);

	if (src_exact == false || dst_exact == false)
		CsImportLack(lacks, sizeof(lacks), "masks that are no prefix");

	// The destination ports: a range the fork never matches makes an entry that matches nothing
	StrCpy(ports, sizeof(ports), "");
	if (a->DstPortStart != 0 || a->DstPortEnd != 0) {
		UINT end = MIN(a->DstPortEnd, 65535);

		if (a->DstPortStart > end)
			dead = true;
		else if (a->DstPortStart == end)
			Format(ports, sizeof(ports), "%u", end);
		else
			Format(ports, sizeof(ports), "%u-%u", a->DstPortStart, end);
	}

	// The protocols: TCP for the TCP state, TCP or UDP for ports, both for ports without a protocol; an entry whose
	// protocol cannot have the TCP state or ports matches nothing
	bool with_ports = (a->SrcPortStart != 0 || a->SrcPortEnd != 0 || a->DstPortStart != 0 || a->DstPortEnd != 0);

	if (a->CheckTcpState) {
		if (a->Protocol == 0 || a->Protocol == CS_PROTO_TCP)
			protocols[num_protocols++] = CS_PROTO_TCP;
		else
			dead = true;
	} else if (with_ports) {
		if (a->Protocol == CS_PROTO_TCP || a->Protocol == CS_PROTO_UDP) {
			protocols[num_protocols++] = a->Protocol;
		} else if (a->Protocol == 0) {
			protocols[num_protocols++] = CS_PROTO_TCP;
			protocols[num_protocols++] = CS_PROTO_UDP;
		} else {
			dead = true;
		}
	} else if (a->Protocol > 255) {
		dead = true;
	} else {
		protocols[num_protocols++] = (a->Protocol == 0 ? CS_PROTO_ANY : a->Protocol);
	}

	if (dead) {
		num_protocols = 0;
		protocols[num_protocols++] = (a->Protocol != 0 && a->Protocol <= 255 ? a->Protocol : CS_PROTO_ANY);
	}

	// An entry of one family: a protocol, ports or the TCP state, which are those of IPv4 or of IPv6
	bool family = (a->Protocol != 0 || with_ports || a->CheckTcpState);

	bool allow = (a->Discard == false && a->Redirect == false);
	bool lack = (IsEmptyStr(lacks) == false);
	bool active = (a->Active && dead == false && (lack == false || allow == false));

	if (a->Active == false)
		UniStrCpy(why, sizeof(why), L", inactive in the fork");
	else if (dead)
		UniStrCpy(why, sizeof(why), L", which matches nothing in the fork");
	else if (lack && allow)
		UniFormat(why, sizeof(why), L", inactive: the policy engine has no match on %S, without which the entry would let more through", lacks);
	else if (lack)
		UniFormat(why, sizeof(why), L", which denies more than the fork did: the policy engine has no match on %S", lacks);
	else
		UniStrCpy(why, sizeof(why), L"");

	if (a->Redirect)
		UniStrCat(why, sizeof(why), L"; a deny entry for its redirect URL, which is left out");
	else if (a->Effects && a->Discard == false)
		UniStrCat(why, sizeof(why), L"; its delay, jitter and loss are left out");

	UINT num_src = CsImportIdentities(s, h, src_name, true, src_keys);
	UINT num_dst = CsImportIdentities(s, h, dst_name, false, dst_keys);
	UINT num_rules = num_src * num_dst * num_protocols;
	UINT num_added = 0;
	UINT k = 0;

	for (UINT i = 0; i < num_src; i++) {
		for (UINT j = 0; j < num_dst; j++) {
			for (UINT p = 0; p < num_protocols; p++) {
				Zero(&rule, sizeof(rule));
				StrCpy(rule.Network, sizeof(rule.Network), h->Network);

				k++;
				if (num_rules == 1)
					Format(rule.Name, sizeof(rule.Name), "%s.acl-%u", h->Prefix, n);
				else
					Format(rule.Name, sizeof(rule.Name), "%s.acl-%u.%u", h->Prefix, n, k);

				rule.Priority = priority;
				rule.Action = (allow ? CS_ALLOW : CS_DENY);
				rule.Protocol = protocols[p];
				rule.Active = active;

				if (UniIsEmptyStr(a->Note))
					UniFormat(rule.Note, sizeof(rule.Note), L"Entry %u of the fork's access list%s", n, why);
				else
					UniFormat(rule.Note, sizeof(rule.Note), L"Entry %u of the fork's access list%s (its note: %s)", n, why, a->Note);

				if (src_keys[i] != INFINITE)
					CsAddRuleValue(&rule, src_keys[i], src_name);

				if (src_addr)
					CsAddRuleValue(&rule, CS_KEY_FROM_ADDRESSES, src_prefix);
				else if (family && dst_addr == false)
					CsAddRuleValue(&rule, CS_KEY_FROM_ADDRESSES, a->IsIPv6 ? "::/0" : "0.0.0.0/0");

				if (dst_keys[j] != INFINITE)
					CsAddRuleValue(&rule, dst_keys[j], dst_name);

				if (dst_addr)
					CsAddRuleValue(&rule, CS_KEY_TO_ADDRESSES, dst_prefix);

				if (IsEmptyStr(ports) == false && (protocols[p] == CS_PROTO_TCP || protocols[p] == CS_PROTO_UDP))
					CsAddRuleValue(&rule, CS_KEY_PORTS, ports);

				if (CsImportCount(r, CsAddRule(s, &rule), &num_added) == false)
					return false;
			}
		}
	}

	if (num_added == 0)
		return true;

	r->NumEntries++;

	if (active == false)
		r->NumEntriesInactive++;
	else if (lack)
		r->NumEntriesWidened++;

	if (a->Redirect || (a->Effects && a->Discard == false))
		r->NumEffectsDropped++;

	return true;
}

// The access list of the hub folder f as rules of the hub h, in the fork's order, at the fork's priorities when the
// engine takes them all, else at their ranks; then <network>.default-allow, which lets through what no entry matches.
// The fork loads MAX_ACCESSLISTS entries of a hub at most. False when the store fails.
static bool CsImportAccessList(CONFIG_STORE *s, CS_IMPORT *r, CS_IMPORT_HUB *h, FOLDER *f) {
	CS_RULE rule;
	FOLDER *acl = CfgFindFolder(f, "AccessList");
	TOKEN_LIST *t = CfgEnumFolderToTokenList(acl);
	LIST *o = NewListFast(CsImportCompareAccess);
	bool ranks = false;
	bool ok = true;
	UINT rank = 0;
	UINT num_default = 0;

	for (UINT i = 0; t != NULL && i < t->NumTokens && LIST_NUM(o) < MAX_ACCESSLISTS; i++) {
		CS_IMPORT_ACCESS *a = Malloc(sizeof(CS_IMPORT_ACCESS));

		CsImportReadAccess(CfgFindFolder(acl, t->Token[i]), i, a);
		Add(o, a);

		if (a->Priority >= CS_MAX_PRIORITY)
			ranks = true;
	}

	FreeToken(t);
	Sort(o);

	for (UINT i = 0; ok && i < LIST_NUM(o); i++) {
		CS_IMPORT_ACCESS *a = LIST_DATA(o, i);

		if (i == 0 || a->Priority != ((CS_IMPORT_ACCESS *)LIST_DATA(o, i - 1))->Priority)
			rank++;

		ok = CsImportEntry(s, r, h, a, i + 1, ranks ? rank : a->Priority);
	}

	for (UINT i = 0; i < LIST_NUM(o); i++)
		Free(LIST_DATA(o, i));

	ReleaseList(o);

	if (ok == false)
		return false;

	Zero(&rule, sizeof(rule));
	StrCpy(rule.Network, sizeof(rule.Network), h->Network);
	Format(rule.Name, sizeof(rule.Name), "%s.default-allow", h->Prefix);
	rule.Priority = CS_MAX_PRIORITY;
	rule.Action = CS_ALLOW;
	rule.Protocol = CS_PROTO_ANY;
	rule.Active = true;
	UniStrCpy(rule.Note, sizeof(rule.Note), L"The default of the fork's access list: a frame that no entry matches passes");

	return CsImportCount(r, CsAddRule(s, &rule), &num_default);
}

// The VLAN settings of the hub folder f: the TPID of its tags (VlanTypeId, 0x8100 without it) and the lowest VLAN that
// no user or group of the hub h has, as its untagged VLAN; and the hub options that the new core does not take
static bool CsImportVlanSettings(CONFIG_STORE *s, CS_IMPORT *r, CS_IMPORT_HUB *h, FOLDER *f) {
	char tmp[MAX_SIZE];
	FOLDER *option = CfgFindFolder(f, "Option");
	UINT tpid = 0;
	UINT untagged = CS_UNTAGGED_VLAN;
	UINT num_settings = 0;

	if (CfgGetStr(option, "VlanTypeId", tmp, sizeof(tmp)))
		tpid = HexToInt(tmp);

	if (tpid == 0)
		tpid = CS_TPID_8021Q;

	while (untagged < 4094 && (h->Vlans[untagged / 8] & (1 << (untagged % 8))) != 0)
		untagged++;

	// The switch of the new core always learns per VLAN, and the policy engine never judges ARP by its rules
	if (CfgGetBool(option, "NoManageVlanId"))
		r->NumOptionsDropped++;

	if (CfgGetBool(option, "ApplyIPv4AccessListOnArpPacket"))
		r->NumOptionsDropped++;

	return CsImportCount(r, CsSetNetworkVlans(s, h->Network, tpid, untagged), &num_settings);
}

// One hub folder of VirtualHUB: the network, its CAs, its groups and users, its administrator and its policy
static bool CsImportHub(CONFIG_STORE *s, CS_IMPORT *r, FOLDER *f) {
	char admin[MAX_SIZE];
	CS_IMPORT_HUB h;
	if (f == NULL)
		return true;

	char *name = f->Name;

	UINT num_networks = r->NumNetworks;
	if (CsImportCount(r, CsAddNetwork(s, name, CS_MODE_L2, CfgGetBool(f, "Online")), &r->NumNetworks) == false)
		return false;

	if (r->NumNetworks == num_networks)
		return true;

	Zero(&h, sizeof(h));
	h.Network = name;
	if (CsPolicyNetworkName(s, name, h.Prefix, sizeof(h.Prefix)) == false)
		return false;

	FOLDER *db = CfgFindFolder(f, "SecurityAccountDatabase");

	if (CsImportCertList(s, r, CS_CERT_CA, name, CfgFindFolder(db, "CertList")) == false)
		return false;

	// The groups before the users, as the fork loads them
	FOLDER *groups = CfgFindFolder(db, "GroupList");
	TOKEN_LIST *t = CfgEnumFolderToTokenList(groups);
	bool ok = true;

	for (UINT i = 0; ok && t != NULL && i < t->NumTokens; i++)
		ok = CsImportGroup(s, r, &h, CfgFindFolder(groups, t->Token[i]));

	FreeToken(t);

	FOLDER *users = CfgFindFolder(db, "UserList");
	t = CfgEnumFolderToTokenList(users);

	for (UINT i = 0; ok && t != NULL && i < t->NumTokens; i++)
		ok = CsImportUser(s, r, &h, CfgFindFolder(users, t->Token[i]));

	FreeToken(t);

	if (ok == false || CsImportVlanSettings(s, r, &h, f) == false || CsImportAccessList(s, r, &h, f) == false)
		return false;

	// The hub administrator of the fork logs in as "administrator" on its hub; a named account takes the hub name
	if (CsImportHasPassword(f, "HashedPassword")) {
		Format(admin, sizeof(admin), "%s@%s", ADMINISTRATOR_USERNAME, name);

		UINT num_admins = r->NumAdmins;
		if (CsImportCount(r, CsAddAdmin(s, admin, CS_ROLE_HUB_ADMIN, name, NULL), &r->NumAdmins) == false)
			return false;

		if (r->NumAdmins != num_admins)
			r->NumPasswordsDropped++;
	}

	return true;
}

// The listener folders of ListenerList (Listener0, Listener1, ...): each TCP port becomes a TLS listener
static bool CsImportListeners(CONFIG_STORE *s, CS_IMPORT *r, FOLDER *f) {
	bool ok = true;

	TOKEN_LIST *t = CfgEnumFolderToTokenList(f);

	for (UINT i = 0; ok && t != NULL && i < t->NumTokens; i++) {
		FOLDER *ff = CfgFindFolder(f, t->Token[i]);
		UINT port = CfgGetInt(ff, "Port");

		// The fork skips a listener without a port as well
		if (port != 0)
			ok = CsImportCount(r, CsAddListener(s, CS_TRANSPORT_TLS, port, CfgGetBool(ff, "Enabled")), &r->NumListeners);
	}

	FreeToken(t);

	return ok;
}

// ServerConfiguration: the server certificate and its chain, and the server administrator as the owner account
static bool CsImportServer(CONFIG_STORE *s, CS_IMPORT *r, FOLDER *f) {
	if (CsImportCert(s, r, CS_CERT_SERVER, NULL, NULL, f, "ServerCert") == false)
		return false;

	if (CsImportCertList(s, r, CS_CERT_CHAIN, NULL, CfgFindFolder(f, "ServerChain")) == false)
		return false;

	r->ServerKeyDropped = CfgIsItem(f, "ServerKey");

	UINT num_admins = r->NumAdmins;
	if (CsImportCount(r, CsAddAdmin(s, ADMINISTRATOR_USERNAME, CS_ROLE_OWNER, NULL, NULL), &r->NumAdmins) == false)
		return false;

	if (r->NumAdmins != num_admins && CsImportHasPassword(f, "HashedPassword"))
		r->NumPasswordsDropped++;

	return true;
}

// The file name of a path, as UTF-8; the caller frees it
static char *CsImportFileName(wchar_t *path) {
	UINT start = 0;

	for (UINT i = 0; path[i] != 0; i++)
		if (path[i] == L'\\' || path[i] == L'/')
			start = i + 1;

	UINT size = CalcUniToUtf8(path + start) + 1;
	char *ret = ZeroMalloc(size);
	UniToUtf8(ret, size, path + start);

	return ret;
}

// Import the fork's Config file path into the store s, which must be empty (CsIsEmpty), in one transaction, and
// record the file name in the setting CS_SETTING_IMPORTED. What was carried and what was left out goes to ret.
// ERR_OBJECT_NOT_FOUND when the file does not exist, ERR_INVALID_PARAMETER when it is no fork configuration (no
// ServerConfiguration folder, as the fork's own start requires), ERR_OBJECT_EXISTS when the store is not empty,
// ERR_INTERNAL_ERROR when the store fails; the store is unchanged after an error.
UINT CsImportForkConfig(CONFIG_STORE *s, wchar_t *path, CS_IMPORT *ret) {
	CS_IMPORT r;
	UINT err = ERR_INTERNAL_ERROR;

	Zero(&r, sizeof(r));

	if (ret != NULL)
		Zero(ret, sizeof(CS_IMPORT));

	if (s == NULL || UniIsEmptyStr(path))
		return ERR_INVALID_PARAMETER;

	if (IsFileExistsW(path) == false)
		return ERR_OBJECT_NOT_FOUND;

	FOLDER *root = CfgReadW(path);
	FOLDER *server = CfgFindFolder(root, "ServerConfiguration");

	if (server == NULL) {
		CfgDeleteFolder(root);
		return ERR_INVALID_PARAMETER;
	}

	Lock(s->Lock);
	{
		if (CsIsEmpty(s) == false) {
			err = ERR_OBJECT_EXISTS;
		} else if (CsBegin(s)) {
			FOLDER *hubs = CfgFindFolder(root, "VirtualHUB");
			TOKEN_LIST *t = CfgEnumFolderToTokenList(hubs);
			bool ok = true;

			for (UINT i = 0; ok && t != NULL && i < t->NumTokens; i++)
				ok = CsImportHub(s, &r, CfgFindFolder(hubs, t->Token[i]));

			FreeToken(t);

			if (ok)
				ok = CsImportListeners(s, &r, CfgFindFolder(root, "ListenerList"));

			if (ok)
				ok = CsImportServer(s, &r, server);

			if (ok) {
				char *name = CsImportFileName(path);
				ok = (CsSetSetting(s, CS_SETTING_IMPORTED, name) == ERR_NO_ERROR);
				Free(name);
			}

			if (ok && CsCommit(s)) {
				err = ERR_NO_ERROR;
			} else {
				if (ok)
					Debug("ConfigStore: the import of %S did not commit\n", path);
				else
					CsRollback(s);

				Zero(&r, sizeof(r));
			}
		}
	}
	Unlock(s->Lock);

	CfgDeleteFolder(root);

	if (ret != NULL)
		Copy(ret, &r, sizeof(CS_IMPORT));

	return err;
}
