// harness_pack.c
// Pack golden outputs of every admin RPC structure for the vpntest "harness" test
//
// Design notes:
// - The current marshal code (InRpc*, OutRpc*, FreeRpc*) is the oracle: every admin RPC wire type is
//   recorded as its serialised Pack plus an In/Out/In/Out round trip, so a rewrite of that code must
//   reproduce the same bytes (spec #28). Nested structures are covered through their parents.
// - Case kinds: SYN (zero structure plus a Prep that sets counts, items, pointers and discriminators,
//   serialised by OutRpc*), LIVE (read-only admin RPC on the running scenario: the server's response Pack,
//   volatile values masked), IN (hand-built request Pack for a read path that the Out side never produces).
// - Element order: every PackAdd* call and every lookup sorts the element list, then an add appends. A Pack
//   is dumped before any lookup on it, so a dump shows the order that WritePack writes (the error of a LIVE
//   response is found by a linear scan for that reason).
// - pack_<Name>.pack is the round-trip input: the canonicalised Pack (values rewritten from the element name
//   and the value index only, see HarnessPackCanon) or the IN case's hand-built Pack. In compare mode the
//   committed file is the input, so a change of the Out side and a change of the In side show separately.
// - pack_<Name>.txt sections: [out] (list order, one line per element, then the size and SHA-1 of the
//   serialised Pack), [in-out] (In of the input, then Out, full dump), [in-out-in-out] ("same" when a second
//   round trip gives the same bytes, else its full dump). Every structure and Pack is freed: the process-wide
//   NO MEMORY LEAKS check covers the FreeRpc* side.
// - Golden family "pack": tests/golden/pack (sibling of the harness golden directory), output directory
//   <harness output directory>/pack, mode line "HARNESS GOLDEN MODE pack update|compare".

#include "harness_int.h"

#include "Cedar/Account.h"
#include "Cedar/Admin.h"
#include "Cedar/Cedar.h"
#include "Cedar/Connection.h"
#include "Cedar/Hub.h"
#include "Cedar/Server.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

// Case kinds
#define	HARNESS_PACK_SYN			0					// Synthetic structure serialised by OutRpc*
#define	HARNESS_PACK_LIVE			1					// Response of a read-only admin RPC on the scenario
#define	HARNESS_PACK_IN				2					// Hand-built request Pack (read side only)

#define	HARNESS_PACK_HEX_MAX		64					// Larger data values are dumped as size and SHA-1
#define	HARNESS_PACK_TAG_MASKED		"<masked>"			// Volatile value of a LIVE response

// Typed adapters of one wire type (no call through a mistyped function pointer)
typedef struct HARNESS_PACK_TYPE
{
	char *TypeName;					// "RPC_ENUM_HUB"
	UINT Size;						// sizeof the structure
	void (*In)(void *t, PACK *p);	// InRpc*
	void (*Out)(PACK *p, void *t);	// OutRpc*
	void (*Free)(void *t);			// FreeRpc*; NULL when the type has none (DECLARE_RPC)
} HARNESS_PACK_TYPE;

// One golden case: pack_<Name>.txt and pack_<Name>.pack
typedef struct HARNESS_PACK_CASE
{
	char *Name;						// File stem
	HARNESS_PACK_TYPE *Type;
	UINT Kind;						// HARNESS_PACK_SYN, HARNESS_PACK_LIVE or HARNESS_PACK_IN
	void (*Prep)(HARNESS *h, void *t);	// SYN: counts, items, pointers, discriminators; LIVE: request fields
	char *RpcName;					// LIVE: admin RPC name for AdminCall (also the RPCs without a Sc* stub)
	PACK *(*Build)(void);			// IN: hand-built input Pack
	char *Masks;					// LIVE: masked keys of this case besides the common list
} HARNESS_PACK_CASE;

// State of the Pack golden phase
typedef struct HARNESS_PACK_RUN
{
	HARNESS *H;
	char OutDir[MAX_SIZE];
	char GoldenDir[MAX_SIZE];
	bool Update;
	BUF *CertDer;					// Fixed test certificate (DER), value of the certificate keys
	BUF *KeyDer;					// Fixed test key (DER), value of the key keys
} HARNESS_PACK_RUN;

static void HarnessPackFreeStruct(HARNESS_PACK_TYPE *y, void *t);
static X *HarnessTestCert();
static K *HarnessTestKey();
static void HarnessPackIp6(IP *ip, UCHAR last);
static void HarnessPackPut(BUF *b, char *s);
static void HarnessPackPutHex(BUF *b, void *data, UINT size);
static void HarnessPackPutSha1(BUF *b, void *data, UINT size);
static void HarnessPackPutStr(BUF *b, char *s);
static char *HarnessPackTypeName(UINT type);
static bool HarnessPackNameInList(char *name, char *list);
static bool HarnessPackIsMasked(HARNESS_PACK_CASE *c, ELEMENT *e);
static void HarnessPackDump(BUF *b, PACK *p, HARNESS_PACK_CASE *c);
static void HarnessPackPutBytes(BUF *b, PACK *p, bool masked);
static UINT HarnessPackHash(char *s);
static bool HarnessPackIsKept(char *name, bool live);
static void HarnessPackCanonData(HARNESS_PACK_RUN *r, ELEMENT *e, UINT h, UINT index, VALUE *v);
static void HarnessPackCanon(HARNESS_PACK_RUN *r, PACK *p, bool live);
static UINT HarnessPackGetError(PACK *p);
static BUF *HarnessCompareGoldenBin(HARNESS *h, char *out_dir, char *golden_dir, char *file_name, BUF *actual, bool update);
static void HarnessPackRoundTrip(BUF *text, HARNESS_PACK_TYPE *y, BUF *input);
static void HarnessPackRunCase(HARNESS_PACK_RUN *r, HARNESS_PACK_CASE *c);
static void HarnessCheckStalePack(HARNESS *h, char *golden_dir);

////////////////////////////
// Wire types

#define	HARNESS_PACK_TYPE_DEF(type, in_rpc, out_rpc, free_rpc)								\
	static void HarnessPackIn_##type(void *t, PACK *p) { in_rpc((type *)t, p); }			\
	static void HarnessPackOut_##type(PACK *p, void *t) { out_rpc(p, (type *)t); }			\
	static void HarnessPackFree_##type(void *t) { free_rpc((type *)t); }					\
	static HARNESS_PACK_TYPE harness_pack_type_##type =										\
		{#type, sizeof(type), HarnessPackIn_##type, HarnessPackOut_##type, HarnessPackFree_##type};
#define	HARNESS_PACK_TYPE_DEF_NOFREE(type, in_rpc, out_rpc)									\
	static void HarnessPackIn_##type(void *t, PACK *p) { in_rpc((type *)t, p); }			\
	static void HarnessPackOut_##type(PACK *p, void *t) { out_rpc(p, (type *)t); }			\
	static HARNESS_PACK_TYPE harness_pack_type_##type =										\
		{#type, sizeof(type), HarnessPackIn_##type, HarnessPackOut_##type, NULL};

// The 57 wire types of the admin RPC dispatch table (Admin.c), RPC_WINVER excepted (login handshake)
HARNESS_PACK_TYPE_DEF(RPC_TEST, InRpcTest, OutRpcTest, FreeRpcTest)
HARNESS_PACK_TYPE_DEF(RPC_SERVER_INFO, InRpcServerInfo, OutRpcServerInfo, FreeRpcServerInfo)
HARNESS_PACK_TYPE_DEF_NOFREE(RPC_SERVER_STATUS, InRpcServerStatus, OutRpcServerStatus)
HARNESS_PACK_TYPE_DEF_NOFREE(RPC_LISTENER, InRpcListener, OutRpcListener)
HARNESS_PACK_TYPE_DEF(RPC_LISTENER_LIST, InRpcListenerList, OutRpcListenerList, FreeRpcListenerList)
HARNESS_PACK_TYPE_DEF_NOFREE(RPC_SET_PASSWORD, InRpcSetPassword, OutRpcSetPassword)
HARNESS_PACK_TYPE_DEF(RPC_KEY_PAIR, InRpcKeyPair, OutRpcKeyPair, FreeRpcKeyPair)
HARNESS_PACK_TYPE_DEF(RPC_STR, InRpcStr, OutRpcStr, FreeRpcStr)
HARNESS_PACK_TYPE_DEF_NOFREE(RPC_CREATE_HUB, InRpcCreateHub, OutRpcCreateHub)
HARNESS_PACK_TYPE_DEF(RPC_ENUM_HUB, InRpcEnumHub, OutRpcEnumHub, FreeRpcEnumHub)
HARNESS_PACK_TYPE_DEF_NOFREE(RPC_DELETE_HUB, InRpcDeleteHub, OutRpcDeleteHub)
HARNESS_PACK_TYPE_DEF(RPC_ENUM_CONNECTION, InRpcEnumConnection, OutRpcEnumConnection, FreeRpcEnumConnection)
HARNESS_PACK_TYPE_DEF_NOFREE(RPC_DISCONNECT_CONNECTION, InRpcDisconnectConnection, OutRpcDisconnectConnection)
HARNESS_PACK_TYPE_DEF_NOFREE(RPC_CONNECTION_INFO, InRpcConnectionInfo, OutRpcConnectionInfo)
HARNESS_PACK_TYPE_DEF_NOFREE(RPC_SET_HUB_ONLINE, InRpcSetHubOnline, OutRpcSetHubOnline)
HARNESS_PACK_TYPE_DEF_NOFREE(RPC_HUB_STATUS, InRpcHubStatus, OutRpcHubStatus)
HARNESS_PACK_TYPE_DEF_NOFREE(RPC_HUB_LOG, InRpcHubLog, OutRpcHubLog)
HARNESS_PACK_TYPE_DEF(RPC_HUB_ADD_CA, InRpcHubAddCa, OutRpcHubAddCa, FreeRpcHubAddCa)
HARNESS_PACK_TYPE_DEF(RPC_HUB_ENUM_CA, InRpcHubEnumCa, OutRpcHubEnumCa, FreeRpcHubEnumCa)
HARNESS_PACK_TYPE_DEF(RPC_HUB_GET_CA, InRpcHubGetCa, OutRpcHubGetCa, FreeRpcHubGetCa)
HARNESS_PACK_TYPE_DEF_NOFREE(RPC_HUB_DELETE_CA, InRpcHubDeleteCa, OutRpcHubDeleteCa)
HARNESS_PACK_TYPE_DEF_NOFREE(RPC_LINK, InRpcLink, OutRpcLink)
HARNESS_PACK_TYPE_DEF_NOFREE(RPC_RENAME_LINK, InRpcRenameLink, OutRpcRenameLink)
HARNESS_PACK_TYPE_DEF(RPC_CREATE_LINK, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
HARNESS_PACK_TYPE_DEF(RPC_ENUM_LINK, InRpcEnumLink, OutRpcEnumLink, FreeRpcEnumLink)
HARNESS_PACK_TYPE_DEF(RPC_LINK_STATUS, InRpcLinkStatus, OutRpcLinkStatus, FreeRpcLinkStatus)
HARNESS_PACK_TYPE_DEF_NOFREE(RPC_ADD_ACCESS, InRpcAddAccess, OutRpcAddAccess)
HARNESS_PACK_TYPE_DEF_NOFREE(RPC_DELETE_ACCESS, InRpcDeleteAccess, OutRpcDeleteAccess)
HARNESS_PACK_TYPE_DEF(RPC_ENUM_ACCESS_LIST, InRpcEnumAccessList, OutRpcEnumAccessList, FreeRpcEnumAccessList)
HARNESS_PACK_TYPE_DEF(RPC_SET_USER, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
HARNESS_PACK_TYPE_DEF_NOFREE(RPC_DELETE_USER, InRpcDeleteUser, OutRpcDeleteUser)
HARNESS_PACK_TYPE_DEF(RPC_ENUM_USER, InRpcEnumUser, OutRpcEnumUser, FreeRpcEnumUser)
HARNESS_PACK_TYPE_DEF(RPC_SET_GROUP, InRpcSetGroup, OutRpcSetGroup, FreeRpcSetGroup)
HARNESS_PACK_TYPE_DEF(RPC_ENUM_GROUP, InRpcEnumGroup, OutRpcEnumGroup, FreeRpcEnumGroup)
HARNESS_PACK_TYPE_DEF(RPC_ENUM_SESSION, InRpcEnumSession, OutRpcEnumSession, FreeRpcEnumSession)
HARNESS_PACK_TYPE_DEF(RPC_SESSION_STATUS, InRpcSessionStatus, OutRpcSessionStatus, FreeRpcSessionStatus)
HARNESS_PACK_TYPE_DEF_NOFREE(RPC_DELETE_SESSION, InRpcDeleteSession, OutRpcDeleteSession)
HARNESS_PACK_TYPE_DEF(RPC_ENUM_MAC_TABLE, InRpcEnumMacTable, OutRpcEnumMacTable, FreeRpcEnumMacTable)
HARNESS_PACK_TYPE_DEF_NOFREE(RPC_DELETE_TABLE, InRpcDeleteTable, OutRpcDeleteTable)
HARNESS_PACK_TYPE_DEF(RPC_ENUM_IP_TABLE, InRpcEnumIpTable, OutRpcEnumIpTable, FreeRpcEnumIpTable)
HARNESS_PACK_TYPE_DEF(RPC_ENUM_ETH, InRpcEnumEth, OutRpcEnumEth, FreeRpcEnumEth)
HARNESS_PACK_TYPE_DEF_NOFREE(RPC_LOCALBRIDGE, InRpcLocalBridge, OutRpcLocalBridge)
HARNESS_PACK_TYPE_DEF(RPC_ENUM_LOCALBRIDGE, InRpcEnumLocalBridge, OutRpcEnumLocalBridge, FreeRpcEnumLocalBridge)
HARNESS_PACK_TYPE_DEF_NOFREE(RPC_BRIDGE_SUPPORT, InRpcBridgeSupport, OutRpcBridgeSupport)
HARNESS_PACK_TYPE_DEF(CAPSLIST, InRpcCapsList, OutRpcCapsList, FreeRpcCapsList)
HARNESS_PACK_TYPE_DEF(RPC_CONFIG, InRpcConfig, OutRpcConfig, FreeRpcConfig)
HARNESS_PACK_TYPE_DEF(RPC_ADMIN_OPTION, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
HARNESS_PACK_TYPE_DEF(RPC_ENUM_CRL, InRpcEnumCrl, OutRpcEnumCrl, FreeRpcEnumCrl)
HARNESS_PACK_TYPE_DEF(RPC_CRL, InRpcCrl, OutRpcCrl, FreeRpcCrl)
HARNESS_PACK_TYPE_DEF(RPC_AC_LIST, InRpcAcList, OutRpcAcList, FreeRpcAcList)
HARNESS_PACK_TYPE_DEF(RPC_ENUM_LOG_FILE, InRpcEnumLogFile, OutRpcEnumLogFile, FreeRpcEnumLogFile)
HARNESS_PACK_TYPE_DEF(RPC_READ_LOG_FILE, InRpcReadLogFile, OutRpcReadLogFile, FreeRpcReadLogFile)
HARNESS_PACK_TYPE_DEF(RPC_ENUM_LICENSE_KEY, InRpcEnumLicenseKey, OutRpcEnumLicenseKey, FreeRpcEnumLicenseKey)
HARNESS_PACK_TYPE_DEF_NOFREE(RPC_LICENSE_STATUS, InRpcLicenseStatus, OutRpcLicenseStatus)
HARNESS_PACK_TYPE_DEF_NOFREE(SYSLOG_SETTING, InRpcSysLogSetting, OutRpcSysLogSetting)
HARNESS_PACK_TYPE_DEF(RPC_ENUM_ETH_VLAN, InRpcEnumEthVLan, OutRpcEnumEthVLan, FreeRpcEnumEthVLan)
HARNESS_PACK_TYPE_DEF(RPC_MSG, InRpcMsg, OutRpcMsg, FreeRpcMsg)

// Release a structure through its FreeRpc* (when the type has one), then its memory
static void HarnessPackFreeStruct(HARNESS_PACK_TYPE *y, void *t)
{
	if (t == NULL)
	{
		return;
	}

	if (y->Free != NULL)
	{
		y->Free(t);
	}

	Free(t);
}

////////////////////////////
// Fixed test material

// Self-signed RSA-2048 test certificate and its key, generated once with openssl
// (CN=Ranz harness test, O=Ranz harness, serial 0x52414E5A, SHA-256, valid 2026-10-13 to 2046-10-08)
static char *harness_pack_test_cert_pem =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDNzCCAh+gAwIBAgIEUkFOWjANBgkqhkiG9w0BAQsFADAzMRowGAYDVQQDDBFS\n"
	"YW56IGhhcm5lc3MgdGVzdDEVMBMGA1UECgwMUmFueiBoYXJuZXNzMB4XDTI2MTAx\n"
	"MzA1NDUzNVoXDTQ2MTAwODA1NDUzNVowMzEaMBgGA1UEAwwRUmFueiBoYXJuZXNz\n"
	"IHRlc3QxFTATBgNVBAoMDFJhbnogaGFybmVzczCCASIwDQYJKoZIhvcNAQEBBQAD\n"
	"ggEPADCCAQoCggEBAIbukM+LSrITzMjeVnBztMcFa7yO6RZZfC4umCkWO8+z8Adp\n"
	"StTrlluNEreAeFSO4LsK3zR8HaQzHGpxSBMVyW3Bps1WFbrlc+eURu5LoOsgkFvF\n"
	"xgmwWQvWG+MAzNqfaOOYnJt0WYTy0Up4ie+En5QQFGj7YiGeG9l9aArEeTevnX5I\n"
	"aRJpDcAFnrDw5EdQiYEk+FtZ+OsDqqv3/IRunTBqPJPEGiOntqFLW1srSfbD+vFp\n"
	"NsWtXjQ7XYpf8XjBUicgx3dIjdyQuwXpdO1GTX9ZG5K8Yy6NgXiNS6gFpGd4PwW2\n"
	"22FLEl2iIMlVVTUmPYSd6ybZzoBiFRMxU4lV78MCAwEAAaNTMFEwHQYDVR0OBBYE\n"
	"FBYQUMYHJMCpsVoH0Ok9jQPqSYeLMB8GA1UdIwQYMBaAFBYQUMYHJMCpsVoH0Ok9\n"
	"jQPqSYeLMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAALrK+lV\n"
	"hcPJCdiCV96TIZkLcnH+PlR1M+jGV9KsyB5uRowTiZY/ZPHXpBNRTxFDK/KWrmQL\n"
	"XAg0jQf13snwjNF1dVxog+Dgc+TdIsmmzmF9dZEIO5dmsH9AE7bs0l4xr9S2rior\n"
	"QXs83IHDZSc+haiil4MH1IGwH1VzChEQDVo/9o062B6FJpbwupV+LHDFyzDOXh6o\n"
	"WGvTF00An7GzKuCjvm/PGm+/TNxvDnRplfunLousktHIKIDGdjpvRvhhexX8c5fp\n"
	"XYHJdrkJSwozzLzpQbAFnWIbd3v5f4ExGpz9cH5hBodoCBBeYXj14l6zDAHcxawI\n"
	"q1jNJQdqcOmhwxw=\n"
	"-----END CERTIFICATE-----\n";

static char *harness_pack_test_key_pem =
	"-----BEGIN PRIVATE KEY-----\n"
	"MIIEugIBADANBgkqhkiG9w0BAQEFAASCBKQwggSgAgEAAoIBAQCG7pDPi0qyE8zI\n"
	"3lZwc7THBWu8jukWWXwuLpgpFjvPs/AHaUrU65ZbjRK3gHhUjuC7Ct80fB2kMxxq\n"
	"cUgTFcltwabNVhW65XPnlEbuS6DrIJBbxcYJsFkL1hvjAMzan2jjmJybdFmE8tFK\n"
	"eInvhJ+UEBRo+2IhnhvZfWgKxHk3r51+SGkSaQ3ABZ6w8ORHUImBJPhbWfjrA6qr\n"
	"9/yEbp0wajyTxBojp7ahS1tbK0n2w/rxaTbFrV40O12KX/F4wVInIMd3SI3ckLsF\n"
	"6XTtRk1/WRuSvGMujYF4jUuoBaRneD8FttthSxJdoiDJVVU1Jj2Enesm2c6AYhUT\n"
	"MVOJVe/DAgMBAAECggEAH7jTe6+sKmyEPw8idEKHlCiemRBiFRqJmtPievpaqmyL\n"
	"uDpVWPRf/3sNlO2TnJGQnPij3BN35oQLoKysPKxpFDAsVmbwKeXK131hJaHLHawk\n"
	"tCatddarQKCgIsCr6JQElUlqPBPg/eQWNzNafmCIIceb/Mho3C1vL7UPckSZmPEN\n"
	"qocisnCSN+IbONN4hhm/oyOyqwAgV5hhXYWtEPeU3dpaOffknmx6xgUQiS7KagGy\n"
	"9aYHDu2DWRfNQhijB/bmcfxlWTMVixK/o38AM+4CtB+1zQPlb5TIiNI9V1ZkEEr1\n"
	"6Mkqg/iOCO9Vwlpku3yxfln+4Xwjvet8QLbLaFb8QQKBgQC6DLxEgmkTNNeWGkiK\n"
	"COBc134D1tOaX+ps3Bh8J3XTCDU+J3gmNk5ufmwpcAbUQzgDxNMAoD0g2ophmSvG\n"
	"DjylDHfNKdM65wdpKM3qOWaKlavxVHgtww4ZGQI6AVykBtjgqEKe+zorZPT9B97u\n"
	"pfZ6UgkmYBT5uum+7Oben477wQKBgQC5qb5d+bGPatlxgcCdAuBMe5sLkW4Y1Iry\n"
	"5TK1lF1fgS/AGiHSxj44c47xNuk3Y5vVbDk4ez80D4bKx34sBVczn5XBsVV6EaLl\n"
	"Ptpdc7oqxdBS/yzILL8VeDIdx2WPygmtm4kqixVuB2ZONGNMyF6LC6S1CKXsRc+h\n"
	"Xzjq0CIcgwKBgAV55Hy7ve4Dyyiu4120vy3cZeglBZtwoUzM+aeF3dD1V+PZc47k\n"
	"YFCeRf6+PmU3CUoLHA7TqJjz9cjDomc0+hH9mPUf+wirzisJOW5gfCUuHJ6A1vy5\n"
	"1gtlEgy1B44IaY/LRBK74E1wrklYVvZ9ShD1ozFO+K8VElY9UNpSpfnBAn8GhvEq\n"
	"XJzhbeA3HVioLHG2PqI0xegY91/rKiOePpkJwoDrP//waQfG9EkSMdwBFn9kAWoB\n"
	"klOmgOU8O8czxPxL1FBvfsyCfhw78vm6T1c8KbgpMs9gOjJ9jrw0T85CP9gXQmCQ\n"
	"HlOiiqAOH8ld6a1pNf+UXbl3lPy3r6FQoACTAoGAVhlB/5Pt3H4RAqEDM8jysPxK\n"
	"A2O+6Tou93+O3sNfL1GItBWZDKHTo6qoI1/jSTWwMzABYuNPnOdmUZHpmVpAFva9\n"
	"q+Bxe64/UD78sZ8KcQGdOonzFMt48+/J+jhEeEU3jX/t2brg6tD9BI7jSL+oOYj/\n"
	"U1SK/v+V2y+NykiibNw=\n"
	"-----END PRIVATE KEY-----\n";

// New certificate object of the fixed test certificate
static X *HarnessTestCert()
{
	BUF *b = NewBuf();
	X *x;

	WriteBuf(b, harness_pack_test_cert_pem, StrLen(harness_pack_test_cert_pem));
	SeekBufToBegin(b);
	x = BufToX(b, true);
	FreeBuf(b);

	return x;
}

// New key object of the fixed test key
static K *HarnessTestKey()
{
	BUF *b = NewBuf();
	K *k;

	WriteBuf(b, harness_pack_test_key_pem, StrLen(harness_pack_test_key_pem));
	SeekBufToBegin(b);
	k = BufToK(b, true, true, NULL);
	FreeBuf(b);

	return k;
}

// IPv6 address 2001:db8::<last>
static void HarnessPackIp6(IP *ip, UCHAR last)
{
	UCHAR a[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

	a[15] = last;
	SetIP6(ip, a);
}

////////////////////////////
// Dump

// Append a string
static void HarnessPackPut(BUF *b, char *s)
{
	WriteBuf(b, s, StrLen(s));
}

// Append data as lowercase hexadecimal
static void HarnessPackPutHex(BUF *b, void *data, UINT size)
{
	static char *digits = "0123456789abcdef";
	UCHAR *u = (UCHAR *)data;
	UINT i;

	for (i = 0;i < size;i++)
	{
		char two[2];

		two[0] = digits[(u[i] >> 4) & 0x0F];
		two[1] = digits[u[i] & 0x0F];
		WriteBuf(b, two, 2);
	}
}

// Append the SHA-1 of data in hexadecimal
static void HarnessPackPutSha1(BUF *b, void *data, UINT size)
{
	UCHAR hash[SHA1_SIZE];

	Sha1(hash, data, size);
	HarnessPackPutHex(b, hash, sizeof(hash));
}

// Append a quoted string: \\, \" and \xNN for control and non-ASCII bytes (the file stays ASCII)
static void HarnessPackPutStr(BUF *b, char *s)
{
	UINT i;

	HarnessPackPut(b, "\"");

	for (i = 0;s[i] != 0;i++)
	{
		UCHAR c = (UCHAR)s[i];

		if (c == '\\')
		{
			HarnessPackPut(b, "\\\\");
		}
		else if (c == '"')
		{
			HarnessPackPut(b, "\\\"");
		}
		else if (c < 0x20 || c >= 0x7F)
		{
			HarnessPackPut(b, "\\x");
			HarnessPackPutHex(b, &c, 1);
		}
		else
		{
			WriteBuf(b, &c, 1);
		}
	}

	HarnessPackPut(b, "\"");
}

// Name of a value type
static char *HarnessPackTypeName(UINT type)
{
	switch (type)
	{
	case VALUE_INT:
		return "int";
	case VALUE_INT64:
		return "int64";
	case VALUE_STR:
		return "str";
	case VALUE_UNISTR:
		return "unistr";
	case VALUE_DATA:
		return "data";
	}

	return "unknown";
}

// Whether a name matches a comma-separated list of names ("Prefix*" matches a prefix)
static bool HarnessPackNameInList(char *name, char *list)
{
	char pattern[MAX_ELEMENT_NAME_LEN + 2];
	UINT len, i = 0;

	if (name == NULL || list == NULL)
	{
		return false;
	}

	len = StrLen(list);

	while (i < len)
	{
		UINT n = 0;

		while (i < len && list[i] != ',')
		{
			if (n < (sizeof(pattern) - 1))
			{
				pattern[n++] = list[i];
			}
			i++;
		}
		pattern[n] = 0;
		i++;

		if (n >= 2 && pattern[n - 1] == '*')
		{
			pattern[n - 1] = 0;
			if (StartWith(name, pattern))
			{
				return true;
			}
		}
		else if (n >= 1 && StrCmp(name, pattern) == 0)
		{
			return true;
		}
	}

	return false;
}

// Keys whose values depend on the build, the machine, the time, the traffic or the session numbering:
// masked in the [out] section of every LIVE case, as every int64 and every data value
static char *harness_pack_live_masks =
	"NumLogin,NumTcpConnections*,CurrentNumTcp,"
	"ServerProductName,ServerVersionString,ServerBuildInfoString,ServerVerInt,ServerBuildInt,ServerHostName,"
	"Os*,Kernel*,"
	"ClientProductName,ClientProductVer,ClientProductBuild,ServerProductVer,ServerProductBuild,"
	"ClientOsName,ClientOsVer,ClientOsProductId,ClientHostname,ServerHostname,SessionStatus_ClientHostName,"
	"SessionName,ConnectionName,CipherName,ProtocolDetails,ClientPort,"
	"caps_*,CapsValue";

// Whether the values of an element are masked in a dump
static bool HarnessPackIsMasked(HARNESS_PACK_CASE *c, ELEMENT *e)
{
	if (c == NULL || c->Kind != HARNESS_PACK_LIVE)
	{
		return false;
	}

	if (e->type == VALUE_INT64 || e->type == VALUE_DATA)
	{
		return true;
	}

	return HarnessPackNameInList(e->name, harness_pack_live_masks) || HarnessPackNameInList(e->name, c->Masks);
}

// Dump the elements of a Pack in list order: #<i> <name> <type>[<num>] = <v0>, <v1>, ...
static void HarnessPackDump(BUF *b, PACK *p, HARNESS_PACK_CASE *c)
{
	UINT i, j;

	for (i = 0;i < LIST_NUM(p->elements);i++)
	{
		ELEMENT *e = LIST_DATA(p->elements, i);
		bool masked = HarnessPackIsMasked(c, e);
		char tmp[MAX_SIZE];

		Format(tmp, sizeof(tmp), "#%u %s %s[%u] =", i, e->name, HarnessPackTypeName(e->type), e->num_value);
		HarnessPackPut(b, tmp);

		for (j = 0;j < e->num_value;j++)
		{
			VALUE *v = e->values[j];

			HarnessPackPut(b, j == 0 ? " " : ", ");

			if (masked)
			{
				HarnessPackPut(b, HARNESS_PACK_TAG_MASKED);
				continue;
			}

			if (v == NULL)
			{
				HarnessPackPut(b, "null");
				continue;
			}

			switch (e->type)
			{
			case VALUE_INT:
				Format(tmp, sizeof(tmp), "%u", v->IntValue);
				HarnessPackPut(b, tmp);
				break;

			case VALUE_INT64:
				ToStr64(tmp, v->Int64Value);
				HarnessPackPut(b, tmp);
				break;

			case VALUE_STR:
				if (v->Str == NULL)
				{
					HarnessPackPut(b, "null");
				}
				else
				{
					HarnessPackPutStr(b, v->Str);
				}
				break;

			case VALUE_UNISTR:
				if (v->UniStr == NULL)
				{
					HarnessPackPut(b, "null");
				}
				else
				{
					char *utf8 = HarnessUniToUtf8(v->UniStr);

					HarnessPackPutStr(b, utf8);
					Free(utf8);
				}
				break;

			case VALUE_DATA:
				if (v->Size <= HARNESS_PACK_HEX_MAX)
				{
					HarnessPackPut(b, "hex:");
					HarnessPackPutHex(b, v->Data, v->Size);
				}
				else
				{
					Format(tmp, sizeof(tmp), "len=%u sha1=", v->Size);
					HarnessPackPut(b, tmp);
					HarnessPackPutSha1(b, v->Data, v->Size);
				}
				break;

			default:
				HarnessPackPut(b, "?");
				break;
			}
		}

		HarnessPackPut(b, "\n");
	}
}

// Size and SHA-1 of the serialised Pack (WritePack writes the list order)
static void HarnessPackPutBytes(BUF *b, PACK *p, bool masked)
{
	BUF *w;
	char tmp[MAX_SIZE];

	if (masked)
	{
		HarnessPackPut(b, "bytes=" HARNESS_PACK_TAG_MASKED "\n");
		return;
	}

	w = PackToBuf(p);
	Format(tmp, sizeof(tmp), "bytes=%u sha1=", w->Size);
	HarnessPackPut(b, tmp);
	HarnessPackPutSha1(b, w->Buf, w->Size);
	HarnessPackPut(b, "\n");
	FreeBuf(w);
}

////////////////////////////
// Canonical round-trip input

// FNV-1a of an element name
static UINT HarnessPackHash(char *s)
{
	UINT h = 2166136261U;
	UINT i;

	for (i = 0;s[i] != 0;i++)
	{
		h ^= (UCHAR)s[i];
		h *= 16777619U;
	}

	return h;
}

// Values kept verbatim: they steer a read branch or a count (policy values are the policy table's)
static bool HarnessPackIsKept(char *name, bool live)
{
	if (StrCmp(name, "AuthType") == 0 || StrCmp(name, "IsIPv6") == 0 || StrCmp(name, "Masked") == 0 ||
		StrCmp(name, "UsePolicy") == 0 || StrCmp(name, "NumItem") == 0)
	{
		return true;
	}

	if (EndWith(name, "@ipv6_bool") || StartWith(name, "policy:"))
	{
		return true;
	}

	// Caps values steer no read; the server's own values depend on the machine (AES-NI, VM, bridge)
	if (StartWith(name, "caps_") && live == false)
	{
		return true;
	}

	return false;
}

// Canonical data value: the test certificate or key for the X and K keys, UTF-8 text for the text keys,
// otherwise bytes derived from the name and the index with the same size (fixed-size reads keep matching)
static void HarnessPackCanonData(HARNESS_PACK_RUN *r, ELEMENT *e, UINT h, UINT index, VALUE *v)
{
	BUF *src = NULL;
	char tmp[MAX_SIZE];
	UINT x, i;

	if (StrCmp(e->name, "Cert") == 0 || StrCmp(e->name, "Chain") == 0 || StrCmp(e->name, "ServerCert") == 0 ||
		StrCmp(e->name, "ServerX") == 0 || StrCmp(e->name, "ClientX") == 0 || StrCmp(e->name, "UserX") == 0)
	{
		src = r->CertDer;
	}
	else if (StrCmp(e->name, "Key") == 0 || StrCmp(e->name, "ClientK") == 0)
	{
		src = r->KeyDer;
	}
	else if (StrCmp(e->name, "Msg") == 0 || StrCmp(e->name, "FileData") == 0)
	{
		Format(tmp, sizeof(tmp), "%s#%u ", e->name, index);
		StrCat(tmp, sizeof(tmp), "\xc3\xa9\xe4\xb8\xad");

		Free(v->Data);
		v->Size = StrLen(tmp);
		v->Data = Clone(tmp, v->Size);
		return;
	}

	if (src != NULL)
	{
		Free(v->Data);
		v->Size = src->Size;
		v->Data = Clone(src->Buf, src->Size);
		return;
	}

	x = h ^ (index * 0x9E3779B9U);

	for (i = 0;i < v->Size;i++)
	{
		x = x * 1103515245U + 12345U;
		((UCHAR *)v->Data)[i] = (UCHAR)(x >> 16);
	}
}

// Rewrite the values of a Pack in place from the element name and the value index only (element order,
// names, types and counts unchanged): ints get a distinct value (0 for about one key in five, so booleans
// take both values), int64 a distinct non-zero value, strings "<name>#<index>" (Unicode strings add U+00E9
// U+4E2D for the UTF-8 path). The kept keys (HarnessPackIsKept) keep their values.
static void HarnessPackCanon(HARNESS_PACK_RUN *r, PACK *p, bool live)
{
	UINT i, j;

	for (i = 0;i < LIST_NUM(p->elements);i++)
	{
		ELEMENT *e = LIST_DATA(p->elements, i);
		UINT h;

		if (HarnessPackIsKept(e->name, live))
		{
			continue;
		}

		h = HarnessPackHash(e->name);

		for (j = 0;j < e->num_value;j++)
		{
			VALUE *v = e->values[j];
			char tmp[MAX_SIZE];

			if (v == NULL)
			{
				continue;
			}

			switch (e->type)
			{
			case VALUE_INT:
				v->IntValue = ((h % 5) == 0) ? 0 : (1000 + ((h / 5) % 1000000) * 64 + j);
				break;

			case VALUE_INT64:
				v->Int64Value = ((UINT64)h << 24) + (UINT64)(j + 1);
				break;

			case VALUE_STR:
				Format(tmp, sizeof(tmp), "%s#%u", e->name, j);
				Free(v->Str);
				v->Str = CopyStr(tmp);
				v->Size = StrSize(v->Str);
				break;

			case VALUE_UNISTR:
				Format(tmp, sizeof(tmp), "%s#%u", e->name, j);
				StrCat(tmp, sizeof(tmp), "\xc3\xa9\xe4\xb8\xad");
				Free(v->UniStr);
				v->UniStr = CopyUtfToUni(tmp);
				v->Size = UniStrSize(v->UniStr);
				break;

			case VALUE_DATA:
				HarnessPackCanonData(r, e, h, j, v);
				break;
			}
		}
	}
}

////////////////////////////
// Cases: SYN preparation (only counts, items, pointers and discriminators; the values come from the
// canonical input of the round trip)

static void HarnessPackPrepListenerList(HARNESS *h, void *p)
{
	RPC_LISTENER_LIST *t = p;

	t->NumPort = 2;
	t->Ports = ZeroMalloc(sizeof(UINT) * t->NumPort);
	t->Enables = ZeroMalloc(sizeof(bool) * t->NumPort);
	t->Errors = ZeroMalloc(sizeof(bool) * t->NumPort);
}

static void HarnessPackPrepServerInfo(HARNESS *h, void *p)
{
	RPC_SERVER_INFO *t = p;

	t->OsInfo.OsSystemName = CopyStr("");
	t->OsInfo.OsProductName = CopyStr("");
	t->OsInfo.OsVendorName = CopyStr("");
	t->OsInfo.OsVersion = CopyStr("");
	t->OsInfo.KernelName = CopyStr("");
	t->OsInfo.KernelVersion = CopyStr("");
}

static void HarnessPackPrepKeyPair(HARNESS *h, void *p)
{
	RPC_KEY_PAIR *t = p;

	t->Cert = HarnessTestCert();
	t->Chain = NewList(NULL);
	Add(t->Chain, HarnessTestCert());
	t->Key = HarnessTestKey();
}

static void HarnessPackPrepStr(HARNESS *h, void *p)
{
	RPC_STR *t = p;

	t->String = CopyStr("");
}

static void HarnessPackPrepEnumHub(HARNESS *h, void *p)
{
	RPC_ENUM_HUB *t = p;

	t->NumHub = 2;
	t->Hubs = ZeroMalloc(sizeof(RPC_ENUM_HUB_ITEM) * t->NumHub);
}

static void HarnessPackPrepEnumConnection(HARNESS *h, void *p)
{
	RPC_ENUM_CONNECTION *t = p;

	t->NumConnection = 2;
	t->Connections = ZeroMalloc(sizeof(RPC_ENUM_CONNECTION_ITEM) * t->NumConnection);
}

static void HarnessPackPrepHubAddCa(HARNESS *h, void *p)
{
	RPC_HUB_ADD_CA *t = p;

	t->Cert = HarnessTestCert();
}

static void HarnessPackPrepHubEnumCa(HARNESS *h, void *p)
{
	RPC_HUB_ENUM_CA *t = p;

	t->NumCa = 2;
	t->Ca = ZeroMalloc(sizeof(RPC_HUB_ENUM_CA_ITEM) * t->NumCa);
}

static void HarnessPackPrepHubGetCa(HARNESS *h, void *p)
{
	RPC_HUB_GET_CA *t = p;

	t->Cert = HarnessTestCert();
}

// CreateLink with one client authentication type
static void HarnessPackPrepCreateLinkAuth(RPC_CREATE_LINK *t, UINT auth_type)
{
	Copy(&t->Policy, GetDefaultPolicy(), sizeof(POLICY));
	t->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	t->ClientAuth = ZeroMalloc(sizeof(CLIENT_AUTH));
	t->ClientAuth->AuthType = auth_type;
}

static void HarnessPackPrepCreateLinkAnon(HARNESS *h, void *p)
{
	HarnessPackPrepCreateLinkAuth(p, CLIENT_AUTHTYPE_ANONYMOUS);
}

static void HarnessPackPrepCreateLinkPassword(HARNESS *h, void *p)
{
	HarnessPackPrepCreateLinkAuth(p, CLIENT_AUTHTYPE_PASSWORD);
}

static void HarnessPackPrepCreateLinkPlain(HARNESS *h, void *p)
{
	HarnessPackPrepCreateLinkAuth(p, CLIENT_AUTHTYPE_PLAIN_PASSWORD);
}

static void HarnessPackPrepCreateLinkCert(HARNESS *h, void *p)
{
	RPC_CREATE_LINK *t = p;

	HarnessPackPrepCreateLinkAuth(t, CLIENT_AUTHTYPE_CERT);
	t->ClientAuth->ClientX = HarnessTestCert();
	t->ClientAuth->ClientK = HarnessTestKey();
	t->CheckServerCert = true;
	t->ServerCert = HarnessTestCert();
}

static void HarnessPackPrepCreateLinkEngine(HARNESS *h, void *p)
{
	RPC_CREATE_LINK *t = p;

	HarnessPackPrepCreateLinkAuth(t, CLIENT_AUTHTYPE_OPENSSLENGINE);
	t->ClientAuth->ClientX = HarnessTestCert();
}

static void HarnessPackPrepEnumLink(HARNESS *h, void *p)
{
	RPC_ENUM_LINK *t = p;

	t->NumLink = 2;
	t->Links = ZeroMalloc(sizeof(RPC_ENUM_LINK_ITEM) * t->NumLink);
}

static void HarnessPackPrepLinkStatus(HARNESS *h, void *p)
{
	RPC_LINK_STATUS *t = p;

	t->Status.ServerX = HarnessTestCert();
	t->Status.ClientX = HarnessTestCert();
}

static void HarnessPackPrepAddAccessV6(HARNESS *h, void *p)
{
	RPC_ADD_ACCESS *t = p;

	t->Access.IsIPv6 = true;
}

static void HarnessPackPrepEnumAccessList(HARNESS *h, void *p)
{
	RPC_ENUM_ACCESS_LIST *t = p;

	t->NumAccess = 2;
	t->Accesses = ZeroMalloc(sizeof(ACCESS) * t->NumAccess);
	t->Accesses[1].IsIPv6 = true;
}

static void HarnessPackPrepSetUserPassword(HARNESS *h, void *p)
{
	RPC_SET_USER *t = p;

	t->AuthType = AUTHTYPE_PASSWORD;
	t->AuthData = ZeroMalloc(sizeof(AUTHPASSWORD));
}

static void HarnessPackPrepSetUserUserCert(HARNESS *h, void *p)
{
	RPC_SET_USER *t = p;
	AUTHUSERCERT *a = ZeroMalloc(sizeof(AUTHUSERCERT));

	a->UserX = HarnessTestCert();
	t->AuthType = AUTHTYPE_USERCERT;
	t->AuthData = a;
}

static void HarnessPackPrepSetUserRootCert(HARNESS *h, void *p)
{
	RPC_SET_USER *t = p;
	AUTHROOTCERT *a = ZeroMalloc(sizeof(AUTHROOTCERT));
	UCHAR serial[8] = {0x52, 0x41, 0x4E, 0x5A, 0x01, 0x02, 0x03, 0x04};

	a->Serial = NewXSerial(serial, sizeof(serial));
	a->CommonName = CopyUniStr(L"");
	t->AuthType = AUTHTYPE_ROOTCERT;
	t->AuthData = a;
}

static void HarnessPackPrepSetUserNt(HARNESS *h, void *p)
{
	RPC_SET_USER *t = p;
	AUTHNT *a = ZeroMalloc(sizeof(AUTHNT));

	a->NtUsername = CopyUniStr(L"");
	t->AuthType = AUTHTYPE_NT;
	t->AuthData = a;
}

// Anonymous user (no authentication data) with a policy
static void HarnessPackPrepSetUserPolicy(HARNESS *h, void *p)
{
	RPC_SET_USER *t = p;

	t->AuthType = AUTHTYPE_ANONYMOUS;
	t->Policy = Clone(GetDefaultPolicy(), sizeof(POLICY));
}

static void HarnessPackPrepEnumUser(HARNESS *h, void *p)
{
	RPC_ENUM_USER *t = p;

	t->NumUser = 2;
	t->Users = ZeroMalloc(sizeof(RPC_ENUM_USER_ITEM) * t->NumUser);
}

static void HarnessPackPrepSetGroupPolicy(HARNESS *h, void *p)
{
	RPC_SET_GROUP *t = p;

	t->Policy = Clone(GetDefaultPolicy(), sizeof(POLICY));
}

static void HarnessPackPrepEnumGroup(HARNESS *h, void *p)
{
	RPC_ENUM_GROUP *t = p;

	t->NumGroup = 2;
	t->Groups = ZeroMalloc(sizeof(RPC_ENUM_GROUP_ITEM) * t->NumGroup);
}

// Item 1 IPv4, item 2 IPv6
static void HarnessPackPrepEnumSession(HARNESS *h, void *p)
{
	RPC_ENUM_SESSION *t = p;

	t->NumSession = 2;
	t->Sessions = ZeroMalloc(sizeof(RPC_ENUM_SESSION_ITEM) * t->NumSession);
	UINTToIP(&t->Sessions[0].ClientIP, 0);
	HarnessPackIp6(&t->Sessions[1].ClientIP, 2);
}

static void HarnessPackPrepSessionStatus(HARNESS *h, void *p)
{
	RPC_SESSION_STATUS *t = p;

	HarnessPackIp6(&t->ClientIpAddress, 1);
}

static void HarnessPackPrepEnumMacTable(HARNESS *h, void *p)
{
	RPC_ENUM_MAC_TABLE *t = p;

	t->NumMacTable = 2;
	t->MacTables = ZeroMalloc(sizeof(RPC_ENUM_MAC_TABLE_ITEM) * t->NumMacTable);
}

// Item 1 IPv4, item 2 IPv6 (the unindexed IpAddress read shows in [in-out])
static void HarnessPackPrepEnumIpTable(HARNESS *h, void *p)
{
	RPC_ENUM_IP_TABLE *t = p;

	t->NumIpTable = 2;
	t->IpTables = ZeroMalloc(sizeof(RPC_ENUM_IP_TABLE_ITEM) * t->NumIpTable);
	UINTToIP(&t->IpTables[0].IpV6, 0);
	UINTToIP(&t->IpTables[0].IpAddress, 0);
	HarnessPackIp6(&t->IpTables[1].IpV6, 3);
	HarnessPackIp6(&t->IpTables[1].IpAddress, 4);
}

static void HarnessPackPrepEnumEth(HARNESS *h, void *p)
{
	RPC_ENUM_ETH *t = p;

	t->NumItem = 2;
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_ETH_ITEM) * t->NumItem);
}

static void HarnessPackPrepEnumLocalBridge(HARNESS *h, void *p)
{
	RPC_ENUM_LOCALBRIDGE *t = p;

	t->NumItem = 2;
	t->Items = ZeroMalloc(sizeof(RPC_LOCALBRIDGE) * t->NumItem);
}

// Three caps: two with a CT_ title in the string table, one without (the description is the name)
static void HarnessPackPrepCapsList(HARNESS *h, void *p)
{
	CAPSLIST *t = p;

	InitCapsList(t);
	AddCapsBool(t, "b_support_cascade", true);
	AddCapsInt(t, "i_max_sessions", 0);
	AddCapsBool(t, "b_harness_pack", false);
}

static void HarnessPackPrepConfig(HARNESS *h, void *p)
{
	RPC_CONFIG *t = p;

	t->FileData = CopyStr("");
}

static void HarnessPackPrepAdminOption(HARNESS *h, void *p)
{
	RPC_ADMIN_OPTION *t = p;

	t->NumItem = 3;
	t->Items = ZeroMalloc(sizeof(ADMIN_OPTION) * t->NumItem);
}

static void HarnessPackPrepEnumCrl(HARNESS *h, void *p)
{
	RPC_ENUM_CRL *t = p;

	t->NumItem = 2;
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_CRL_ITEM) * t->NumItem);
}

// CRL with a serial number, the six name parts and both digests
static void HarnessPackPrepCrlFull(HARNESS *h, void *p)
{
	RPC_CRL *t = p;
	UCHAR serial[8] = {0x52, 0x41, 0x4E, 0x5A, 0x05, 0x06, 0x07, 0x08};
	NAME *n;
	UINT i;

	t->Crl = ZeroMalloc(sizeof(CRL));
	t->Crl->Serial = NewXSerial(serial, sizeof(serial));
	n = t->Crl->Name = ZeroMalloc(sizeof(NAME));
	n->CommonName = CopyUniStr(L"");
	n->Organization = CopyUniStr(L"");
	n->Unit = CopyUniStr(L"");
	n->Country = CopyUniStr(L"");
	n->State = CopyUniStr(L"");
	n->Local = CopyUniStr(L"");

	// Non-zero digests: OutRpcCrl writes only those
	for (i = 0;i < MD5_SIZE;i++)
	{
		t->Crl->DigestMD5[i] = (UCHAR)(0x10 + i);
	}
	for (i = 0;i < SHA1_SIZE;i++)
	{
		t->Crl->DigestSHA1[i] = (UCHAR)(0x40 + i);
	}
}

// CRL with an empty name only
static void HarnessPackPrepCrlMin(HARNESS *h, void *p)
{
	RPC_CRL *t = p;

	t->Crl = ZeroMalloc(sizeof(CRL));
	t->Crl->Name = ZeroMalloc(sizeof(NAME));
}

// Three entries through AddAc: IPv4 masked, IPv4 deny, IPv6 masked
static void HarnessPackPrepAcList(HARNESS *h, void *p)
{
	RPC_AC_LIST *t = p;
	AC ac;

	t->o = NewList(CmpAc);

	Zero(&ac, sizeof(ac));
	ac.Masked = true;
	UINTToIP(&ac.IpAddress, 0);
	UINTToIP(&ac.SubnetMask, 0);
	AddAc(t->o, &ac);

	Zero(&ac, sizeof(ac));
	ac.Deny = true;
	UINTToIP(&ac.IpAddress, 0);
	UINTToIP(&ac.SubnetMask, 0);
	AddAc(t->o, &ac);

	Zero(&ac, sizeof(ac));
	ac.Masked = true;
	HarnessPackIp6(&ac.IpAddress, 5);
	HarnessPackIp6(&ac.SubnetMask, 6);
	AddAc(t->o, &ac);
}

static void HarnessPackPrepEnumLogFile(HARNESS *h, void *p)
{
	RPC_ENUM_LOG_FILE *t = p;

	t->NumItem = 2;
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_LOG_FILE_ITEM) * t->NumItem);
}

static void HarnessPackPrepReadLogFileBuffer(HARNESS *h, void *p)
{
	RPC_READ_LOG_FILE *t = p;
	UCHAR data[8] = {0};

	t->Buffer = NewBuf();
	WriteBuf(t->Buffer, data, sizeof(data));
}

static void HarnessPackPrepEnumLicenseKey(HARNESS *h, void *p)
{
	RPC_ENUM_LICENSE_KEY *t = p;

	t->NumItem = 2;
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_LICENSE_KEY_ITEM) * t->NumItem);
}

static void HarnessPackPrepEnumEthVLan(HARNESS *h, void *p)
{
	RPC_ENUM_ETH_VLAN *t = p;

	t->NumItem = 2;
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_ETH_VLAN_ITEM) * t->NumItem);
}

static void HarnessPackPrepMsg(HARNESS *h, void *p)
{
	RPC_MSG *t = p;

	t->Msg = CopyUniStr(L"Ranz \x00e9\x4e2d");
}

////////////////////////////
// Cases: LIVE requests (read-only RPCs on the scenario of harness.c)

static void HarnessPackLiveHubA(HARNESS *h, void *p)
{
	// HubName is the first member of every request structure that uses this preparation
	StrCpy((char *)p, MAX_HUBNAME_LEN + 1, HARNESS_HUB_A);
}

static void HarnessPackLiveHubB(HARNESS *h, void *p)
{
	StrCpy((char *)p, MAX_HUBNAME_LEN + 1, HARNESS_HUB_B);
}

static void HarnessPackLiveGetLink(HARNESS *h, void *p)
{
	RPC_CREATE_LINK *t = p;

	StrCpy(t->HubName, sizeof(t->HubName), HARNESS_HUB_A);
	t->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t->ClientOption->AccountName, sizeof(t->ClientOption->AccountName), HARNESS_LINK_NAME);
}

static void HarnessPackLiveLinkStatus(HARNESS *h, void *p)
{
	RPC_LINK_STATUS *t = p;

	StrCpy(t->HubName, sizeof(t->HubName), HARNESS_HUB_A);
	UniStrCpy(t->AccountName, sizeof(t->AccountName), HARNESS_LINK_NAME);
}

static void HarnessPackLiveGetUser(HARNESS *h, void *p)
{
	RPC_SET_USER *t = p;

	StrCpy(t->HubName, sizeof(t->HubName), HARNESS_HUB_A);
	StrCpy(t->Name, sizeof(t->Name), HARNESS_USER_A);
}

// Session of test user A on HARNESS_A
static void HarnessPackLiveSessionStatus(HARNESS *h, void *p)
{
	RPC_SESSION_STATUS *t = p;

	StrCpy(t->HubName, sizeof(t->HubName), HARNESS_HUB_A);
	HarnessFindSession(h, HARNESS_HUB_A, HARNESS_USER_A, false, t->Name, sizeof(t->Name));
}

////////////////////////////
// Cases: IN input Packs (read quirks of the current code)

// Plain password read after Name: the hash is salted with the user name
static PACK *HarnessPackBuildSetUserPlainPassword(void)
{
	PACK *p = NewPack();

	PackAddStr(p, "HubName", HARNESS_HUB_A);
	PackAddStr(p, "Name", "in_user");
	PackAddInt(p, "AuthType", AUTHTYPE_PASSWORD);
	PackAddStr(p, "Auth_Password", "In-Plain-Pass-1");

	return p;
}

// TargetHubName only: the hub name falls back from ConnectedHubName
static PACK *HarnessPackBuildEnumLinkTargetHub(void)
{
	PACK *p = NewPack();

	PackAddStr(p, "HubName", HARNESS_HUB_A);
	PackAddUniStrEx(p, "AccountName", L"in_link_1", 0, 2);
	PackAddUniStrEx(p, "AccountName", L"in_link_2", 1, 2);
	PackAddStrEx(p, "TargetHubName", "IN_TARGET_1", 0, 2);
	PackAddStrEx(p, "TargetHubName", "IN_TARGET_2", 1, 2);

	return p;
}

// Ip without IpV6 (IPv6 falls back to Ip), two different IpAddress values (read without index)
static PACK *HarnessPackBuildEnumIpTableIpv4Only(void)
{
	PACK *p = NewPack();
	IP a, b;

	UINTToIP(&a, 0x0A0A0A0A);
	UINTToIP(&b, 0x0B0B0B0B);

	PackAddStr(p, "HubName", HARNESS_HUB_A);
	PackAddStrEx(p, "SessionName", "SID-IN-1", 0, 2);
	PackAddStrEx(p, "SessionName", "SID-IN-2", 1, 2);
	PackAddIp32Ex(p, "Ip", 0x0100000A, 0, 2);
	PackAddIp32Ex(p, "Ip", 0x0200000A, 1, 2);
	PackAddIpEx(p, "IpAddress", &a, 0, 2);
	PackAddIpEx(p, "IpAddress", &b, 1, 2);

	return p;
}

// Digests of the wrong size are not read
static PACK *HarnessPackBuildCrlBadDigest(void)
{
	PACK *p = NewPack();
	UCHAR d[32];
	UINT i;

	for (i = 0;i < sizeof(d);i++)
	{
		d[i] = (UCHAR)(0xA0 + i);
	}

	PackAddStr(p, "HubName", HARNESS_HUB_A);
	PackAddInt(p, "Key", 7);
	PackAddData(p, "Serial", d, 4);
	PackAddUniStr(p, "CommonName", L"in_crl");
	PackAddData(p, "DigestMD5", d, MD5_SIZE - 1);
	PackAddData(p, "DigestSHA1", d, SHA1_SIZE + 1);

	return p;
}

// Session key of the wrong size is not read
static PACK *HarnessPackBuildSessionStatusBadSessionKey(void)
{
	PACK *p = NewPack();
	UCHAR d[SHA1_SIZE];

	Zero(d, sizeof(d));
	d[0] = 0x5A;

	PackAddStr(p, "HubName", HARNESS_HUB_A);
	PackAddStr(p, "Name", "SID-IN-1");
	PackAddData(p, "SessionKey", d, SHA1_SIZE - 1);

	return p;
}

// Hashed password of the wrong size is not read
static PACK *HarnessPackBuildCreateLinkBadHashedPassword(void)
{
	PACK *p = NewPack();
	UCHAR d[SHA1_SIZE];

	Zero(d, sizeof(d));
	d[0] = 0x5A;

	PackAddStr(p, "HubName_Ex", HARNESS_HUB_A);
	PackAddUniStr(p, "AccountName", L"in_link");
	PackAddInt(p, "AuthType", CLIENT_AUTHTYPE_PASSWORD);
	PackAddStr(p, "Username", "in_user");
	PackAddData(p, "HashedPassword", d, SHA1_SIZE - 1);

	return p;
}

// NumItem larger than the values: the count comes from the index count of Name
static PACK *HarnessPackBuildAdminOptionNumItemMismatch(void)
{
	PACK *p = NewPack();

	PackAddInt(p, "NumItem", 5);
	PackAddStr(p, "HubName", HARNESS_HUB_A);
	PackAddStrEx(p, "Name", "in_option_1", 0, 2);
	PackAddStrEx(p, "Name", "in_option_2", 1, 2);
	PackAddIntEx(p, "Value", 11, 0, 2);
	PackAddIntEx(p, "Value", 22, 1, 2);

	return p;
}

// NumItem larger than the values: the count is NumItem capped at the FilePath values (SEC-6), so one item
static PACK *HarnessPackBuildEnumLogFileNumItemMore(void)
{
	PACK *p = NewPack();

	PackAddInt(p, "NumItem", 3);
	PackAddStrEx(p, "FilePath", "in_file_1.log", 0, 1);
	PackAddIntEx(p, "FileSize", 1234, 0, 1);

	return p;
}

// Ragged arrays: two hub names, one Online value
static PACK *HarnessPackBuildEnumHubRagged(void)
{
	PACK *p = NewPack();

	PackAddStrEx(p, "HubName", "IN_HUB_1", 0, 2);
	PackAddStrEx(p, "HubName", "IN_HUB_2", 1, 2);
	PackAddBoolEx(p, "Online", true, 0, 1);

	return p;
}

// Values of the wrong type are not read
static PACK *HarnessPackBuildCreateHubWrongType(void)
{
	PACK *p = NewPack();

	PackAddUniStr(p, "HubName", L"IN_HUB");
	PackAddInt64(p, "Online", 1);
	PackAddInt(p, "MaxSession", 9);

	return p;
}

// No Msg: an empty message
static PACK *HarnessPackBuildMsgNoMsg(void)
{
	PACK *p = NewPack();

	PackAddStr(p, "HubName", HARNESS_HUB_A);

	return p;
}

// No String: an empty string
static PACK *HarnessPackBuildStrMissing(void)
{
	return NewPack();
}

// NumItem whose item array does not fit in 32 bits: the table engine reads no item (count 0)
static PACK *HarnessPackBuildEnumLicenseKeyNumItemOverflow(void)
{
	PACK *p = NewPack();

	PackAddInt(p, "NumItem", 0x10000000);

	return p;
}

// NumItem far above the values, with an item array that still fits in 32 bits (15,000,000 items of 272 bytes, about
// 4 GiB): the count is capped at the one FilePath value sent, so the reader allocates one item (SEC-6)
static PACK *HarnessPackBuildEnumLogFileNumItemHuge(void)
{
	PACK *p = NewPack();

	PackAddInt(p, "NumItem", 15000000);
	PackAddStrEx(p, "FilePath", "in_file_1.log", 0, 1);

	return p;
}

////////////////////////////
// Case table

#define	HARNESS_PACK_SYN_CASE(name, type, prep)		\
	{name, &harness_pack_type_##type, HARNESS_PACK_SYN, prep, NULL, NULL, NULL}
#define	HARNESS_PACK_LIVE_CASE(name, type, prep, rpc, masks)		\
	{name, &harness_pack_type_##type, HARNESS_PACK_LIVE, prep, rpc, NULL, masks}
#define	HARNESS_PACK_IN_CASE(name, type, build)		\
	{name, &harness_pack_type_##type, HARNESS_PACK_IN, NULL, NULL, build, NULL}

static HARNESS_PACK_CASE harness_pack_cases[] =
{
	// SYN: every wire type, plus the branch variants
	HARNESS_PACK_SYN_CASE("RPC_TEST", RPC_TEST, NULL),
	HARNESS_PACK_SYN_CASE("RPC_SERVER_INFO", RPC_SERVER_INFO, HarnessPackPrepServerInfo),
	HARNESS_PACK_SYN_CASE("RPC_SERVER_STATUS", RPC_SERVER_STATUS, NULL),
	HARNESS_PACK_SYN_CASE("RPC_LISTENER", RPC_LISTENER, NULL),
	HARNESS_PACK_SYN_CASE("RPC_LISTENER_LIST", RPC_LISTENER_LIST, HarnessPackPrepListenerList),
	HARNESS_PACK_SYN_CASE("RPC_SET_PASSWORD", RPC_SET_PASSWORD, NULL),
	HARNESS_PACK_SYN_CASE("RPC_KEY_PAIR", RPC_KEY_PAIR, HarnessPackPrepKeyPair),
	HARNESS_PACK_SYN_CASE("RPC_STR", RPC_STR, HarnessPackPrepStr),
	HARNESS_PACK_SYN_CASE("RPC_CREATE_HUB", RPC_CREATE_HUB, NULL),
	HARNESS_PACK_SYN_CASE("RPC_ENUM_HUB", RPC_ENUM_HUB, HarnessPackPrepEnumHub),
	HARNESS_PACK_SYN_CASE("RPC_DELETE_HUB", RPC_DELETE_HUB, NULL),
	HARNESS_PACK_SYN_CASE("RPC_ENUM_CONNECTION", RPC_ENUM_CONNECTION, HarnessPackPrepEnumConnection),
	HARNESS_PACK_SYN_CASE("RPC_DISCONNECT_CONNECTION", RPC_DISCONNECT_CONNECTION, NULL),
	HARNESS_PACK_SYN_CASE("RPC_CONNECTION_INFO", RPC_CONNECTION_INFO, NULL),
	HARNESS_PACK_SYN_CASE("RPC_SET_HUB_ONLINE", RPC_SET_HUB_ONLINE, NULL),
	HARNESS_PACK_SYN_CASE("RPC_HUB_STATUS", RPC_HUB_STATUS, NULL),
	HARNESS_PACK_SYN_CASE("RPC_HUB_LOG", RPC_HUB_LOG, NULL),
	HARNESS_PACK_SYN_CASE("RPC_HUB_ADD_CA", RPC_HUB_ADD_CA, HarnessPackPrepHubAddCa),
	HARNESS_PACK_SYN_CASE("RPC_HUB_ENUM_CA", RPC_HUB_ENUM_CA, HarnessPackPrepHubEnumCa),
	HARNESS_PACK_SYN_CASE("RPC_HUB_GET_CA", RPC_HUB_GET_CA, HarnessPackPrepHubGetCa),
	HARNESS_PACK_SYN_CASE("RPC_HUB_DELETE_CA", RPC_HUB_DELETE_CA, NULL),
	HARNESS_PACK_SYN_CASE("RPC_LINK", RPC_LINK, NULL),
	HARNESS_PACK_SYN_CASE("RPC_RENAME_LINK", RPC_RENAME_LINK, NULL),
	HARNESS_PACK_SYN_CASE("RPC_CREATE_LINK_anon", RPC_CREATE_LINK, HarnessPackPrepCreateLinkAnon),
	HARNESS_PACK_SYN_CASE("RPC_CREATE_LINK_password", RPC_CREATE_LINK, HarnessPackPrepCreateLinkPassword),
	HARNESS_PACK_SYN_CASE("RPC_CREATE_LINK_plain", RPC_CREATE_LINK, HarnessPackPrepCreateLinkPlain),
	HARNESS_PACK_SYN_CASE("RPC_CREATE_LINK_cert", RPC_CREATE_LINK, HarnessPackPrepCreateLinkCert),
	HARNESS_PACK_SYN_CASE("RPC_CREATE_LINK_engine", RPC_CREATE_LINK, HarnessPackPrepCreateLinkEngine),
	HARNESS_PACK_SYN_CASE("RPC_ENUM_LINK", RPC_ENUM_LINK, HarnessPackPrepEnumLink),
	HARNESS_PACK_SYN_CASE("RPC_LINK_STATUS", RPC_LINK_STATUS, HarnessPackPrepLinkStatus),
	HARNESS_PACK_SYN_CASE("RPC_ADD_ACCESS_v4", RPC_ADD_ACCESS, NULL),
	HARNESS_PACK_SYN_CASE("RPC_ADD_ACCESS_v6", RPC_ADD_ACCESS, HarnessPackPrepAddAccessV6),
	HARNESS_PACK_SYN_CASE("RPC_DELETE_ACCESS", RPC_DELETE_ACCESS, NULL),
	HARNESS_PACK_SYN_CASE("RPC_ENUM_ACCESS_LIST", RPC_ENUM_ACCESS_LIST, HarnessPackPrepEnumAccessList),
	HARNESS_PACK_SYN_CASE("RPC_SET_USER_password", RPC_SET_USER, HarnessPackPrepSetUserPassword),
	HARNESS_PACK_SYN_CASE("RPC_SET_USER_usercert", RPC_SET_USER, HarnessPackPrepSetUserUserCert),
	HARNESS_PACK_SYN_CASE("RPC_SET_USER_rootcert", RPC_SET_USER, HarnessPackPrepSetUserRootCert),
	HARNESS_PACK_SYN_CASE("RPC_SET_USER_nt", RPC_SET_USER, HarnessPackPrepSetUserNt),
	HARNESS_PACK_SYN_CASE("RPC_SET_USER_policy", RPC_SET_USER, HarnessPackPrepSetUserPolicy),
	HARNESS_PACK_SYN_CASE("RPC_DELETE_USER", RPC_DELETE_USER, NULL),
	HARNESS_PACK_SYN_CASE("RPC_ENUM_USER", RPC_ENUM_USER, HarnessPackPrepEnumUser),
	HARNESS_PACK_SYN_CASE("RPC_SET_GROUP", RPC_SET_GROUP, NULL),
	HARNESS_PACK_SYN_CASE("RPC_SET_GROUP_policy", RPC_SET_GROUP, HarnessPackPrepSetGroupPolicy),
	HARNESS_PACK_SYN_CASE("RPC_ENUM_GROUP", RPC_ENUM_GROUP, HarnessPackPrepEnumGroup),
	HARNESS_PACK_SYN_CASE("RPC_ENUM_SESSION", RPC_ENUM_SESSION, HarnessPackPrepEnumSession),
	HARNESS_PACK_SYN_CASE("RPC_SESSION_STATUS", RPC_SESSION_STATUS, HarnessPackPrepSessionStatus),
	HARNESS_PACK_SYN_CASE("RPC_DELETE_SESSION", RPC_DELETE_SESSION, NULL),
	HARNESS_PACK_SYN_CASE("RPC_ENUM_MAC_TABLE", RPC_ENUM_MAC_TABLE, HarnessPackPrepEnumMacTable),
	HARNESS_PACK_SYN_CASE("RPC_DELETE_TABLE", RPC_DELETE_TABLE, NULL),
	HARNESS_PACK_SYN_CASE("RPC_ENUM_IP_TABLE", RPC_ENUM_IP_TABLE, HarnessPackPrepEnumIpTable),
	HARNESS_PACK_SYN_CASE("RPC_ENUM_ETH", RPC_ENUM_ETH, HarnessPackPrepEnumEth),
	HARNESS_PACK_SYN_CASE("RPC_LOCALBRIDGE", RPC_LOCALBRIDGE, NULL),
	HARNESS_PACK_SYN_CASE("RPC_ENUM_LOCALBRIDGE", RPC_ENUM_LOCALBRIDGE, HarnessPackPrepEnumLocalBridge),
	HARNESS_PACK_SYN_CASE("RPC_BRIDGE_SUPPORT", RPC_BRIDGE_SUPPORT, NULL),
	HARNESS_PACK_SYN_CASE("CAPSLIST", CAPSLIST, HarnessPackPrepCapsList),
	HARNESS_PACK_SYN_CASE("RPC_CONFIG", RPC_CONFIG, HarnessPackPrepConfig),
	HARNESS_PACK_SYN_CASE("RPC_ADMIN_OPTION", RPC_ADMIN_OPTION, HarnessPackPrepAdminOption),
	HARNESS_PACK_SYN_CASE("RPC_ENUM_CRL", RPC_ENUM_CRL, HarnessPackPrepEnumCrl),
	HARNESS_PACK_SYN_CASE("RPC_CRL_full", RPC_CRL, HarnessPackPrepCrlFull),
	HARNESS_PACK_SYN_CASE("RPC_CRL_min", RPC_CRL, HarnessPackPrepCrlMin),
	HARNESS_PACK_SYN_CASE("RPC_AC_LIST", RPC_AC_LIST, HarnessPackPrepAcList),
	HARNESS_PACK_SYN_CASE("RPC_ENUM_LOG_FILE", RPC_ENUM_LOG_FILE, HarnessPackPrepEnumLogFile),
	HARNESS_PACK_SYN_CASE("RPC_READ_LOG_FILE_buffer", RPC_READ_LOG_FILE, HarnessPackPrepReadLogFileBuffer),
	HARNESS_PACK_SYN_CASE("RPC_READ_LOG_FILE_nobuffer", RPC_READ_LOG_FILE, NULL),
	HARNESS_PACK_SYN_CASE("RPC_ENUM_LICENSE_KEY", RPC_ENUM_LICENSE_KEY, HarnessPackPrepEnumLicenseKey),
	HARNESS_PACK_SYN_CASE("RPC_LICENSE_STATUS", RPC_LICENSE_STATUS, NULL),
	HARNESS_PACK_SYN_CASE("SYSLOG_SETTING", SYSLOG_SETTING, NULL),
	HARNESS_PACK_SYN_CASE("RPC_ENUM_ETH_VLAN", RPC_ENUM_ETH_VLAN, HarnessPackPrepEnumEthVLan),
	HARNESS_PACK_SYN_CASE("RPC_MSG", RPC_MSG, HarnessPackPrepMsg),

	// LIVE: read-only RPCs on the scenario (no server state changes)
	HARNESS_PACK_LIVE_CASE("RPC_SERVER_INFO_live", RPC_SERVER_INFO, NULL, "GetServerInfo", NULL),
	HARNESS_PACK_LIVE_CASE("RPC_SERVER_STATUS_live", RPC_SERVER_STATUS, NULL, "GetServerStatus", NULL),
	HARNESS_PACK_LIVE_CASE("RPC_LISTENER_LIST_live", RPC_LISTENER_LIST, NULL, "EnumListener", NULL),
	HARNESS_PACK_LIVE_CASE("RPC_KEY_PAIR_live", RPC_KEY_PAIR, NULL, "GetServerCert", NULL),
	HARNESS_PACK_LIVE_CASE("RPC_STR_live", RPC_STR, NULL, "GetServerCipher", "String"),
	HARNESS_PACK_LIVE_CASE("RPC_CREATE_HUB_live", RPC_CREATE_HUB, HarnessPackLiveHubA, "GetHub", NULL),
	HARNESS_PACK_LIVE_CASE("RPC_ENUM_HUB_live", RPC_ENUM_HUB, NULL, "EnumHub", NULL),
	HARNESS_PACK_LIVE_CASE("RPC_HUB_STATUS_live", RPC_HUB_STATUS, HarnessPackLiveHubA, "GetHubStatus", NULL),
	HARNESS_PACK_LIVE_CASE("RPC_HUB_LOG_live", RPC_HUB_LOG, HarnessPackLiveHubA, "GetHubLog", NULL),
	HARNESS_PACK_LIVE_CASE("RPC_CREATE_LINK_live", RPC_CREATE_LINK, HarnessPackLiveGetLink, "GetLink", NULL),
	HARNESS_PACK_LIVE_CASE("RPC_ENUM_LINK_live", RPC_ENUM_LINK, HarnessPackLiveHubA, "EnumLink", NULL),
	HARNESS_PACK_LIVE_CASE("RPC_LINK_STATUS_live", RPC_LINK_STATUS, HarnessPackLiveLinkStatus, "GetLinkStatus", NULL),
	HARNESS_PACK_LIVE_CASE("RPC_SET_USER_live", RPC_SET_USER, HarnessPackLiveGetUser, "GetUser", NULL),
	HARNESS_PACK_LIVE_CASE("RPC_ENUM_USER_live", RPC_ENUM_USER, HarnessPackLiveHubB, "EnumUser", NULL),
	HARNESS_PACK_LIVE_CASE("RPC_ENUM_SESSION_live", RPC_ENUM_SESSION, HarnessPackLiveHubB, "EnumSession", "Name,Hostname"),
	HARNESS_PACK_LIVE_CASE("RPC_SESSION_STATUS_live", RPC_SESSION_STATUS, HarnessPackLiveSessionStatus, "GetSessionStatus", "Name"),
	HARNESS_PACK_LIVE_CASE("CAPSLIST_live", CAPSLIST, NULL, "GetCaps", NULL),
	HARNESS_PACK_LIVE_CASE("RPC_ADMIN_OPTION_live_admin", RPC_ADMIN_OPTION, HarnessPackLiveHubA, "GetHubAdminOptions", NULL),
	HARNESS_PACK_LIVE_CASE("RPC_ADMIN_OPTION_live_ext", RPC_ADMIN_OPTION, HarnessPackLiveHubA, "GetHubExtOptions", NULL),
	HARNESS_PACK_LIVE_CASE("RPC_ADMIN_OPTION_live_default", RPC_ADMIN_OPTION, NULL, "GetDefaultHubAdminOptions", NULL),
	HARNESS_PACK_LIVE_CASE("SYSLOG_SETTING_live", SYSLOG_SETTING, NULL, "GetSysLog", NULL),
	HARNESS_PACK_LIVE_CASE("RPC_MSG_live_hub", RPC_MSG, HarnessPackLiveHubA, "GetHubMsg", NULL),
	HARNESS_PACK_LIVE_CASE("RPC_MSG_live_admin", RPC_MSG, NULL, "GetAdminMsg", NULL),

	// IN: read quirks of the current code
	HARNESS_PACK_IN_CASE("RPC_SET_USER_in_plainpassword", RPC_SET_USER, HarnessPackBuildSetUserPlainPassword),
	HARNESS_PACK_IN_CASE("RPC_ENUM_LINK_in_targethub", RPC_ENUM_LINK, HarnessPackBuildEnumLinkTargetHub),
	HARNESS_PACK_IN_CASE("RPC_ENUM_IP_TABLE_in_ipv4only", RPC_ENUM_IP_TABLE, HarnessPackBuildEnumIpTableIpv4Only),
	HARNESS_PACK_IN_CASE("RPC_CRL_in_baddigest", RPC_CRL, HarnessPackBuildCrlBadDigest),
	HARNESS_PACK_IN_CASE("RPC_SESSION_STATUS_in_badsessionkey", RPC_SESSION_STATUS, HarnessPackBuildSessionStatusBadSessionKey),
	HARNESS_PACK_IN_CASE("RPC_CREATE_LINK_in_badhashedpassword", RPC_CREATE_LINK, HarnessPackBuildCreateLinkBadHashedPassword),
	HARNESS_PACK_IN_CASE("RPC_ADMIN_OPTION_in_numitem_mismatch", RPC_ADMIN_OPTION, HarnessPackBuildAdminOptionNumItemMismatch),
	HARNESS_PACK_IN_CASE("RPC_ENUM_LOG_FILE_in_numitem_more", RPC_ENUM_LOG_FILE, HarnessPackBuildEnumLogFileNumItemMore),
	HARNESS_PACK_IN_CASE("RPC_ENUM_HUB_in_ragged", RPC_ENUM_HUB, HarnessPackBuildEnumHubRagged),
	HARNESS_PACK_IN_CASE("RPC_CREATE_HUB_in_wrongtype", RPC_CREATE_HUB, HarnessPackBuildCreateHubWrongType),
	HARNESS_PACK_IN_CASE("RPC_MSG_in_nomsg", RPC_MSG, HarnessPackBuildMsgNoMsg),
	HARNESS_PACK_IN_CASE("RPC_STR_in_missing", RPC_STR, HarnessPackBuildStrMissing),

	// IN: intended change of the table engine (spec #28, unchecked NumItem option b)
	HARNESS_PACK_IN_CASE("RPC_ENUM_LICENSE_KEY_in_numitem_overflow", RPC_ENUM_LICENSE_KEY,
		HarnessPackBuildEnumLicenseKeyNumItemOverflow),

	// IN: intended change of the table engine (SEC-6 #96, NumItem capped at the values of the sentinel key)
	HARNESS_PACK_IN_CASE("RPC_ENUM_LOG_FILE_in_numitem_huge", RPC_ENUM_LOG_FILE, HarnessPackBuildEnumLogFileNumItemHuge),
};

////////////////////////////
// Run

// Error of an admin RPC response, found by a linear scan (a lookup would sort the element list)
static UINT HarnessPackGetError(PACK *p)
{
	UINT i;

	if (p == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	for (i = 0;i < LIST_NUM(p->elements);i++)
	{
		ELEMENT *e = LIST_DATA(p->elements, i);

		if ((StrCmpi(e->name, "error") == 0 || StrCmpi(e->name, "error_code") == 0) &&
			e->type == VALUE_INT && e->num_value >= 1 && e->values[0] != NULL && e->values[0]->IntValue != 0)
		{
			return e->values[0]->IntValue;
		}
	}

	return ERR_NO_ERROR;
}

// Write the binary file of this run, then compare it with the golden file (compare mode). Returns the
// round-trip input: the golden file in compare mode (when it exists), else a copy of the file of this run.
static BUF *HarnessCompareGoldenBin(HARNESS *h, char *out_dir, char *golden_dir, char *file_name, BUF *actual, bool update)
{
	char path[MAX_SIZE];
	char tmp[MAX_SIZE];
	BUF *g;
	BUF *ret;

	Format(path, sizeof(path), "%s/%s", out_dir, file_name);
	if (DumpBuf(actual, path) == false)
	{
		Format(tmp, sizeof(tmp), "write %s", path);
		HarnessCheck(h, false, tmp);
	}

	if (update == false)
	{
		Format(path, sizeof(path), "%s/%s", golden_dir, file_name);
		g = ReadDump(path);

		if (g == NULL)
		{
			Format(tmp, sizeof(tmp), "%s matches the golden file (golden file missing: %s)", file_name, path);
			HarnessCheck(h, false, tmp);
		}
		else
		{
			bool same = (g->Size == actual->Size && Cmp(g->Buf, actual->Buf, g->Size) == 0);

			Format(tmp, sizeof(tmp), "%s matches the golden file", file_name);
			if (HarnessCheck(h, same, tmp) == false)
			{
				BUF *w = NewBuf();
				char *s;

				HarnessPackPut(w, "  golden: bytes=");
				Format(tmp, sizeof(tmp), "%u sha1=", g->Size);
				HarnessPackPut(w, tmp);
				HarnessPackPutSha1(w, g->Buf, g->Size);
				HarnessPackPut(w, ", actual: bytes=");
				Format(tmp, sizeof(tmp), "%u sha1=", actual->Size);
				HarnessPackPut(w, tmp);
				HarnessPackPutSha1(w, actual->Buf, actual->Size);
				s = HarnessBufToStr(w);
				Print("%s\n", s);
				Free(s);
				FreeBuf(w);
			}

			SeekBufToBegin(g);

			return g;
		}
	}
	else
	{
		Format(tmp, sizeof(tmp), "%s written (update mode, not compared)", file_name);
		HarnessCheck(h, true, tmp);
	}

	ret = NewBuf();
	WriteBuf(ret, actual->Buf, actual->Size);
	SeekBufToBegin(ret);

	return ret;
}

// [in-out] and [in-out-in-out] sections of one input
static void HarnessPackRoundTrip(BUF *text, HARNESS_PACK_TYPE *y, BUF *input)
{
	PACK *pin, *p1, *pin2, *p2;
	BUF *b1, *b2;
	void *t1, *t2;

	HarnessPackPut(text, "[in-out]\n");

	SeekBufToBegin(input);
	pin = BufToPack(input);
	if (pin == NULL)
	{
		HarnessPackPut(text, "input is not a Pack\n");
		return;
	}

	t1 = ZeroMalloc(y->Size);
	y->In(t1, pin);
	p1 = NewPack();
	y->Out(p1, t1);
	HarnessPackDump(text, p1, NULL);
	HarnessPackPutBytes(text, p1, false);

	HarnessPackPut(text, "[in-out-in-out]\n");

	b1 = PackToBuf(p1);
	SeekBufToBegin(b1);
	pin2 = BufToPack(b1);
	t2 = ZeroMalloc(y->Size);
	if (pin2 != NULL)
	{
		y->In(t2, pin2);
	}
	p2 = NewPack();
	y->Out(p2, t2);
	b2 = PackToBuf(p2);

	if (b1->Size == b2->Size && Cmp(b1->Buf, b2->Buf, b1->Size) == 0)
	{
		HarnessPackPut(text, "same\n");
	}
	else
	{
		HarnessPackDump(text, p2, NULL);
		HarnessPackPutBytes(text, p2, false);
	}

	HarnessPackFreeStruct(y, t1);
	HarnessPackFreeStruct(y, t2);
	FreePack(pin);
	FreePack(p1);
	FreePack(pin2);
	FreePack(p2);
	FreeBuf(b1);
	FreeBuf(b2);
}

// Run one case and compare its two golden files
static void HarnessPackRunCase(HARNESS_PACK_RUN *r, HARNESS_PACK_CASE *c)
{
	HARNESS *h = r->H;
	HARNESS_PACK_TYPE *y = c->Type;
	BUF *text = NewBuf();
	PACK *p0 = NULL;
	BUF *fresh;
	BUF *input;
	char file_name[MAX_SIZE];
	char tmp[MAX_SIZE];
	char *kind = (c->Kind == HARNESS_PACK_SYN ? "syn" : (c->Kind == HARNESS_PACK_LIVE ? "live" : "in"));
	char *s;

	HarnessSetPhase("pack", c->Name);

	Format(tmp, sizeof(tmp), "# %s %s %s\n", c->Name, y->TypeName, kind);
	HarnessPackPut(text, tmp);

	if (c->Kind == HARNESS_PACK_SYN)
	{
		void *t = ZeroMalloc(y->Size);

		if (c->Prep != NULL)
		{
			c->Prep(h, t);
		}

		p0 = NewPack();
		y->Out(p0, t);
		HarnessPackFreeStruct(y, t);
	}
	else if (c->Kind == HARNESS_PACK_LIVE)
	{
		void *t = ZeroMalloc(y->Size);
		PACK *req = NewPack();
		UINT err;

		if (c->Prep != NULL)
		{
			c->Prep(h, t);
		}

		y->Out(req, t);
		HarnessPackFreeStruct(y, t);

		// AdminCall releases the request; the response keeps the server's element order
		p0 = AdminCall(h->Rpc, c->RpcName, req);
		err = HarnessPackGetError(p0);
		if (err != ERR_NO_ERROR)
		{
			Format(tmp, sizeof(tmp), "pack %s: admin RPC %s", c->Name, c->RpcName);
			HarnessCheckErr(h, err, tmp);
			FreePack(p0);
			FreeBuf(text);
			return;
		}
	}

	if (p0 != NULL)
	{
		HarnessPackPut(text, "[out]\n");
		HarnessPackDump(text, p0, c);
		HarnessPackPutBytes(text, p0, c->Kind == HARNESS_PACK_LIVE);

		HarnessPackCanon(r, p0, c->Kind == HARNESS_PACK_LIVE);
		fresh = PackToBuf(p0);
		FreePack(p0);
	}
	else
	{
		PACK *b = c->Build();

		fresh = PackToBuf(b);
		FreePack(b);
	}

	Format(file_name, sizeof(file_name), "pack_%s.pack", c->Name);
	input = HarnessCompareGoldenBin(h, r->OutDir, r->GoldenDir, file_name, fresh, r->Update);

	HarnessPackRoundTrip(text, y, input);

	s = HarnessBufToStr(text);
	Format(file_name, sizeof(file_name), "pack_%s.txt", c->Name);
	HarnessCompareGolden(h, r->OutDir, r->GoldenDir, file_name, s, r->Update);

	Free(s);
	FreeBuf(input);
	FreeBuf(fresh);
	FreeBuf(text);
}

// Compare mode: fail on every pack_* golden file that no case produces
static void HarnessCheckStalePack(HARNESS *h, char *golden_dir)
{
	DIRLIST *d = EnumDir(golden_dir);
	UINT i, j;
	UINT num_stale = 0;
	char expected[MAX_SIZE];
	char tmp[MAX_SIZE];

	if (d == NULL)
	{
		return;
	}

	for (i = 0;i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		bool known = false;

		if (e->Folder || StartWith(e->FileName, "pack_") == false)
		{
			continue;
		}

		for (j = 0;j < sizeof(harness_pack_cases) / sizeof(harness_pack_cases[0]);j++)
		{
			Format(expected, sizeof(expected), "pack_%s.txt", harness_pack_cases[j].Name);
			if (StrCmpi(e->FileName, expected) == 0)
			{
				known = true;
				break;
			}

			Format(expected, sizeof(expected), "pack_%s.pack", harness_pack_cases[j].Name);
			if (StrCmpi(e->FileName, expected) == 0)
			{
				known = true;
				break;
			}
		}

		if (known == false)
		{
			Format(tmp, sizeof(tmp), "stale golden file %s: no pack case produces it", e->FileName);
			HarnessCheck(h, false, tmp);
			num_stale++;
		}
	}

	FreeDir(d);

	if (num_stale == 0)
	{
		HarnessCheck(h, true, "no stale pack_* golden file");
	}
}

// Pack golden phase: every case of the table, then the stale file check
void HarnessPackGolden(HARNESS *h)
{
	HARNESS_PACK_RUN r;
	UINT64 start = Tick64();
	X *x;
	K *k;
	UINT i;

	Print("[golden: admin RPC Packs]\n");
	HarnessSetPhase("pack", NULL);

	Zero(&r, sizeof(r));
	r.H = h;
	HarnessGetFamilyDirs("pack", r.OutDir, sizeof(r.OutDir), r.GoldenDir, sizeof(r.GoldenDir), &r.Update);
	MakeDirEx(r.OutDir);

	// Fixed machine-readable mode line: CI requires compare mode once the golden files are committed
	Print("HARNESS GOLDEN MODE pack %s\n", r.Update ? "update" : "compare");
	Print("  golden directory: %s (%s)\n", r.GoldenDir,
		r.Update ? "update mode: missing or empty, or RANZ_UPDATE_GOLDEN=1" : "compare mode");
	Print("  output directory: %s\n", r.OutDir);

	x = HarnessTestCert();
	k = HarnessTestKey();
	if (HarnessCheck(h, x != NULL && k != NULL, "fixed test certificate and key parsed") == false)
	{
		FreeX(x);
		FreeK(k);
		return;
	}
	r.CertDer = XToBuf(x, false);
	r.KeyDer = KToBuf(k, false, NULL);
	FreeX(x);
	FreeK(k);

	for (i = 0;i < sizeof(harness_pack_cases) / sizeof(harness_pack_cases[0]);i++)
	{
		HarnessPackRunCase(&r, &harness_pack_cases[i]);
	}

	if (r.Update == false)
	{
		HarnessCheckStalePack(h, r.GoldenDir);
	}

	FreeBuf(r.CertDer);
	FreeBuf(r.KeyDer);

	Print("TIME pack_golden %I64u ms (%u cases)\n", Tick64() - start,
		(UINT)(sizeof(harness_pack_cases) / sizeof(harness_pack_cases[0])));
}
