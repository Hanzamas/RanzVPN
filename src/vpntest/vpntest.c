// vpntest.c
// VPN Server test program

#define VPN_EXE

#include "harness.h"
#include "Cedar/Command.h"
#include "Cedar/MsChapV2.h"
#include "Cedar/Server.h"
#include "Cedar/WaterMark.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Stun.h"

void server_test(UINT num, char **arg)
{
	Print("VPN Server Test. Press Enter key to stop the VPN Server .\n");

	StInit();

	StStartServer(false);

	GetLine(NULL, 0);

	StStopServer();

	StFree();
}

void memory_leak_test(UINT num, char **arg)
{
	char *a = Malloc(1);

	Print("Hello, I am the great dictator of this kingdom!\n");
	Print("Just now I called Malloc(1) and never free! Ha ha ha !!\n");
}

// MS-CHAPv2 / NT-hash helpers test using the RFC 2759 section 9.2 test vectors
void mschapv2_test(UINT num, char **arg)
{
	// RFC 2759 section 9.2 test vectors
	char *username = "User";
	char *password = "clientPass";
	char *auth_challenge_hex = "5B5D7C7D7B3F2F3E3C2C602132262628";	// AuthenticatorChallenge (server)
	char *peer_challenge_hex = "21402324255E262A28295F2B3A337C7E";	// PeerChallenge (client)
	char *expect_challenge8 = "D02E4386BCE91226";
	char *expect_pw_hash = "44EBBA8D5312B8D611474411F56989AE";
	char *expect_pw_hash_hash = "41C00C584BD2D91C4017A2A12FA59F3F";
	char *expect_nt_response = "82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF";
	char *expect_auth_response = "S=407A5589115FD0D6209F510FE9C04566932CDA56";

	BUF *auth_challenge = StrToBin(auth_challenge_hex);
	BUF *peer_challenge = StrToBin(peer_challenge_hex);

	UCHAR nt_hash[16];
	UCHAR nt_hash_hash[16];
	UCHAR challenge8[8];
	UCHAR nt_response[24];
	UCHAR server_response_20[20];

	char nt_hash_str[64];
	char nt_hash_hash_str[64];
	char challenge8_str[64];
	char nt_response_str[128];
	char server_response_hex[64];
	char auth_response_str[128];

	bool ok = true;

	Print("MS-CHAPv2 / NT-hash helpers test (RFC 2759 section 9.2)\n");

	// PasswordHash = NtPasswordHash(Password)
	GenerateNtPasswordHash(nt_hash, password);
	BinToStr(nt_hash_str, sizeof(nt_hash_str), nt_hash, sizeof(nt_hash));
	if (StrCmpi(nt_hash_str, expect_pw_hash) == 0)
	{
		Print("  [PASS] PasswordHash = %s\n", nt_hash_str);
	}
	else
	{
		Print("  [FAIL] PasswordHash = %s (expected %s)\n", nt_hash_str, expect_pw_hash);
		ok = false;
	}

	// PasswordHashHash = NtPasswordHash(PasswordHash)
	GenerateNtPasswordHashHash(nt_hash_hash, nt_hash);
	BinToStr(nt_hash_hash_str, sizeof(nt_hash_hash_str), nt_hash_hash, sizeof(nt_hash_hash));
	if (StrCmpi(nt_hash_hash_str, expect_pw_hash_hash) == 0)
	{
		Print("  [PASS] PasswordHashHash = %s\n", nt_hash_hash_str);
	}
	else
	{
		Print("  [FAIL] PasswordHashHash = %s (expected %s)\n", nt_hash_hash_str, expect_pw_hash_hash);
		ok = false;
	}

	// ChallengeHash = SHA1(PeerChallenge + AuthenticatorChallenge + UserName)[0..7]
	MsChapV2_GenerateChallenge8(challenge8, peer_challenge->Buf, auth_challenge->Buf, username);
	BinToStr(challenge8_str, sizeof(challenge8_str), challenge8, sizeof(challenge8));
	if (StrCmpi(challenge8_str, expect_challenge8) == 0)
	{
		Print("  [PASS] Challenge = %s\n", challenge8_str);
	}
	else
	{
		Print("  [FAIL] Challenge = %s (expected %s)\n", challenge8_str, expect_challenge8);
		ok = false;
	}

	// NT-Response = ChallengeResponse(Challenge, PasswordHash)
	MsChapV2Client_GenerateResponse(nt_response, challenge8, nt_hash);
	BinToStr(nt_response_str, sizeof(nt_response_str), nt_response, sizeof(nt_response));
	if (StrCmpi(nt_response_str, expect_nt_response) == 0)
	{
		Print("  [PASS] NT-Response = %s\n", nt_response_str);
	}
	else
	{
		Print("  [FAIL] NT-Response = %s (expected %s)\n", nt_response_str, expect_nt_response);
		ok = false;
	}

	// AuthenticatorResponse = "S=" + uppercase hex of the 20-byte server response
	MsChapV2Server_GenerateResponse(server_response_20, nt_hash_hash, nt_response, challenge8);
	BinToStr(server_response_hex, sizeof(server_response_hex), server_response_20, sizeof(server_response_20));
	Format(auth_response_str, sizeof(auth_response_str), "S=%s", server_response_hex);
	if (StrCmpi(auth_response_str, expect_auth_response) == 0)
	{
		Print("  [PASS] AuthenticatorResponse = %s\n", auth_response_str);
	}
	else
	{
		Print("  [FAIL] AuthenticatorResponse = %s (expected %s)\n", auth_response_str, expect_auth_response);
		ok = false;
	}

	// Round-trip ParseAndExtractMsChapV2InfoFromPassword against an IPC MS-CHAPv2 password string
	{
		char pw[MAX_SIZE];
		IPC_MSCHAP_V2_AUTHINFO d;

		Format(pw, sizeof(pw), "%s%s:%s:%s:%s:%s", IPC_PASSWORD_MSCHAPV2_TAG, username,
		       auth_challenge_hex, peer_challenge_hex, nt_response_str, "0000000000000000");

		if (ParseAndExtractMsChapV2InfoFromPassword(&d, pw) &&
		        StrCmp(d.MsChapV2_PPPUsername, username) == 0 &&
		        Cmp(d.MsChapV2_ServerChallenge, auth_challenge->Buf, 16) == 0 &&
		        Cmp(d.MsChapV2_ClientChallenge, peer_challenge->Buf, 16) == 0 &&
		        Cmp(d.MsChapV2_ClientResponse, nt_response, 24) == 0)
		{
			Print("  [PASS] ParseAndExtractMsChapV2InfoFromPassword round-trip\n");
		}
		else
		{
			Print("  [FAIL] ParseAndExtractMsChapV2InfoFromPassword round-trip\n");
			ok = false;
		}
	}

	FreeBuf(auth_challenge);
	FreeBuf(peer_challenge);

	if (ok)
	{
		Print("MSCHAPV2 TEST OK\n");
	}
	else
	{
		Print("MSCHAPV2 TEST FAILED\n");
	}
}

// Print the result of one STUN test case
void stun_test_check(bool *ok, bool passed, char *name)
{
	if (passed)
	{
		Print("  [PASS] %s\n", name);
	}
	else
	{
		Print("  [FAIL] %s\n", name);
		*ok = false;
	}
}

// Parse a STUN response and compare the mapped address with the expected one
bool stun_test_parse(UCHAR *buf, UINT size, UCHAR *transaction_id, IP *expect_ip, UINT expect_port)
{
	IP ip;
	UINT port = 0;
	char ip_str[MAX_SIZE];

	Zero(&ip, sizeof(ip));

	if (StunParseBindingResponse(buf, size, transaction_id, &ip, &port) == false)
	{
		Print("    parse failed\n");
		return false;
	}

	IPToStr(ip_str, sizeof(ip_str), &ip);
	Print("    mapped address: %s port %u\n", ip_str, port);

	return (CmpIpAddr(&ip, expect_ip) == 0 && port == expect_port);
}

// STUN Binding Request / Response helpers test (RFC 5389, RFC 5769 sample messages, no network access)
void stun_test(UINT num, char **arg)
{
	// Transaction ID of the RFC 5769 sample messages
	UCHAR tid[STUN_TRANSACTION_ID_SIZE] =
	{
		0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
	};

	// RFC 5769 section 2.2: sample IPv4 response (192.0.2.1 port 32853)
	UCHAR rfc5769_ipv4[] =
	{
		0x01, 0x01, 0x00, 0x3c,		// Response type and message length
		0x21, 0x12, 0xa4, 0x42,		// Magic cookie
		0xb7, 0xe7, 0xa7, 0x01,		// Transaction ID
		0xbc, 0x34, 0xd6, 0x86,
		0xfa, 0x87, 0xdf, 0xae,
		0x80, 0x22, 0x00, 0x0b,		// SOFTWARE attribute header
		0x74, 0x65, 0x73, 0x74,		// UTF-8 server name
		0x20, 0x76, 0x65, 0x63,
		0x74, 0x6f, 0x72, 0x20,
		0x00, 0x20, 0x00, 0x08,		// XOR-MAPPED-ADDRESS attribute header
		0x00, 0x01, 0xa1, 0x47,		// Address family (IPv4) and xor'd mapped port number
		0xe1, 0x12, 0xa6, 0x43,		// Xor'd mapped IPv4 address
		0x00, 0x08, 0x00, 0x14,		// MESSAGE-INTEGRITY attribute header
		0x2b, 0x91, 0xf5, 0x99,		// HMAC-SHA1 fingerprint
		0xfd, 0x9e, 0x90, 0xc3,
		0x8c, 0x74, 0x89, 0xf9,
		0x2a, 0xf9, 0xba, 0x53,
		0xf0, 0x6b, 0xe7, 0xd7,
		0x80, 0x28, 0x00, 0x04,		// FINGERPRINT attribute header
		0xc0, 0x7d, 0x4c, 0x96,		// CRC32 fingerprint
	};

	// XOR-MAPPED-ADDRESS of the RFC 5769 section 2.3 sample (2001:db8:1234:5678:11:2233:4455:6677 port 32853)
	UCHAR xor_mapped_ipv6[] =
	{
		0x01, 0x01, 0x00, 0x18,		// Binding Success Response, message length 24
		0x21, 0x12, 0xa4, 0x42,		// Magic cookie
		0xb7, 0xe7, 0xa7, 0x01,		// Transaction ID
		0xbc, 0x34, 0xd6, 0x86,
		0xfa, 0x87, 0xdf, 0xae,
		0x00, 0x20, 0x00, 0x14,		// XOR-MAPPED-ADDRESS attribute header
		0x00, 0x02, 0xa1, 0x47,		// Address family (IPv6) and xor'd mapped port number
		0x01, 0x13, 0xa9, 0xfa,		// Xor'd mapped IPv6 address
		0xa5, 0xd3, 0xf1, 0x79,
		0xbc, 0x25, 0xf4, 0xb5,
		0xbe, 0xd2, 0xb9, 0xd9,
	};

	// MAPPED-ADDRESS only (203.0.113.7 port 3478), after an unknown attribute that needs padding
	UCHAR mapped_only[] =
	{
		0x01, 0x01, 0x00, 0x18,		// Binding Success Response, message length 24
		0x21, 0x12, 0xa4, 0x42,		// Magic cookie
		0xb7, 0xe7, 0xa7, 0x01,		// Transaction ID
		0xbc, 0x34, 0xd6, 0x86,
		0xfa, 0x87, 0xdf, 0xae,
		0x80, 0x23, 0x00, 0x05,		// Unknown comprehension-optional attribute, length 5
		0x41, 0x42, 0x43, 0x44,
		0x45, 0x00, 0x00, 0x00,		// Last value byte and 3 bytes of padding
		0x00, 0x01, 0x00, 0x08,		// MAPPED-ADDRESS attribute header
		0x00, 0x01, 0x0d, 0x96,		// Address family (IPv4) and port number
		0xcb, 0x00, 0x71, 0x07,		// IPv4 address
	};

	// MAPPED-ADDRESS (203.0.113.7 port 3478) followed by XOR-MAPPED-ADDRESS (192.0.2.1 port 32853)
	UCHAR both_mapped[] =
	{
		0x01, 0x01, 0x00, 0x18,		// Binding Success Response, message length 24
		0x21, 0x12, 0xa4, 0x42,		// Magic cookie
		0xb7, 0xe7, 0xa7, 0x01,		// Transaction ID
		0xbc, 0x34, 0xd6, 0x86,
		0xfa, 0x87, 0xdf, 0xae,
		0x00, 0x01, 0x00, 0x08,		// MAPPED-ADDRESS attribute header
		0x00, 0x01, 0x0d, 0x96,		// Address family (IPv4) and port number
		0xcb, 0x00, 0x71, 0x07,		// IPv4 address
		0x00, 0x20, 0x00, 0x08,		// XOR-MAPPED-ADDRESS attribute header
		0x00, 0x01, 0xa1, 0x47,		// Address family (IPv4) and xor'd mapped port number
		0xe1, 0x12, 0xa6, 0x43,		// Xor'd mapped IPv4 address
	};

	// XOR-MAPPED-ADDRESS whose length (12) runs past the end of the message
	UCHAR truncated_attr[] =
	{
		0x01, 0x01, 0x00, 0x0c,		// Binding Success Response, message length 12
		0x21, 0x12, 0xa4, 0x42,		// Magic cookie
		0xb7, 0xe7, 0xa7, 0x01,		// Transaction ID
		0xbc, 0x34, 0xd6, 0x86,
		0xfa, 0x87, 0xdf, 0xae,
		0x00, 0x20, 0x00, 0x0c,		// XOR-MAPPED-ADDRESS attribute header, length 12
		0x00, 0x01, 0xa1, 0x47,
		0xe1, 0x12, 0xa6, 0x43,
	};

	UCHAR ipv6_addr[16] =
	{
		0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	};

	UCHAR expect_request_head[8] = {0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42};
	UCHAR request[STUN_HEADER_SIZE + 4];
	UCHAR wrong_tid[STUN_TRANSACTION_ID_SIZE];
	UCHAR tmp[sizeof(rfc5769_ipv4)];
	char host[MAX_HOST_NAME_LEN + 1];
	IP expect_ipv4, expect_ipv6, expect_mapped;
	IP ip;
	UINT port;
	UINT size;
	bool ok = true;

	Print("STUN Binding Request / Response helpers test (RFC 5389, RFC 5769)\n");

	SetIP(&expect_ipv4, 192, 0, 2, 1);
	SetIP6(&expect_ipv6, ipv6_addr);
	SetIP(&expect_mapped, 203, 0, 113, 7);

	// (1) Binding Request
	Zero(request, sizeof(request));
	size = StunBuildBindingRequest(request, sizeof(request), tid);
	stun_test_check(&ok, size == STUN_HEADER_SIZE &&
		Cmp(request, expect_request_head, sizeof(expect_request_head)) == 0 &&
		Cmp(request + 8, tid, STUN_TRANSACTION_ID_SIZE) == 0,
		"Binding Request: 20 bytes, type 0x0001, length 0, cookie 21 12 A4 42, transaction ID copied");

	stun_test_check(&ok, StunBuildBindingRequest(request, STUN_HEADER_SIZE - 1, tid) == 0,
		"Binding Request: too small buffer is rejected");

	// (2) RFC 5769 section 2.2 sample IPv4 response (SOFTWARE, MESSAGE-INTEGRITY and FINGERPRINT are ignored)
	stun_test_check(&ok, stun_test_parse(rfc5769_ipv4, sizeof(rfc5769_ipv4), tid, &expect_ipv4, 32853),
		"RFC 5769 sample IPv4 response: XOR-MAPPED-ADDRESS 192.0.2.1 port 32853");

	stun_test_check(&ok, stun_test_parse(xor_mapped_ipv6, sizeof(xor_mapped_ipv6), tid, &expect_ipv6, 32853),
		"XOR-MAPPED-ADDRESS IPv6 2001:db8:1234:5678:11:2233:4455:6677 port 32853");

	// (3) MAPPED-ADDRESS fallback and XOR-MAPPED-ADDRESS preference
	stun_test_check(&ok, stun_test_parse(mapped_only, sizeof(mapped_only), tid, &expect_mapped, 3478),
		"MAPPED-ADDRESS only response falls back to 203.0.113.7 port 3478");

	stun_test_check(&ok, stun_test_parse(both_mapped, sizeof(both_mapped), tid, &expect_ipv4, 32853),
		"XOR-MAPPED-ADDRESS is preferred over MAPPED-ADDRESS");

	// (4) Rejected responses
	Copy(wrong_tid, tid, sizeof(wrong_tid));
	wrong_tid[STUN_TRANSACTION_ID_SIZE - 1] ^= 0x01;
	stun_test_check(&ok, StunParseBindingResponse(rfc5769_ipv4, sizeof(rfc5769_ipv4), wrong_tid, &ip, &port) == false,
		"Wrong transaction ID is rejected");

	stun_test_check(&ok, StunParseBindingResponse(truncated_attr, sizeof(truncated_attr), tid, &ip, &port) == false,
		"Truncated attribute is rejected");

	stun_test_check(&ok, StunParseBindingResponse(rfc5769_ipv4, sizeof(rfc5769_ipv4) - 4, tid, &ip, &port) == false &&
		StunParseBindingResponse(rfc5769_ipv4, STUN_HEADER_SIZE - 1, tid, &ip, &port) == false,
		"Truncated message is rejected");

	Copy(tmp, rfc5769_ipv4, sizeof(tmp));
	tmp[7] ^= 0x01;
	stun_test_check(&ok, StunParseBindingResponse(tmp, sizeof(tmp), tid, &ip, &port) == false,
		"Wrong magic cookie is rejected");

	Copy(tmp, rfc5769_ipv4, sizeof(tmp));
	tmp[1] = 0x11;
	stun_test_check(&ok, StunParseBindingResponse(tmp, sizeof(tmp), tid, &ip, &port) == false,
		"Binding Error Response (0x0111) is rejected");

	Copy(tmp, rfc5769_ipv4, sizeof(tmp));
	tmp[1] = 0x01;
	tmp[0] = 0x00;
	stun_test_check(&ok, StunParseBindingResponse(tmp, sizeof(tmp), tid, &ip, &port) == false,
		"Binding Request (0x0001) is rejected");

	Copy(tmp, both_mapped, sizeof(both_mapped));
	tmp[25] = 0x03;
	stun_test_check(&ok, StunParseBindingResponse(tmp, sizeof(both_mapped), tid, &ip, &port) == false,
		"Unknown address family (0x03) is rejected");

	Copy(tmp, both_mapped, sizeof(both_mapped));
	tmp[23] = 0x04;
	stun_test_check(&ok, StunParseBindingResponse(tmp, sizeof(both_mapped), tid, &ip, &port) == false,
		"MAPPED-ADDRESS too short for the IPv4 family (length 4) is rejected");

	Copy(tmp, both_mapped, sizeof(both_mapped));
	tmp[3] = 0x16;
	stun_test_check(&ok, StunParseBindingResponse(tmp, sizeof(both_mapped), tid, &ip, &port) == false,
		"Message length not a multiple of 4 (22) is rejected");

	// (5) STUN server string
	stun_test_check(&ok, StunParseServerStr("stun.example.com", host, sizeof(host), &port) &&
		StrCmp(host, "stun.example.com") == 0 && port == STUN_DEFAULT_PORT,
		"Server string: host name with the default port 3478");

	stun_test_check(&ok, StunParseServerStr("192.0.2.1:19302", host, sizeof(host), &port) &&
		StrCmp(host, "192.0.2.1") == 0 && port == 19302,
		"Server string: host:port");

	stun_test_check(&ok, StunParseServerStr("[2001:db8::1]:3479", host, sizeof(host), &port) &&
		StrCmp(host, "2001:db8::1") == 0 && port == 3479,
		"Server string: [IPv6 address]:port");

	stun_test_check(&ok, StunParseServerStr("2001:db8::1", host, sizeof(host), &port) &&
		StrCmp(host, "2001:db8::1") == 0 && port == STUN_DEFAULT_PORT,
		"Server string: bare IPv6 address with the default port 3478");

	stun_test_check(&ok, StunParseServerStr("", host, sizeof(host), &port) == false &&
		StunParseServerStr("host:", host, sizeof(host), &port) == false &&
		StunParseServerStr("host:0", host, sizeof(host), &port) == false &&
		StunParseServerStr("host:65536", host, sizeof(host), &port) == false &&
		StunParseServerStr("host:34a", host, sizeof(host), &port) == false &&
		StunParseServerStr("[2001:db8::1", host, sizeof(host), &port) == false &&
		StunParseServerStr("[2001:db8::1]3478", host, sizeof(host), &port) == false,
		"Server string: invalid strings are rejected");

	if (ok)
	{
		Print("STUN TEST OK\n");
	}
	else
	{
		Print("STUN TEST FAILED\n");
	}
}

// Mayaqua runtime stress test (stress.c)
void stress_test(UINT num, char **arg);

// Named runtime tests of the Windows-native runtime, spec #30 (runtime.c)
void tickorigin_test(UINT num, char **arg);
void timeenc_test(UINT num, char **arg);
void nullsafe_test(UINT num, char **arg);
void fileio_test(UINT num, char **arg);
void threadpool_test(UINT num, char **arg);
void dns_test(UINT num, char **arg);

// Named string test of NAT-4, #90 (strtest.c)
void str_test(UINT num, char **arg);

// Size and SHA-256 of the former WaterMark[] array in Cedar/WaterMark.c, also used by fileio_test (runtime.c)
UINT watermark_expect_size = 1411;
char *watermark_expect_sha256 = "96A706BBAB378EC37DFEF21E02B1A3C177FBEBEFFA039EB0EFAC918630DF12A0";

// Watermark test: the hamcore file must hold the bytes of the former WaterMark[] C array
void watermark_test(UINT num, char **arg)
{
	UINT expect_size = watermark_expect_size;
	char *expect_sha256 = watermark_expect_sha256;

	UCHAR hash[SHA256_SIZE];
	char hash_str[SHA256_SIZE * 2 + 1];
	bool ok = true;
	BUF *b;

	Print("Watermark test (hamcore %s)\n", WATERMARK_FILENAME);

	// Same code path as InitWaterMark() at startup
	b = LoadWaterMark();
	if (b == NULL)
	{
		Print("  [FAIL] LoadWaterMark(): file missing, or its size or SHA-256 is wrong\n");
		Print("WATERMARK TEST FAILED\n");
		return;
	}

	if (b->Size == expect_size)
	{
		Print("  [PASS] Size = %u\n", b->Size);
	}
	else
	{
		Print("  [FAIL] Size = %u (expected %u)\n", b->Size, expect_size);
		ok = false;
	}

	Sha2_256(hash, b->Buf, b->Size);
	BinToStr(hash_str, sizeof(hash_str), hash, sizeof(hash));
	if (StrCmpi(hash_str, expect_sha256) == 0)
	{
		Print("  [PASS] SHA-256 = %s\n", hash_str);
	}
	else
	{
		Print("  [FAIL] SHA-256 = %s (expected %s)\n", hash_str, expect_sha256);
		ok = false;
	}

	// The buffer loaded by InitCedar() must hold the same bytes
	if (WaterMark != NULL && WaterMarkSize == b->Size && Cmp(WaterMark, b->Buf, b->Size) == 0)
	{
		Print("  [PASS] Startup buffer matches the file\n");
	}
	else
	{
		Print("  [FAIL] Startup buffer does not match the file\n");
		ok = false;
	}

	FreeBuf(b);

	if (ok)
	{
		Print("WATERMARK TEST OK\n");
	}
	else
	{
		Print("WATERMARK TEST FAILED\n");
	}
}

// The list of test functions
// Test function definition list
typedef void (TEST_PROC)(UINT num, char **arg);

typedef struct TEST_LIST
{
	char *command_str;
	TEST_PROC *proc;
	char *help;
} TEST_LIST;

TEST_LIST test_list[] =
{
	{"s", server_test, "VPN Server in Test Mode, enter key to graceful stop."},
	{"memory_leak", memory_leak_test, "Memory leak test: Try to leak one byte by malloc()."},
	{"mschapv2", mschapv2_test, "MS-CHAPv2 / NT-hash helpers against RFC 2759 test vectors."},
	{"stun", stun_test, "STUN Binding Request / Response helpers against RFC 5769 sample messages."},
	{"harness", harness_test, "In-process server: hubs, cascade, frames, vpncmd golden outputs, config round-trip."},
	{"bench", bench_test, "Cascade frame throughput and Pack encode/decode benchmark (informational)."},
	{"stress", stress_test, "Mayaqua runtime stress test: stress [timing] [case ...]."},
	{"watermark", watermark_test, "Watermark: hamcore watermark.bin size and SHA-256 against the former C array."},
	{"tickorigin", tickorigin_test, "Tick64 origin: the first value is at least 1 and at most the process age."},
	{"timeenc", timeenc_test, "Time encoding: SystemTime64/LocalTime64 against the OS clock, fixed-input conversions."},
	{"nullsafe", nullsafe_test, "NULL safety of the LOCK, LIST, COUNTER, REF and EVENT functions."},
	{"fileio", fileio_test, "FileIO: @, $ and | prefixes, path separator, sharing modes, reads past the end."},
	{"threadpool", threadpool_test, "Thread pool: job pickup, host thread id and COM, idle reuse, many waiters, host handles."},
	{"dns", dns_test, "DNS: localhost and IP literals answered at once, the computer name through the resolver thread."},
	{"certdl", certdl_test, "SetServerCert downloads the issuer certificate from a loopback listener (DownloadCert)."},
	{"str", str_test, "String functions: truncation and return values of copy, concatenate, format, search, tokens, compare."},
};

// Test function
int TestMain(char *cmd)
{
	char tmp[MAX_SIZE];
	bool first = true;
	bool exit_now = false;
	int status = 0;

	Print("Ranz VPN\n");
	Print("vpntest: VPN Server test program\n");
	Print("Usage: vpntest [/memcheck] [command]\n\n");
	Print("Enter '?' or 'help' to show the command list.\n");
	Print("Enter 'q' or 'exit' to exit the process.\n\n");
	Print("   - In Jurassic Park: \"It's a UNIX system! I know this!\"\n\n");

#ifdef	OS_WIN32
	MsSetEnableMinidump(true);
#endif	// OS_WIN32

	while (true)
	{
		Print("TEST>");
		if (first && StrLen(cmd) != 0 && g_memcheck == false)
		{
			first = false;
			StrCpy(tmp, sizeof(tmp), cmd);
			exit_now = true;
			Print("%s\n", cmd);
		}
		else
		{
			GetLine(tmp, sizeof(tmp));
		}
		Trim(tmp);
		if (StrLen(tmp) != 0)
		{
			UINT i, num;
			bool b = false;
			TOKEN_LIST *token = ParseCmdLine(tmp);
			char *cmd = token->Token[0];
			if (!StrCmpi(cmd, "exit") || !StrCmpi(cmd, "quit") || !StrCmpi(cmd, "q"))
			{
				FreeToken(token);
				break;
			}
			else if (StrCmpi(cmd, "?") == 0 || StrCmpi(cmd, "help") == 0)
			{
				UINT max_len = 0;
				Print("Available commands:\n\n");
				num = sizeof(test_list) / sizeof(TEST_LIST);
				for (i = 0;i < num;i++)
				{
					TEST_LIST *t = &test_list[i];
					max_len = MAX(max_len, StrLen(t->command_str));
				}
				for (i = 0;i < num;i++)
				{
					TEST_LIST *t = &test_list[i];
					UINT len = StrLen(t->command_str);
					char *pad = NULL;
					if (len < max_len)
					{
						UINT padlen = max_len - len;
						pad = MakeCharArray(' ', padlen);
					}
					Print(" '%s'%s : %s\n", t->command_str, pad == NULL ? "" : pad, t->help);
					if (pad != NULL)
					{
						Free(pad);
					}
				}
				Print("\n");
			}
			else if (StartWith(tmp, "vpncmd"))
			{
				wchar_t *s = CopyStrToUni(tmp);
				CommandMain(s);
				Free(s);
			}
			else
			{
				num = sizeof(test_list) / sizeof(TEST_LIST);
				for (i = 0;i < num;i++)
				{
					if (!StrCmpi(test_list[i].command_str, cmd))
					{
						char **arg = Malloc(sizeof(char *) * (token->NumTokens - 1));
						UINT j;
						for (j = 0;j < token->NumTokens - 1;j++)
						{
							arg[j] = CopyStr(token->Token[j + 1]);
						}
						test_list[i].proc(token->NumTokens - 1, arg);
						for (j = 0;j < token->NumTokens - 1;j++)
						{
							Free(arg[j]);
						}
						Free(arg);
						b = true;
						Print("\n");
						break;
					}
				}
				if (b == false)
				{
					status = 2;
					Print("Invalid Command: %s\n\n", cmd);
				}
			}
			FreeToken(token);

			if (exit_now)
			{
				break;
			}
		}
	}
	Print("Exiting...\n\n");
	return status;
}

// Main function
int main(int argc, char *argv[])
{
	bool memchk = false;
	UINT i;
	char cmd[MAX_SIZE];
	char *s;
	int status = 0;

	InitProcessCallOnce();

	cmd[0] = 0;
	if (argc >= 2)
	{
		for (i = 1;i < (UINT)argc;i++)
		{
			s = argv[i];
			if (s[0] == '/')
			{
				if (!StrCmpi(s, "/memcheck"))
				{
					memchk = true;
				}
			}
			else
			{
				StrCpy(cmd, sizeof(cmd), &s[0]);
			}
		}
	}

	InitMayaqua(memchk, true, argc, argv);
	EnableProbe(true);
	InitCedar();
	SetHamMode();
	status = TestMain(cmdline);
	FreeCedar();
	FreeMayaqua();

	return status;
}

