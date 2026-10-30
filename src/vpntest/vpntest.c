// vpntest.c
// VPN Server test program

#include "testlist.h"
#include "Cedar/Account.h"
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

RANZ_TEST("s", server_test, "VPN Server in Test Mode, enter key to graceful stop.");
void server_test(UINT num, char **arg)
{
	Print("VPN Server Test. Press Enter key to stop the VPN Server .\n");

	StInit();

	StStartServer();

	GetLine(NULL, 0);

	StStopServer();

	StFree();
}

RANZ_TEST("memory_leak", memory_leak_test, "Memory leak test: Try to leak one byte by malloc().");
void memory_leak_test(UINT num, char **arg)
{
	char *a = Malloc(1);

	Print("Hello, I am the great dictator of this kingdom!\n");
	Print("Just now I called Malloc(1) and never free! Ha ha ha !!\n");
}

// One NT-hash vector: GenerateNtPasswordHash(password) must give expect_hex
static void nthash_test_check(bool *ok, char *password, char *expect_hex)
{
	UCHAR nt_hash[16];
	char nt_hash_str[64];

	Zero(nt_hash, sizeof(nt_hash));
	GenerateNtPasswordHash(nt_hash, password);
	BinToStr(nt_hash_str, sizeof(nt_hash_str), nt_hash, sizeof(nt_hash));

	if (StrCmpi(nt_hash_str, expect_hex) == 0)
	{
		Print("  [PASS] NtPasswordHash(\"%s\") = %s\n", password, nt_hash_str);
	}
	else
	{
		Print("  [FAIL] NtPasswordHash(\"%s\") = %s (expected %s)\n", password, nt_hash_str, expect_hex);
		*ok = false;
	}
}

// NT-hash (MD4 of the UTF-16LE password, the value stored as AuthNtLmSecureHash) known-answer test
RANZ_TEST("nthash", nthash_test, "NT-hash (MD4 of the UTF-16LE password) against known-answer vectors.");
void nthash_test(UINT num, char **arg)
{
	bool ok = true;
	UCHAR nt_hash[16];
	UCHAR guard[16];

	Print("NT-hash test (RFC 2759 section 9.2 and well-known vectors)\n");

	// RFC 2759 section 9.2: PasswordHash of "clientPass"
	nthash_test_check(&ok, "clientPass", "44EBBA8D5312B8D611474411F56989AE");

	// The empty password is the MD4 of the empty string
	nthash_test_check(&ok, "", "31D6CFE0D16AE931B73C59D7E0C089C0");

	// Well-known NT hash of "password"
	nthash_test_check(&ok, "password", "8846F7EAEE8FB117AD06BDD830B7586C");

	// Missing arguments are ignored
	Zero(nt_hash, sizeof(nt_hash));
	Zero(guard, sizeof(guard));
	GenerateNtPasswordHash(NULL, "password");
	GenerateNtPasswordHash(nt_hash, NULL);
	if (Cmp(nt_hash, guard, sizeof(nt_hash)) == 0)
	{
		Print("  [PASS] a missing argument writes nothing\n");
	}
	else
	{
		Print("  [FAIL] a missing argument wrote the output\n");
		ok = false;
	}

	if (ok)
	{
		Print("NTHASH TEST OK\n");
	}
	else
	{
		Print("NTHASH TEST FAILED\n");
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
RANZ_TEST("stun", stun_test, "STUN Binding Request / Response helpers against RFC 5769 sample messages.");
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
	bool ok = true;

	Print("STUN Binding Request / Response helpers test (RFC 5389, RFC 5769)\n");

	SetIP(&expect_ipv4, 192, 0, 2, 1);
	SetIP6(&expect_ipv6, ipv6_addr);
	SetIP(&expect_mapped, 203, 0, 113, 7);

	// (1) Binding Request
	Zero(request, sizeof(request));
	UINT size = StunBuildBindingRequest(request, sizeof(request), tid);
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

// Size and SHA-256 of the former WaterMark[] array in Cedar/WaterMark.c, also used by fileio_test (runtime.c)
UINT watermark_expect_size = 1411;
char *watermark_expect_sha256 = "96A706BBAB378EC37DFEF21E02B1A3C177FBEBEFFA039EB0EFAC918630DF12A0";

// Watermark test: the hamcore file must hold the bytes of the former WaterMark[] C array
RANZ_TEST("watermark", watermark_test, "Watermark: hamcore watermark.bin size and SHA-256 against the former C array.");
void watermark_test(UINT num, char **arg)
{
	UINT expect_size = watermark_expect_size;
	char *expect_sha256 = watermark_expect_sha256;

	UCHAR hash[SHA256_SIZE];
	char hash_str[SHA256_SIZE * 2 + 1];
	bool ok = true;

	Print("Watermark test (hamcore %s)\n", WATERMARK_FILENAME);

	// Same code path as InitWaterMark() at startup
	BUF *b = LoadWaterMark();
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

// The registered tests (testlist.h): the linker puts the registrations of every test file between these two markers
__declspec(allocate(".rztest$a")) const TEST_LIST *const ranz_test_first = NULL;
__declspec(allocate(".rztest$z")) const TEST_LIST *const ranz_test_last = NULL;

// The registered tests in an array that the caller frees, sorted by name. A NULL between two registrations is padding
// that the linker left. The markers are two objects: their addresses go through volatile pointers, so that the
// compiler does not take the registrations between them for a read past the end of the first object
static const TEST_LIST **TestListCollect(UINT *num_tests)
{
	const TEST_LIST *const *volatile first_marker = &ranz_test_first;
	const TEST_LIST *const *volatile last_marker = &ranz_test_last;
	const TEST_LIST *const *p = (const TEST_LIST *const *)first_marker + 1;
	const TEST_LIST *const *end = (const TEST_LIST *const *)last_marker;
	UINT max_tests = end > p ? (UINT)(end - p) : 0;
	const TEST_LIST **list = Malloc(sizeof(TEST_LIST *) * (max_tests + 1));
	UINT num = 0;

	for (;p < end;p++)
	{
		const TEST_LIST *t = *p;
		UINT i = num;

		if (t == NULL)
		{
			continue;
		}

		// Insertion sort: the tests are few
		while (i > 0 && StrCmpi(list[i - 1]->command_str, t->command_str) > 0)
		{
			list[i] = list[i - 1];
			i--;
		}
		list[i] = t;
		num++;
	}

	*num_tests = num;

	return list;
}

// Test function
int TestMain(char *cmd)
{
	char tmp[MAX_SIZE];
	bool first = true;
	bool exit_now = false;
	int status = 0;
	UINT num_tests = 0;
	const TEST_LIST **tests = TestListCollect(&num_tests);

	Print("Ranz VPN\n");
	Print("vpntest: VPN Server test program\n");
	Print("Usage: vpntest [/memcheck] [command]\n\n");
	Print("Enter '?' or 'help' to show the command list.\n");
	Print("Enter 'list' to print the tests one per line (for .github/scripts/vpntest.ps1).\n");
	Print("Enter 'q' or 'exit' to exit the process.\n\n");
	Print("   - In Jurassic Park: \"It's a UNIX system! I know this!\"\n\n");

	// Two tests under one name could not be told apart
	for (UINT i = 1;i < num_tests;i++)
	{
		if (StrCmpi(tests[i - 1]->command_str, tests[i]->command_str) == 0)
		{
			Print("ERROR: two tests are registered under the name %s\n", tests[i]->command_str);
			Free(tests);
			return 2;
		}
	}

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
			UINT num;
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
				num = num_tests;
				for (UINT i = 0;i < num;i++)
				{
					const TEST_LIST *t = tests[i];
					max_len = MAX(max_len, StrLen(t->command_str));
				}
				for (UINT i = 0;i < num;i++)
				{
					const TEST_LIST *t = tests[i];
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
			else if (StrCmpi(cmd, "list") == 0)
			{
				// One line per test: TESTLIST <name> <tags, comma-separated, or - for none>
				for (UINT i = 0;i < num_tests;i++)
				{
					Print("TESTLIST %s %s\n", tests[i]->command_str, StrLen(tests[i]->tags) == 0 ? "-" : tests[i]->tags);
				}
			}
			else
			{
				num = num_tests;
				for (UINT i = 0;i < num;i++)
				{
					if (!StrCmpi(tests[i]->command_str, cmd))
					{
						char **arg = Malloc(sizeof(char *) * (token->NumTokens - 1));
						for (UINT j = 0;j < token->NumTokens - 1;j++)
						{
							arg[j] = CopyStr(token->Token[j + 1]);
						}
						tests[i]->proc(token->NumTokens - 1, arg);
						for (UINT j = 0;j < token->NumTokens - 1;j++)
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
	Free(tests);
	Print("Exiting...\n\n");
	return status;
}

// Main function
int main(int argc, char *argv[])
{
	bool memchk = false;
	char cmd[MAX_SIZE];
	char *s;
	int status = 0;

	InitProcessCallOnce();

	cmd[0] = 0;
	if (argc >= 2)
	{
		for (UINT i = 1;i < (UINT)argc;i++)
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

	InitMayaqua(memchk, true);
	EnableProbe(true);
	InitCedar();
	SetHamMode();
	wchar_t *args_w = MsCopyProcessArgsW();
	char *args = CopyUniToStr(args_w);
	status = TestMain(args);
	Free(args);
	Free(args_w);
	FreeCedar();
	FreeMayaqua();

	return status;
}

