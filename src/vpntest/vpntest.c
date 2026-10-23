// vpntest.c
// VPN Server test program

#include "harness.h"
#include "Cedar/Command.h"
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

void server_test(UINT num, char **arg)
{
	Print("VPN Server Test. Press Enter key to stop the VPN Server .\n");

	StInit();

	StStartServer();

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

// Known-answer tests of the hash, cipher and random primitives, ticket #87 (crypto.c)
void crypto_test(UINT num, char **arg);

// Mayaqua runtime stress test (stress.c)
void stress_test(UINT num, char **arg);

// Named runtime tests of the Windows-native runtime, spec #30 (runtime.c)
void tickorigin_test(UINT num, char **arg);
void timeenc_test(UINT num, char **arg);
void nullsafe_test(UINT num, char **arg);
void charset_test(UINT num, char **arg);
void fileio_test(UINT num, char **arg);
void resources_test(UINT num, char **arg);
void threadpool_test(UINT num, char **arg);
void dns_test(UINT num, char **arg);
void trace_test(UINT num, char **arg);
void eventlog_test(UINT num, char **arg);

// Named string test of NAT-4, #90 (strtest.c)
void str_test(UINT num, char **arg);

// Named UDP Acceleration receive test of FIX-1, #97 (udpaccel.c)
void udpaccel_test(UINT num, char **arg);

// Named SeLow test of FIX-2, #98 (selowtest.c)
void selow_test(UINT num, char **arg);

// Named DLL search order test of FIX-4, #100 (dllsearch.c)
void dllsearch_test(UINT num, char **arg);

// Named machine identity test of FIX-5, #101 (machineid.c)
void machineid_test(UINT num, char **arg);

// Named VM detection test of FIX-7, #103 (vmdetect.c)
void vmdetect_test(UINT num, char **arg);

// Named TCP/IP packet test of SEC-1, #96 (tcpiptest.c)
void tcpip_test(UINT num, char **arg);

// Named X.509 and certificate signature test of SEC-2, #96 (x509test.c)
void x509_test(UINT num, char **arg);

// Named BUF and binary configuration bounds test of SEC-3, #96 (bufbounds.c)
void bufbounds_test(UINT num, char **arg);

// Named keepalive span and client Pack size cap tests of SEC-4, #96 (keepalive.c, packcap.c)
void keepalive_test(UINT num, char **arg);
void packcap_test(UINT num, char **arg);

// Named StorePacket test of SEC-5, #96 (storepacket.c)
void storepacket_test(UINT num, char **arg);

// Named console input test of SEC-7, #96 (consoleline.c)
void consoleline_test(UINT num, char **arg);

// Named temp directory and string table test of SEC-8, #96 (tempdir.c)
void tempdir_test(UINT num, char **arg);

// Named log writer, syslog and eraser tests of PKG-4, #108 (logtest.c)
void logwriter_test(UINT num, char **arg);
void logbound_test(UINT num, char **arg);
void slog_test(UINT num, char **arg);
void eraser_test(UINT num, char **arg);

// Named login path tests of PKG-6, #110 (login.c)
void authtype_test(UINT num, char **arg);
void acpassword_test(UINT num, char **arg);
void sigleak_test(UINT num, char **arg);

// Named listeners test of spec #43, cases 1 to 5 of REL-3, #48, and case 6 of REL-4, #49 (listeners.c)
void listeners_test(UINT num, char **arg);

// Named packet parser tests of FND-38, FND-39 and FND-54, #113 and #117 (pkttest.c)
void pktparse_test(UINT num, char **arg);
void vlantpid_test(UINT num, char **arg);
void icmpv6ns_test(UINT num, char **arg);

// Named PACK decoder bounds test of FND-42, #114 (packdecode.c)
void pack_decode_bounds_test(UINT num, char **arg);

// Named string table loader test of FND-43, #114 (tablecache.c)
void tablecache_test(UINT num, char **arg);

// Named registry test of FND-64, #121 (registry.c)
void registry_test(UINT num, char **arg);

// Named certificate signature test of FND-80, #127 (x509test.c)
void certsig_test(UINT num, char **arg);

// Named root certificate and X509ToX ownership test of FND-81, #127 (x509test.c)
void x509root_test(UINT num, char **arg);

// Named RSA client certificate signature test of FND-83, #127 (x509test.c)
void rsasig_test(UINT num, char **arg);

// Named chain_certs cache test of FND-139, #145 (chaincerts.c)
void chaincerts_test(UINT num, char **arg);

// Named shared server SSL_CTX test of FND-140, #145 (tlsctx.c)
void tlsctx_test(UINT num, char **arg);

// Named OS information test of FND-203, #166 (osinfo.c)
void osinfo_test(UINT num, char **arg);

// Named byte-order test of FND-152, #149 (endian.c)
void endian_test(UINT num, char **arg);

// Named service argument test of FND-205, #167 (svcargs.c)
void svcargs_test(UINT num, char **arg);

// Named FIFO and queue test of FND-215, #174 (fifo.c)
void fifo_test(UINT num, char **arg);

// Named hardened licence gate test of SEC-4, #282 (harden.c)
void harden_test(UINT num, char **arg);

// Named node tests of CORE-F3, #63 (nodetest.c)
void node_test(UINT num, char **arg);
void nodesvc_test(UINT num, char **arg);

// Named node Login test of CORE-F2, #62 (nodelogin.c)
void nodelogin_test(UINT num, char **arg);

// Named configuration store test of CORE-F5, #65 (storetest.c)
void store_test(UINT num, char **arg);

// Named BGP sidecar test of CORE-S7-1, #82 (bgptest.c)
void bgp_test(UINT num, char **arg);

// Named self-integrity test of SEC-3, #281 (selfint.c)
void selfint_test(UINT num, char **arg);

// Named transport test of CORE-F4, #64 (transporttest.c)
void transport_test(UINT num, char **arg);

// Named QUIC transport test of CORE-S1-1, #67 (quictest.c)
void quic_test(UINT num, char **arg);

// Named Noise-to-Hub test of CORE-S1-2, #68 (noisehub.c)
void noisehub_test(UINT num, char **arg);

// Named TLS transport test of CORE-S2-1, #69 (tlstest.c)
void tls_test(UINT num, char **arg);

// Named lossy-link test of CORE-S2-1, #69 (lossylink.c)
void lossylink_test(UINT num, char **arg);

// Named HTTP listener test of REL-6, #51 (httplistener.c)
void httplistener_test(UINT num, char **arg);

// Named default VRF tracer of SDN-3, #179 (sdntrace.c)
void sdntrace_test(UINT num, char **arg);

// Named VRF forwarding table test of SDN-4, #180 (vrftest.c)
void vrf_test(UINT num, char **arg);

// Named VXLAN test of SDN-62, #289 (vxlantest.c)
void vxlan_test(UINT num, char **arg);

// Named shaping test of SDN-20, #196 (shapetest.c)
void shape_test(UINT num, char **arg);

// Named switch test and switch benchmark of CORE-S4-1, #74 (switchtest.c)
void switch_test(UINT num, char **arg);
void switchbench_test(UINT num, char **arg);

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
	{"nthash", nthash_test, "NT-hash (MD4 of the UTF-16LE password) against known-answer vectors."},
	{"crypto", crypto_test, "MD4, MD5, SHA-0, SHA-1, SHA-256, RC4 and Rand against known-answer vectors."},
	{"stun", stun_test, "STUN Binding Request / Response helpers against RFC 5769 sample messages."},
	{"harness", harness_test, "In-process server: hubs, cascade, frames, vpncmd golden outputs, config round-trip."},
	{"bench", bench_test, "Cascade frame throughput and Pack encode/decode benchmark (informational)."},
	{"stress", stress_test, "Mayaqua runtime stress test: stress [timing] [case ...]."},
	{"watermark", watermark_test, "Watermark: hamcore watermark.bin size and SHA-256 against the former C array."},
	{"tickorigin", tickorigin_test, "Tick64 origin: the first value is at least 1 and at most the process age."},
	{"timeenc", timeenc_test, "Time encoding: SystemTime64/LocalTime64 against the OS clock, fixed-input conversions, RFC 3339 strings."},
	{"nullsafe", nullsafe_test, "NULL safety of the LOCK, LIST, COUNTER, REF and EVENT functions."},
	{"charset", charset_test, "Charset: UTF-8 and ANSI conversions against fixed vectors and the historic UTF-8 coding."},
	{"fileio", fileio_test, "FileIO: @, $ and | prefixes, path separator, sharing modes, reads past the end."},
	{"resources", resources_test, "Resources: every hamcore file through ReadHamcore and |, the loose hamcore folder, no hamcore.se2, the same resources in vpnserver and vpncmd."},
	{"threadpool", threadpool_test, "Thread pool: job pickup, host thread id and COM, idle reuse, many waiters, host handles."},
	{"dns", dns_test, "DNS: localhost and IP literals answered at once, the computer name through the resolver thread."},
	{"trace", trace_test, "ETW trace: Debug() output unchanged, messages to the TraceLogging provider: trace [listening]."},
	{"eventlog", eventlog_test, "Event Log: MsWriteEventLog entries read back from the Application log."},
	{"certdl", certdl_test, "SetServerCert downloads the issuer certificate from a loopback listener (DownloadCert)."},
	{"str", str_test, "String functions: truncation and return values of copy, concatenate, format, search, tokens, compare."},
	{"udpaccel", udpaccel_test, "UDP Acceleration: receive budget per poll and per tick, header check before decryption, drop counters and their log."},
	{"selow", selow_test, "SeLow: the capability query installs nothing, a Local Bridge reaches the driver install, one adapter-list read."},
	{"listenerbind", listenerbind_test, "ListenerCreate and ListenerEnable wait for the bind and report a port that cannot be bound."},
	{"dllsearch", dllsearch_test, "DLL search order: next to the executable, System32 and AddDllDirectory, never the current directory or PATH."},
	{"machineid", machineid_test, "Machine identity: MachineGuid and the configuration salt, known answers, separate salts, the salt in the config."},
	{"vmdetect", vmdetect_test, "VM detection: MsIsInVm writes no script, starts no process, answers at once, reports a VM on a GitHub-hosted runner."},
	{"tcpip", tcpip_test, "TCP/IP packets: DhcpModify reads the cookie at offset 236 and nothing past the payload, the MSS clamp walks the TCP options."},
	{"x509", x509_test, "X.509: long name fields, certificate times in UTC, PKCS#1 v1.5 signature length, PEM bundle with an unknown key."},
	{"bufbounds", bufbounds_test, "BUF bounds: ReadBuf, ReadBufStr and WriteBuf near 2^32, the binary configuration reader against counts and sizes past the end."},
	{"keepalive", keepalive_test, "Keepalive span: a session timeout out of bounds, also 0 or 1 from a server, gives the span of the clamped timeout."},
	{"packcap", packcap_test, "Client Pack size cap: a 1 MiB hello or welcome Pack from a loopback peer is refused, the longest real welcome Pack is read."},
	{"storepacket", storepacket_test, "StorePacket: the broadcast storm list of a session stays at its cap, access list delay and jitter never divide by zero."},
	{"consoleline", consoleline_test, "Console input: a prompt line longer than its buffer, Ctrl+D and Ctrl+Z, the /IN file reader, UniToInt on a long string."},
	{"tempdir", tempdir_test, "Temp directory: 64-bit random name, protected DACL; loading a string table writes no cache file."},
	{"adminaudit", adminaudit_test, "Admin audit: audit lines only after a successful call and with the right key, the configuration revision only after a change."},
	{"logwriter", logwriter_test, "Log writer: one file open per LOG for 1000 records, every record in order, one size switch named as before."},
	{"logbound", logbound_test, "Log writer without a file: bounded record queue and buffer, dropped records released and counted in one line."},
	{"slog", slog_test, "Syslog: the next resolve is a tick deadline, a second sender does not wait for a slow resolve, datagram content."},
	{"eraser", eraser_test, "Eraser: a check interval of 1 s gives at most 4 free space checks in 3 s; the configuration keeps seconds."},
	{"authtype", authtype_test, "Login authtype: 96 (the former external authentication) and unknown types are refused without a session, 0 to 2 keep their results."},
	{"acpassword", acpassword_test, "Access list on the 'password' method: a denied address gets ERR_IP_ADDRESS_DENIED before the old password is checked."},
	{"sigleak", sigleak_test, "Signature POST: a body that is not the watermark gets 403 and is freed; the request after the last one gets no answer."},
	{"listeners", listeners_test, "Listeners and admin access: TCP 443 on a fresh configuration, 5555 when 443 cannot be bound at that first start, kept on later starts; ListenerCreate on any port; an admin login with the empty password gets error 51 from a non-loopback address and passes over loopback."},
	{"pktparse", pktparse_test, "Packet parsers: DNS opcode mask and label limits, DHCP Pad and whole option bodies, the DHCP cookie at offset 236."},
	{"vlantpid", vlantpid_test, "VLAN TPID: frames tagged with the hub's VlanTypeId reach layer 3 and 4, the access list of such a hub sees their IPv4."},
	{"icmpv6ns", icmpv6ns_test, "Neighbor Solicitation: BuildNeighborSolicitation gives the bytes of the former builder chain, nothing for a NULL argument."},
	{"pack_decode_bounds", pack_decode_bounds_test, "PACK decoder: value counts and sizes past the bytes present, unknown types and values cut short are rejected before they allocate."},
	{"tablecache", tablecache_test, "String table: loaded from the resource only, a planted table_name.txt beside the exe is ignored, no cache file is written."},
	{"registry", registry_test, "Registry: empty and 1-byte REG_SZ read as empty strings, a REG_MULTI_SZ as its first string, writes and deletes need no KEY_ALL_ACCESS."},
	{"certsig", certsig_test, "Certificate signatures: only X509_verify() == 1 is valid; an unknown signature algorithm fails CheckXEx and GetIssuerFromList."},
	{"x509root", x509root_test, "Root certificates: root_cert only for a verified self-signature; X509ToX leaves a certificate it refuses to its caller."},
	{"rsasig", rsasig_test, "RSA client certificate signatures: PKCS#1 v1.5 SHA-1, a destination smaller than the key refused, a signature of another length rejected."},
	{"chaincerts", chaincerts_test, "chain_certs: the folder is scanned once for many connections, again after a certificate is added, removed or saved."},
	{"tlsctx", tlsctx_test, "Shared server SSL_CTX: a new certificate, cipher list or SslAcceptSettings reaches the next connection; accept rate (informational)."},
	{"ptrkey", ptrkey_test, "Pointer keys: POINTER_TO_KEY keys a block by its address; AccessDelete by UniqueId removes that entry after the Ids are renumbered."},
	{"osinfo", osinfo_test, "OS information: Windows 10 and 11, Server 2016, 2019, 2022 and 2025 by build number; a GitHub-hosted runner is Server 2022 or later or Windows 11."},
	{"endian", endian_test, "Byte order: Endian16/32/64 reverse the bytes as htons and htonl do, READ_* and WRITE_* are big-endian at unaligned addresses."},
	{"svcargs", svcargs_test, "Service arguments: each argument of SVC_HELP selects its mode, /usermode_showtray and /usermode_hidetray select none."},
	{"fifo", fifo_test, "FIFO and queue: a FIFO that never fully drains stays small and keeps the byte order; the queue ring keeps the item order."},
	{"node", node_test, "Node: each role from the configuration starts and stops with every thread joined; per-core workers, adapter queues, atomic table swaps; fork Hub and Sam."},
	{"nodesvc", nodesvc_test, "Node service: ranz-node installs as ranzvpnserver, runs each role of its configuration and stops cleanly (administrator rights)."},
	{"nodelogin", nodelogin_test, "Node Login: password, certificate and domain credentials through a Noise session and NodeLogin give the SE-VPN login's result (administrator rights)."},
	{"store", store_test, "Configuration store: SQLite through the winsqlite3.dll of System32, a fork configuration import matching its golden dump, named admin roles, PBKDF2 passwords."},
	{"bgp", bgp_test, "BGP sidecar: ranz bgp peers with a router (gobgpd, RANZ_GOBGP) on TCP 179, a prefix announced and withdrawn, a learned route installed through IP Helper (administrator rights)."},
	{"selfintegrity", selfint_test, "Self-integrity: WinVerifyTrust and the .text hash of the running binary; OK when signed and intact, the degrade-or-deceive response when changed (SEC-3; run on a signed binary by self-integrity.ps1)."},
	{"transport", transport_test, "Transport: a Noise session end to end over the loopback transport, the race of a configured fallback list (the first to connect wins), the same session over a second transport."},
	{"quic", quic_test, "QUIC: a client completes the QUIC handshake against the HTTP/3 listener on msquic, the Noise session comes up, Sam checks the Login, and the client's static key is pinned on first login (trust on first use)."},
	{"noisehub", noisehub_test, "Noise to Hub: the L2 frames of a Noise session enter a Hub as a Session of type CONNECTION_NOISE and come out as the oracle's (golden family noisehub); a Tunnel of four connections keeps each flow in order and spreads the flows over all four."},
	{"tls", tls_test, "TLS-443: a client completes a Schannel TLS 1.3 handshake on a test port, the Noise session comes up bound to the TLS exporter; X25519MLKEM768 first where the OS has ML-KEM, AES-GCM only, the server key in the KSP, the pin, the fallback when UDP is blocked (administrator rights)."},
	{"lossylink", lossylink_test, "Lossy link: the ingress queue of the session layer (FIFO, CoDel's drops), and an inner TCP over the TLS-443 path on a simulated link of 1% and 2% loss and 50 ms round trip, over CoDel and over FIFO: no collapse with CoDel."},
	{"harden", harden_test, "Hardened licence gate: ranzguard reports unlocked unwatched and degrades to locked under a debugger, never crashing (skips when ranzguard.exe is absent)."},
	{"httplistener", httplistener_test, "HTTP listener on a test port: the redirect to HTTPS, ACME HTTP-01 challenges, the errors, port conflicts, the configuration round trip, a held port."},
	{"sdntrace", sdntrace_test, "Default VRF tracer: sdntrace <host:port> <key> [<file>]: two nodes join VRF default of a running ranz controller, get addresses from its pool and ping each other over the loopback transport, also once the controller stopped (.github/scripts/sdn-tracer.ps1)."},
	{"vrf", vrf_test, "VRF forwarding tables: DIR-24-8 and trie lookups against a reference on random routes, swaps under readers, two VRFs on 10.0.0.0/24 kept apart over the overlay (golden family vrf), a stream that loses no packet while the tables swap."},
	{"vxlan", vxlan_test, "VXLAN: a frame, VLAN-tagged or not, goes out with its VNI and reaches a harness VTEP identical, and back to the module; a flood list of three VTEPs gets every frame and changes while the module runs; a datagram on an unknown VNI is dropped and counted."},
	{"shape", shape_test, "Shaping of the overlay: the MTU of each VRF on its adapter and an override that raises it, TCP SYNs that leave with the MSS clamped to it, DSCP and ECN through the tunnel unchanged, traffic above the rate limit of a VRF and of the node shaped to that rate."},
	{"switch", switch_test, "Switch: frames between members of different VLANs across access, trunk and native ports, VLAN-aware learning, broadcast and multicast by group subscription, non-IP EtherTypes, per-VLAN limits and counters and the TPID of a Network against golden files (golden family switch); ports that change while threads forward."},
	{"switchbench", switchbench_test, "Switch benchmark: the forwarding of the L2 switch on one thread, on one thread per core and behind one lock as the Hub; it fails when the threads do not scale (BENCH lines)."},
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
				num = sizeof(test_list) / sizeof(TEST_LIST);
				for (UINT i = 0;i < num;i++)
				{
					TEST_LIST *t = &test_list[i];
					max_len = MAX(max_len, StrLen(t->command_str));
				}
				for (UINT i = 0;i < num;i++)
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
				for (UINT i = 0;i < num;i++)
				{
					if (!StrCmpi(test_list[i].command_str, cmd))
					{
						char **arg = Malloc(sizeof(char *) * (token->NumTokens - 1));
						for (UINT j = 0;j < token->NumTokens - 1;j++)
						{
							arg[j] = CopyStr(token->Token[j + 1]);
						}
						test_list[i].proc(token->NumTokens - 1, arg);
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

