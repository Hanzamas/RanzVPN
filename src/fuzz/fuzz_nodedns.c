// fuzz_nodedns.c
// libFuzzer target: the stub resolver of overlay DNS (Cedar/NodeDns.c, SDN-11 #187), which answers the DNS queries that
// reach UDP port 53 of the node's addresses in a VRF from the zone of that VRF (NodeDnsAnswer). The first byte of an input
// picks the zone: bit 0 gives the VRF the 4via6 of the host, so an IPv4 address answers in an AAAA record; bit 1 takes the
// suffix corp in place of red.ranz.internal. The zone holds fileserver (an IPv4 and an IPv6 address), files.hq (under the
// empty non-terminal hq), node-s and many, which has as many addresses as a name holds. The rest of the input is the
// query, copied into a buffer of its size exactly, so that AddressSanitizer reports a read past it. Each answer must fit
// NODE_DNS_MAX_ANSWER, keep the id of the query and give an RCODE that the stub resolver answers with.
//
// fuzz-max-len: 1500

#include "fuzz_common.h"

#include "Cedar/CedarType.h"
#include "Cedar/Node.h"

#include <stdlib.h>
#include <string.h>

#define	FUZZ_DNS_NAMES	4	// The names of the zone

// One name of the zone with the num addresses of v4 (IPv4, 4 bytes each), then v6 (IPv6, 16 bytes) when it is not NULL
static void FuzzNodeDnsName(NODE_DNS_NAME *n, const char *name, const UCHAR *v4, UINT num, const UCHAR *v6)
{
	memset(n, 0, sizeof(NODE_DNS_NAME));
	strcpy_s(n->Name, sizeof(n->Name), name);
	for (UINT i = 0;i < num && n->NumAddresses < NODE_DNS_MAX_ADDRESSES;i++)
	{
		memcpy(n->Addresses[n->NumAddresses], v4 + i * 4, 4);
		n->AddressSizes[n->NumAddresses++] = 4;
	}
	if (v6 != NULL && n->NumAddresses < NODE_DNS_MAX_ADDRESSES)
	{
		memcpy(n->Addresses[n->NumAddresses], v6, 16);
		n->AddressSizes[n->NumAddresses++] = 16;
	}
}

// The zone of the input's first byte
static void FuzzNodeDnsZone(NODE_DNS_ZONE *z, NODE_DNS_NAME *names, UCHAR pick)
{
	static const UCHAR fileserver[4] = {10, 1, 0, 10};
	static const UCHAR files[4] = {10, 1, 0, 20};
	static const UCHAR node_s[4] = {10, 1, 0, 1};
	static const UCHAR v6[16] = {0xfd, 0x00, 0x01, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};
	static const UCHAR via6[12] = {0xfd, 0x00, 0x01, 0x01, 0, 0, 0xff, 0xff, 0, 0, 0, 0};
	UCHAR many[NODE_DNS_MAX_ADDRESSES * 4];

	for (UINT i = 0;i < NODE_DNS_MAX_ADDRESSES;i++)
	{
		many[i * 4] = 10;
		many[i * 4 + 1] = 1;
		many[i * 4 + 2] = 1;
		many[i * 4 + 3] = (UCHAR)(i + 1);
	}

	memset(z, 0, sizeof(NODE_DNS_ZONE));
	z->VrfId = 101;
	strcpy_s(z->Suffix, sizeof(z->Suffix), (pick & 0x02) != 0 ? "corp" : "red.ranz.internal");
	z->Serial = 7;
	z->Via6 = ((pick & 0x01) != 0);
	memcpy(z->Via6Prefix, via6, sizeof(via6));

	FuzzNodeDnsName(&names[0], "fileserver", fileserver, 1, v6);
	FuzzNodeDnsName(&names[1], "files.hq", files, 1, NULL);
	FuzzNodeDnsName(&names[2], "node-s", node_s, 1, NULL);
	FuzzNodeDnsName(&names[3], "many", many, NODE_DNS_MAX_ADDRESSES, NULL);
	z->Names = names;
	z->NumNames = FUZZ_DNS_NAMES;
}

// One input: the zone, then the query
static void FuzzNodeDns(const uint8_t *data, size_t size)
{
	NODE_DNS_ZONE z;
	NODE_DNS_NAME names[FUZZ_DNS_NAMES];
	UCHAR answer[NODE_DNS_MAX_ANSWER];
	char name[NODE_DNS_MAX_ANSWER];
	UINT rcode = 0;

	if (size == 0)
	{
		return;
	}

	FuzzNodeDnsZone(&z, names, data[0]);

	size_t query_size = size - 1;
	UCHAR *query = malloc(query_size != 0 ? query_size : 1);
	if (query == NULL)
	{
		return;
	}
	memcpy(query, data + 1, query_size);

	UINT n = NodeDnsAnswer(&z, query, (UINT)query_size, answer, sizeof(answer), &rcode, name, sizeof(name));
	if (n > sizeof(answer) || (n != 0 && (n < 12 || answer[0] != query[0] || answer[1] != query[1] || (answer[2] & 0x80) == 0)))
	{
		abort();
	}
	if (n != 0 && rcode != NODE_DNS_RCODE_NOERROR && rcode != NODE_DNS_RCODE_FORMERR && rcode != NODE_DNS_RCODE_NXDOMAIN && rcode != NODE_DNS_RCODE_NOTIMP &&
		rcode != NODE_DNS_RCODE_REFUSED)
	{
		abort();
	}

	free(query);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzNodeDns, data, size);

	return 0;
}
