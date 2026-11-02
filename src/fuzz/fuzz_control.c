// fuzz_control.c
// libFuzzer target: the control stream of a node (Core/Control.c, SDN-3 #179; AUD1-DT-12 #460), which reads the messages
// that the Controller sends. The node decodes each one with the code that nanopb generates from
// proto/ranz/control/v1/control.proto and control.options (ControlDecode), applies an Update to the desired state that it
// holds, a full state or a delta from the Generation that it applied last (ControlApply), and hands that state to its
// owner, which builds the tables of the node from it (ControlInput). Every input runs on two clients without a thread
// (ControlNew), a new one each time:
// - the whole input as one message, as tests/control/nanopb_roundtrip.c decodes a file that the controller tests wrote;
// - the input as the frames of a stream, each the size of its message in 4 bytes (big-endian) and the message, as the
//   controller sends them after the Hello: the client takes them in turn until one ends the stream, as the stream of a
//   client ends then, or the next frame is empty or longer than the input left.
// The owner checks each state that it is handed: its Generation is not 0, every count is within its array, every address
// and prefix within its bytes, every string ends in its buffer, a TLS fingerprint is 64 hex digits in lower case, a
// session profile of the node or of a peer that is not set holds nothing (ControlCopyProfiles; SDN-40 #233), the BGP
// peering of the node and of each peer has the address of a sidecar that is IPv4 or IPv6, and that of a peer a VRF
// (ControlCopyPeerings; SDN-77 #357), and a source group has a group ID of 16 bits and a VRF a tag mode that the node
// knows (SDN-87 #386). After
// a message whose Update was handed to the owner, the client must have taken it and stand at its Generation. Each message
// is copied into a buffer of its size exactly, so that AddressSanitizer reports a read past it. The client allocates from
// the process heap, which Mayaqua does not count: AddressSanitizer checks those blocks, and -rss_limit_mb bounds a leak.
//
// An Operation of the Controller (SDN-50-N, #492) the client decodes and checks (ControlTakeOperation), and hands one for an
// L2 Network of its state to the owner, which checks it in turn: a kind that the node knows, a Network that ends in its
// buffer, and a MAC address or an address of the size of one, for a clear of its table alone. The owner answers with every
// entry that an answer holds and one more, of every size of address, with a status of every value and strings of bytes that
// are no ASCII and do not end, which the client must make an answer of.
//
// The seeds (src/fuzz/seeds/fuzz_control.py) are the control messages that the controller conformance tests and the
// cluster tests sent and received, each a seed of its own (wire-*.bin), and the messages that each simulated node
// received, in their order, as one stream (stream-*.bin); a state with L2 and L3 Networks followed by Operations of
// every kind (operation-*.bin); and a state whose VRFs peer by BGP followed by deltas with a peering that the node cannot
// read, without it and with it again (peering-*.bin).
//
// fuzz-max-len: 8192
// fuzz-libs: corecontrol

#include "fuzz_common.h"

#include "Core/Control.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Largest input accepted (fuzz-max-len above, for run_fuzzers.ps1): longer inputs are skipped
#define	FUZZ_MAX_INPUT_SIZE		8192

// The size of a frame before its message, big-endian, as the client reads it (CONTROL_FRAME_HEADER of Core/Control.c)
#define	FUZZ_CONTROL_HEADER		4

// What the owner of a client saw
typedef struct FUZZ_CONTROL
{
	UINT NumStates;					// The states handed to it
	UINT64 Generation;				// ... and the Generation of the last one
	UINT NumOperations;				// The Operations handed to it (SDN-50-N, #492)
} FUZZ_CONTROL;

// The static key of the node of the clients: the client keeps it and never runs a handshake with it
static const UCHAR fuzz_control_key[NOISE_KEY_SIZE] = {0x01};

// The transport of the clients, which no thread dials
static TRANSPORT fuzz_control_transport = {"fuzz"};

// A property of the control module that does not hold: libFuzzer saves the input, with no abort message box and no
// Windows Error Reporting (as FuzzRun in fuzz_common.c)
static void FuzzFail(const char *what)
{
	fprintf(stderr, "==RANZ FUZZ== %s\n", what);
	fflush(stderr);
	_set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
	abort();
}

// Whether the string of a buffer of size bytes ends in it
static bool FuzzEnds(const char *s, UINT size)
{
	return (memchr(s, 0, size) != NULL);
}

// A prefix of a NAT rule, a route or a rule: IPv4 or IPv6, no longer than its address
static void FuzzPrefix(UINT size, UINT length, const char *what)
{
	if ((size != 4 && size != 16) || length > size * 8)
	{
		FuzzFail(what);
	}
}

// The addresses of a node, a peer or a Device: num of them at most max, each within the bytes of an address
static void FuzzAddresses(const CONTROL_ADDRESS *a, UINT num, UINT max, const char *what)
{
	if (num > max)
	{
		FuzzFail(what);
	}

	for (UINT i = 0;i < num;i++)
	{
		if (a[i].AddressSize > sizeof(a[i].Address) || FuzzEnds(a[i].Network, sizeof(a[i].Network)) == false)
		{
			FuzzFail(what);
		}
	}
}

// The tags of a node, a peer, a Device or an end of a rule: num of them at most max, each name ending in its buffer
static void FuzzTags(const char (*tags)[CONTROL_NAME_SIZE], UINT num, UINT max, const char *what)
{
	if (num > max)
	{
		FuzzFail(what);
	}

	for (UINT i = 0;i < num;i++)
	{
		if (FuzzEnds(tags[i], CONTROL_NAME_SIZE) == false)
		{
			FuzzFail(what);
		}
	}
}

// A tunnel endpoint of the links of kind vxlan and geneve
static void FuzzVtep(const CONTROL_VTEP *v, const char *what)
{
	if ((v->AddressSize != 0 && v->AddressSize != 4 && v->AddressSize != 16) || v->VxlanPort > 0xFFFF || v->GenevePort > 0xFFFF)
	{
		FuzzFail(what);
	}
}

// The session profile of the node or of a peer (ControlCopyProfiles; SDN-40 #233): its names end in their buffers, and one
// that is not set holds no name, no limit and no flag
static void FuzzProfile(const CONTROL_PROFILE *p, const char *what)
{
	bool held = (p->Name[0] != 0 || p->User[0] != 0 || p->UploadLimit != 0 || p->DownloadLimit != 0 || p->MaxSessions != 0 || p->MaxMacs != 0 ||
		p->MaxIpv4 != 0 || p->MaxIpv6 != 0 || p->IdleTimeout != 0 || p->AutoDisconnect != 0 || p->NoBridge || p->NoRouting || p->NoServer || p->PrivacyFilter);

	if (FuzzEnds(p->Name, sizeof(p->Name)) == false || FuzzEnds(p->User, sizeof(p->User)) == false || (p->Set == false && held))
	{
		FuzzFail(what);
	}
}

// The source groups of a node or of a peer (SDN-87 #386): num of them at most CONTROL_MAX_VRFS, each with a group ID from 1
// to 65535
static void FuzzGroups(const CONTROL_SOURCE_GROUP *g, UINT num, const char *what)
{
	if (num > CONTROL_MAX_VRFS)
	{
		FuzzFail(what);
	}

	for (UINT i = 0;i < num;i++)
	{
		if (g[i].Group == 0 || g[i].Group > 0xFFFF)
		{
			FuzzFail(what);
		}
	}
}

// The endpoints of a node or of a peer
static void FuzzEndpoints(const CONTROL_ENDPOINT *e, UINT num, const char *what)
{
	if (num > CONTROL_MAX_ENDPOINTS)
	{
		FuzzFail(what);
	}

	for (UINT i = 0;i < num;i++)
	{
		if (FuzzEnds(e[i].Transport, sizeof(e[i].Transport)) == false || FuzzEnds(e[i].Address, sizeof(e[i].Address)) == false)
		{
			FuzzFail(what);
		}
	}
}

// The rules of the policy of the VRFs
static void FuzzRules(const CONTROL_STATE *st)
{
	if (st->NumRules != 0 && st->Rules == NULL)
	{
		FuzzFail("a state has rules and no array of them");
	}

	for (UINT i = 0;i < st->NumRules;i++)
	{
		const CONTROL_RULE *r = &st->Rules[i];
		const CONTROL_RULE_END *ends[2] = {&r->From, &r->To};

		if (FuzzEnds(r->Name, sizeof(r->Name)) == false || r->NumPorts > CONTROL_RULE_VALUES)
		{
			FuzzFail("a rule has a name that does not end or too many ports");
		}

		for (UINT j = 0;j < 2;j++)
		{
			FuzzTags(ends[j]->Tags, ends[j]->NumTags, CONTROL_RULE_VALUES, "an end of a rule has a tag that does not end or too many tags");
			if (ends[j]->NumPrefixes > CONTROL_RULE_VALUES)
			{
				FuzzFail("an end of a rule has too many prefixes");
			}
			for (UINT k = 0;k < ends[j]->NumPrefixes;k++)
			{
				FuzzPrefix(ends[j]->Prefixes[k].AddressSize, ends[j]->Prefixes[k].Length, "a prefix of a rule is neither IPv4 nor IPv6, or longer than its address");
			}
		}
	}
}

// The VRFs, with their zones of overlay DNS
static void FuzzVrfs(const CONTROL_STATE *st)
{
	if (st->NumVrfs > CONTROL_MAX_VRFS)
	{
		FuzzFail("a state has too many VRFs");
	}

	for (UINT i = 0;i < st->NumVrfs;i++)
	{
		const CONTROL_VRF *v = &st->Vrfs[i];
		const CONTROL_DNS_ZONE *z = v->Dns;

		if (FuzzEnds(v->Name, sizeof(v->Name)) == false || v->Link > CONTROL_LINK_GENEVE || v->Vni > 0xFFFFFF)
		{
			FuzzFail("a VRF has a name that does not end, a link of no kind, or a VNI of more than 24 bits");
		}
		if (v->TagMode != CONTROL_TAG_MODE_OFF && v->TagMode != CONTROL_TAG_MODE_TRUSTED)
		{
			FuzzFail("a VRF has a tag mode that is neither off nor trusted-underlay");
		}
		if (z == NULL)
		{
			continue;
		}
		if (FuzzEnds(z->Suffix, sizeof(z->Suffix)) == false || z->NumRecords > CONTROL_MAX_DNS_RECORDS)
		{
			FuzzFail("a zone has a suffix that does not end or too many records");
		}
		for (UINT j = 0;j < z->NumRecords;j++)
		{
			const CONTROL_DNS_RECORD *d = &z->Records[j];

			if (FuzzEnds(d->Name, sizeof(d->Name)) == false || d->NumAddresses > CONTROL_MAX_DNS_ADDRESSES)
			{
				FuzzFail("a record of a zone has a name that does not end or too many addresses");
			}
			for (UINT k = 0;k < d->NumAddresses;k++)
			{
				if (d->AddressSizes[k] != 4 && d->AddressSizes[k] != 16)
				{
					FuzzFail("an address of a record of a zone is neither IPv4 nor IPv6");
				}
			}
		}
	}
}

// The peers
static void FuzzPeers(const CONTROL_STATE *st)
{
	if (st->NumPeers != 0 && st->Peers == NULL)
	{
		FuzzFail("a state has peers and no array of them");
	}

	for (UINT i = 0;i < st->NumPeers;i++)
	{
		const CONTROL_PEER *p = &st->Peers[i];

		if (FuzzEnds(p->Name, sizeof(p->Name)) == false || p->NumVrfs > CONTROL_MAX_VRFS || p->NumRoutes > CONTROL_MAX_ROUTES)
		{
			FuzzFail("a peer has a name that does not end, too many VRFs or too many routes");
		}
		FuzzAddresses(p->Addresses, p->NumAddresses, CONTROL_MAX_ADDRESSES, "a peer has too many addresses, or one that does not fit");
		for (UINT j = 0;j < p->NumRoutes;j++)
		{
			FuzzPrefix(p->Routes[j].AddressSize, p->Routes[j].Length, "a route of a peer is neither IPv4 nor IPv6, or longer than its address");
		}
		FuzzTags(p->Tags, p->NumTags, CONTROL_MAX_TAGS, "a peer has a tag that does not end or too many tags");
		FuzzEndpoints(p->Endpoints, p->NumEndpoints, "a peer has too many endpoints, or one that does not end");
		FuzzVtep(&p->Vtep, "a peer has a tunnel endpoint that is neither IPv4 nor IPv6, or a port above 65535");
		FuzzProfile(&p->Profile, "a peer has a session profile whose names do not end, or one that is not set and holds something");
		FuzzGroups(p->Groups, p->NumGroups, "a peer has too many source groups, or one whose group ID is 0 or above 65535");
	}
}

// The Mirrors and the DHCP responders
static void FuzzMirrorsDhcps(const CONTROL_STATE *st)
{
	if (st->NumMirrors > CONTROL_MAX_MIRRORS || st->NumDhcps > CONTROL_MAX_DHCPS)
	{
		FuzzFail("a state has too many Mirrors or DHCP responders");
	}

	for (UINT i = 0;i < st->NumMirrors;i++)
	{
		const CONTROL_MIRROR *m = &st->Mirrors[i];

		if (FuzzEnds(m->Name, sizeof(m->Name)) == false || (m->SensorSize != 4 && m->SensorSize != 16))
		{
			FuzzFail("a Mirror has a name that does not end, or a sensor that is neither IPv4 nor IPv6");
		}
	}

	for (UINT i = 0;i < st->NumDhcps;i++)
	{
		const CONTROL_DHCP *d = &st->Dhcps[i];

		if (FuzzEnds(d->Network, sizeof(d->Network)) == false || d->PoolLength > 32 || d->NumDns > CONTROL_MAX_DNS || d->NumReserved > CONTROL_MAX_RESERVED)
		{
			FuzzFail("a DHCP responder has a Network that does not end, a pool longer than 32 bits, or too many DNS servers or reservations");
		}
		for (UINT j = 0;j < d->NumReserved;j++)
		{
			if (d->Reserved[j].Length > 32)
			{
				FuzzFail("a reservation of a DHCP responder is longer than 32 bits");
			}
		}
	}
}

// The Listener and the WireGuard Devices
static void FuzzListenerDevices(const CONTROL_STATE *st)
{
	const CONTROL_LISTENER *l = st->Listener;

	if (l != NULL)
	{
		if (l->Source < CONTROL_CERT_FILE || l->Source > CONTROL_CERT_ACME || l->Port > 65535 || l->QuicPort > 65535 || l->NumNames > CONTROL_ACME_NAMES ||
			FuzzEnds(l->Name, sizeof(l->Name)) == false || FuzzEnds(l->Path, sizeof(l->Path)) == false || FuzzEnds(l->PasswordFile, sizeof(l->PasswordFile)) == false ||
			FuzzEnds(l->Thumbprint, sizeof(l->Thumbprint)) == false || FuzzEnds(l->Directory, sizeof(l->Directory)) == false ||
			FuzzEnds(l->Email, sizeof(l->Email)) == false || FuzzEnds(l->CaFile, sizeof(l->CaFile)) == false)
		{
			FuzzFail("a Listener has no source of a certificate, a port above 65535, too many names, or a string that does not end");
		}
		for (UINT i = 0;i < l->NumNames;i++)
		{
			if (FuzzEnds(l->Names[i], sizeof(l->Names[i])) == false)
			{
				FuzzFail("a name of the ACME source of a Listener does not end");
			}
		}
	}

	if (st->NumDevices != 0 && st->Devices == NULL)
	{
		FuzzFail("a state has Devices and no array of them");
	}

	for (UINT i = 0;i < st->NumDevices;i++)
	{
		const CONTROL_DEVICE *d = &st->Devices[i];

		if (FuzzEnds(d->Name, sizeof(d->Name)) == false || FuzzEnds(d->Gateway, sizeof(d->Gateway)) == false)
		{
			FuzzFail("a Device has a name or a gateway that does not end");
		}
		FuzzAddresses(d->Addresses, d->NumAddresses, CONTROL_DEVICE_ADDRESSES, "a Device has too many addresses, or one that does not fit");
		FuzzTags(d->Tags, d->NumTags, CONTROL_MAX_TAGS, "a Device has a tag that does not end or too many tags");
		if (d->Group > 0xFFFF)
		{
			FuzzFail("a Device has a source group whose group ID is above 65535");
		}
	}
}

// The TLS fingerprints of the certificate of the Controller: 64 hex digits in lower case each
static void FuzzTlsPins(const CONTROL_STATE *st)
{
	if (st->NumTlsPins > CONTROL_TLS_PINS)
	{
		FuzzFail("a state has too many TLS fingerprints");
	}

	for (UINT i = 0;i < st->NumTlsPins;i++)
	{
		const char *pin = st->TlsPins[i];

		if (FuzzEnds(pin, CONTROL_TLS_PIN_SIZE) == false || strlen(pin) != CONTROL_TLS_PIN_SIZE - 1)
		{
			FuzzFail("a TLS fingerprint is not 64 characters");
		}
		for (UINT j = 0;j < CONTROL_TLS_PIN_SIZE - 1;j++)
		{
			if ((pin[j] >= '0' && pin[j] <= '9') == false && (pin[j] >= 'a' && pin[j] <= 'f') == false)
			{
				FuzzFail("a TLS fingerprint is not hex digits in lower case");
			}
		}
	}
}

// The securities of the L2 Networks (SDN-41 #234): each of a Network whose name ends, with its gateways
static void FuzzSecurities(const CONTROL_STATE *st)
{
	if (st->NumSecurities > CONTROL_MAX_SECURITIES || (st->NumSecurities != 0 && st->Securities == NULL))
	{
		FuzzFail("a state has too many securities, or securities and no array of them");
	}

	for (UINT i = 0;i < st->NumSecurities;i++)
	{
		const CONTROL_SECURITY *s = &st->Securities[i];

		if (FuzzEnds(s->Network, sizeof(s->Network)) == false)
		{
			FuzzFail("the Network of a security does not end");
		}
		FuzzTags(s->Gateways, s->NumGateways, CONTROL_MAX_GATEWAYS, "a security has a gateway that does not end, or too many gateways");
	}
}

// The BGP peering of the node and of the peers (SDN-77 #357): the address of each sidecar is IPv4 or IPv6, the peering of a
// peer has a VRF, every count is within its array and every prefix within its bytes
static void FuzzPeerings(const CONTROL_STATE *st)
{
	const CONTROL_PEERING *own = st->Peering;

	if (own != NULL)
	{
		if ((own->AddressSize != 4 && own->AddressSize != 16) || own->NumAnnounce > CONTROL_MAX_ANNOUNCE)
		{
			FuzzFail("the peering of the node has an address that is neither IPv4 nor IPv6, or too many LAN subnets");
		}
		for (UINT i = 0;i < own->NumAnnounce;i++)
		{
			FuzzPrefix(own->Announce[i].AddressSize, own->Announce[i].Length, "a LAN subnet that the node announces is neither IPv4 nor IPv6, or longer than its address");
		}
	}

	for (UINT i = 0;i < st->NumPeers;i++)
	{
		const CONTROL_PEER_PEERING *p = st->Peers[i].Peering;

		if (p == NULL)
		{
			continue;
		}
		if ((p->AddressSize != 4 && p->AddressSize != 16) || p->NumVrfs == 0 || p->NumVrfs > CONTROL_MAX_VRFS || p->NumAccept > CONTROL_MAX_ACCEPT)
		{
			FuzzFail("the peering of a peer has an address that is neither IPv4 nor IPv6, no VRF, too many VRFs or too many prefixes");
		}
		for (UINT j = 0;j < p->NumAccept;j++)
		{
			FuzzPrefix(p->Accept[j].AddressSize, p->Accept[j].Length, "a prefix that a peer may announce is neither IPv4 nor IPv6, or longer than its address");
		}
	}
}

// The owner of the clients: it checks each state that it is handed
static void FuzzControlState(void *param, const CONTROL_STATE *st)
{
	FUZZ_CONTROL *f = (FUZZ_CONTROL *)param;

	f->NumStates++;
	f->Generation = st->Generation;

	if (st->Generation == 0)
	{
		FuzzFail("the state of Generation 0 was handed to the owner");
	}
	if (FuzzEnds(st->Name, sizeof(st->Name)) == false)
	{
		FuzzFail("the name of the node does not end");
	}

	FuzzAddresses(st->Addresses, st->NumAddresses, CONTROL_MAX_ADDRESSES, "the node has too many addresses, or one that does not fit");
	FuzzTags(st->Tags, st->NumTags, CONTROL_MAX_TAGS, "the node has a tag that does not end or too many tags");
	FuzzEndpoints(st->Endpoints, st->NumEndpoints, "the node has too many endpoints, or one that does not end");
	FuzzVtep(&st->Vtep, "the node has a tunnel endpoint that is neither IPv4 nor IPv6, or a port above 65535");
	FuzzProfile(&st->Profile, "the node has a session profile whose names do not end, or one that is not set and holds something");
	FuzzGroups(st->Groups, st->NumGroups, "the node has too many source groups, or one whose group ID is 0 or above 65535");

	if (st->NumNats > CONTROL_MAX_NATS)
	{
		FuzzFail("the node has too many 1:1 NAT rules");
	}
	for (UINT i = 0;i < st->NumNats;i++)
	{
		FuzzPrefix(st->Nats[i].InsideSize, st->Nats[i].InsideLength, "the inside prefix of a 1:1 NAT rule is neither IPv4 nor IPv6, or longer than its address");
		FuzzPrefix(st->Nats[i].OutsideSize, st->Nats[i].OutsideLength, "the outside prefix of a 1:1 NAT rule is neither IPv4 nor IPv6, or longer than its address");
	}

	FuzzRules(st);
	FuzzVrfs(st);
	FuzzPeers(st);
	FuzzMirrorsDhcps(st);
	FuzzListenerDevices(st);
	FuzzTlsPins(st);
	FuzzSecurities(st);
	FuzzPeerings(st);
}

// The owner of the live operations (SDN-50-N, #492): it checks the Operation that it is handed, and answers it with every entry
// that an answer holds and one more, each of another size of address, a status of any value by the id of the Operation, and a
// message and members of bytes that are no ASCII and do not end
static void FuzzControlOperation(void *param, const CONTROL_OPERATION *op, CONTROL_OPERATION_RESULT *res)
{
	static const UINT sizes[] = {4, 16, 0, 5};
	FUZZ_CONTROL *f = (FUZZ_CONTROL *)param;

	f->NumOperations++;

	if (op->Kind < CONTROL_OPERATION_MAC_TABLE || op->Kind > CONTROL_OPERATION_CLEAR_IP_TABLE)
	{
		FuzzFail("an Operation of a kind that the node does not know was handed to the owner");
	}
	if (FuzzEnds(op->Network, sizeof(op->Network)) == false)
	{
		FuzzFail("the Network of an Operation does not end");
	}
	if (op->HasMac && op->Kind != CONTROL_OPERATION_CLEAR_MAC_TABLE)
	{
		FuzzFail("an Operation that is no clear of the MAC table names a MAC address");
	}
	if (op->AddressSize != 0 && (op->Kind != CONTROL_OPERATION_CLEAR_IP_TABLE || (op->AddressSize != 4 && op->AddressSize != 16)))
	{
		FuzzFail("an Operation that is no clear of the IP table names an address, or one that is neither IPv4 nor IPv6");
	}

	res->Status = (UINT)(op->Id % 5);
	memset(res->Message, 0xC3, sizeof(res->Message));
	res->Total = (UINT)op->Id;
	res->NumEntries = CONTROL_MAX_ENTRIES + 1;
	for (UINT i = 0;i < CONTROL_MAX_ENTRIES;i++)
	{
		CONTROL_TABLE_ENTRY *e = &res->Entries[i];

		e->Vlan = i;
		memset(e->Mac, (int)i, sizeof(e->Mac));
		e->AddressSize = sizes[i % (sizeof(sizes) / sizeof(sizes[0]))];
		memset(e->Address, (int)(i + 1), sizeof(e->Address));
		memset(e->Member, 'a' + (int)(i % 26), sizeof(e->Member));
		e->Member[0] = (char)0xFF;
		e->LastSeen = op->Id + i;
	}
}

// A client without its thread, whose owner is f
static CONTROL_CLIENT *FuzzControlNew(FUZZ_CONTROL *f)
{
	CONTROL_CONFIG cfg;

	memset(f, 0, sizeof(FUZZ_CONTROL));
	memset(&cfg, 0, sizeof(cfg));
	cfg.Transport = &fuzz_control_transport;
	strcpy_s(cfg.Address, sizeof(cfg.Address), "controller");
	cfg.StaticKey = fuzz_control_key;
	cfg.Proc = FuzzControlState;
	cfg.Param = f;
	cfg.OperationProc = FuzzControlOperation;
	cfg.OperationParam = f;

	CONTROL_CLIENT *c = ControlNew(&cfg);
	if (c == NULL)
	{
		FuzzFail("ControlNew refused a complete configuration");
	}

	return c;
}

// The client c takes one message of size bytes: true when it went on, as ControlInput gives
static bool FuzzControlTake(CONTROL_CLIENT *c, FUZZ_CONTROL *f, const uint8_t *data, UINT size)
{
	CONTROL_STATUS before, after;
	UINT num_states = f->NumStates;

	// malloc() rather than Malloc(): the copy is exactly the message, so AddressSanitizer reports any read past it
	UCHAR *message = malloc(size != 0 ? size : 1);
	if (message == NULL)
	{
		return false;
	}
	memcpy(message, data, size);

	ControlGetStatus(c, &before);
	bool ret = ControlInput(c, message, size);
	ControlGetStatus(c, &after);

	free(message);

	// An Update that the owner took was applied: the client went on and stands at its Generation
	if (f->NumStates != num_states && (ret == false || after.Applied != f->Generation || after.NumUpdates != before.NumUpdates + 1))
	{
		FuzzFail("an Update that the owner took left the client off its Generation, or ended the stream");
	}

	return ret;
}

// The whole input as one message
static void FuzzControlMessage(const uint8_t *data, size_t size)
{
	FUZZ_CONTROL f;
	CONTROL_CLIENT *c = FuzzControlNew(&f);

	FuzzControlTake(c, &f, data, (UINT)size);

	ControlFree(c);
}

// The input as the frames of a stream
static void FuzzControlStream(const uint8_t *data, size_t size)
{
	FUZZ_CONTROL f;
	CONTROL_CLIENT *c = FuzzControlNew(&f);
	size_t pos = 0;

	while (size - pos >= FUZZ_CONTROL_HEADER)
	{
		UINT n = ((UINT)data[pos] << 24) | ((UINT)data[pos + 1] << 16) | ((UINT)data[pos + 2] << 8) | data[pos + 3];

		pos += FUZZ_CONTROL_HEADER;

		// The client ends the stream at an empty frame; a frame longer than the input left never comes whole
		if (n == 0 || n > size - pos)
		{
			break;
		}
		if (FuzzControlTake(c, &f, data + pos, n) == false)
		{
			break;
		}
		pos += n;
	}

	ControlFree(c);
}

// One input: as a message, then as a stream
static void FuzzControl(const uint8_t *data, size_t size)
{
	if (size > FUZZ_MAX_INPUT_SIZE)
	{
		return;
	}

	FuzzControlMessage(data, size);
	FuzzControlStream(data, size);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzControl, data, size);

	return 0;
}
