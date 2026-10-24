// ControlDhcp.c
// The DHCP responders of the L2 Networks on the control stream (SDN-43, #236; Core/Control.h). The Network objects of
// a state that carry a Dhcp in the mode pool become the responders of the state (ControlCopyDhcps): the node that the
// controller names answers DHCP for those Networks, and for no other. The leases that its responders hold go to the
// controller as one Leases message per Network (ControlSetLeases): after each Hello, so a controller that the node
// reaches anew has them all, and whenever they change. The controller keeps the report of each Network in place of the
// one before and lists them with IPAM (GET /api/v1/ipam/leases).

#include "Core/ControlInternal.h"

#include <pb_encode.h>

#include <stdlib.h>
#include <string.h>

#define CONTROL_LEASES_HEADER 4 // The size of a frame, big-endian, before its message (as Control.c writes them)

// The report of the leases of one Network
typedef struct CONTROL_LEASE_REPORT {
	char Network[CONTROL_NAME_SIZE]; // The L2 Network
	UINT NumLeases;                  // Its leases
	CONTROL_LEASE *Leases;           // ... NumLeases of them, NULL for none
	bool Sent;                       // The stream that runs has them
} CONTROL_LEASE_REPORT;

// The leases that a client reports
struct CONTROL_LEASES {
	SRWLOCK Lock;                                    // The reports
	UINT NumReports;                                 // The reports, one per Network
	CONTROL_LEASE_REPORT Reports[CONTROL_MAX_DHCPS]; // ...
	ranz_control_v1_Leases *Message;                 // The message that the thread of the client writes
};

static void *ControlDhcpAlloc(SIZE_T size) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

static void ControlDhcpFree(void *p) {
	if (p != NULL)
		HeapFree(GetProcessHeap(), 0, p);
}

//
// The responders of a state
//

// Copy an IPv4 address of 4 bytes: false for any other size
static bool ControlDhcpAddress(UCHAR *dst, const pb_byte_t *src, pb_size_t size) {
	if (size != 4)
		return false;

	CopyMemory(dst, src, 4);
	return true;
}

static int ControlCompareDhcps(const void *a, const void *b) {
	return strcmp(((const CONTROL_DHCP *)a)->Network, ((const CONTROL_DHCP *)b)->Network);
}

// The DHCP responders of the Network objects among num objects into the state: a Network of the mode L2 whose Dhcp is
// in the mode pool, with an IPv4 pool and the responder's own address. A DNS server or a reservation that is not IPv4
// is left out. At most CONTROL_MAX_DHCPS, sorted by Network name.
void ControlCopyDhcps(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num) {
	st->NumDhcps = 0;

	for (UINT i = 0; i < num && st->NumDhcps < CONTROL_MAX_DHCPS; i++) {
		const ranz_control_v1_Object *o = &objects[i];

		if (o->which_kind != ranz_control_v1_Object_network_tag)
			continue;

		const ranz_control_v1_Network *nw = &o->kind.network;
		const ranz_control_v1_Dhcp *dhcp = &nw->dhcp;
		CONTROL_DHCP *d = &st->Dhcps[st->NumDhcps];

		if (nw->has_dhcp == false || dhcp->mode != ranz_control_v1_DhcpMode_DHCP_MODE_POOL || nw->mode != ranz_control_v1_NetworkMode_NETWORK_MODE_L2 || nw->has_ipv4_pool == false || nw->ipv4_pool.length > 32)
			continue;

		ZeroMemory(d, sizeof(CONTROL_DHCP));
		strncpy_s(d->Network, sizeof(d->Network), nw->name, _TRUNCATE);
		d->VrfId = nw->vrf_id;
		d->PoolLength = nw->ipv4_pool.length;
		d->LeaseTime = dhcp->lease_time;
		if (ControlDhcpAddress(d->Pool, nw->ipv4_pool.address.bytes, nw->ipv4_pool.address.size) == false || ControlDhcpAddress(d->Address, dhcp->address.bytes, dhcp->address.size) == false)
			continue;
		// No gateway, or one of 4 bytes
		if (dhcp->gateway.size != 0 && ControlDhcpAddress(d->Gateway, dhcp->gateway.bytes, dhcp->gateway.size) == false)
			continue;

		for (pb_size_t j = 0; j < dhcp->dns_count && d->NumDns < CONTROL_MAX_DNS; j++) {
			if (ControlDhcpAddress(d->Dns[d->NumDns], dhcp->dns[j].bytes, dhcp->dns[j].size))
				d->NumDns++;
		}
		for (pb_size_t j = 0; j < dhcp->reserved_count && d->NumReserved < CONTROL_MAX_RESERVED; j++) {
			const ranz_control_v1_Prefix *p = &dhcp->reserved[j];
			CONTROL_RESERVED *r = &d->Reserved[d->NumReserved];

			if (p->length <= 32 && ControlDhcpAddress(r->Address, p->address.bytes, p->address.size)) {
				r->Length = p->length;
				d->NumReserved++;
			}
		}

		st->NumDhcps++;
	}

	// A delta appends the objects it adds, so the responders are sorted here
	qsort(st->Dhcps, st->NumDhcps, sizeof(CONTROL_DHCP), ControlCompareDhcps);
}

//
// The leases
//

CONTROL_LEASES *ControlNewLeases() {
	CONTROL_LEASES *l = ControlDhcpAlloc(sizeof(CONTROL_LEASES));

	if (l == NULL)
		return NULL;

	InitializeSRWLock(&l->Lock);
	l->Message = ControlDhcpAlloc(sizeof(ranz_control_v1_Leases));
	if (l->Message == NULL) {
		ControlDhcpFree(l);
		return NULL;
	}

	return l;
}

void ControlFreeLeases(CONTROL_LEASES *l) {
	if (l == NULL)
		return;

	for (UINT i = 0; i < l->NumReports; i++)
		ControlDhcpFree(l->Reports[i].Leases);
	ControlDhcpFree(l->Message);
	ControlDhcpFree(l);
}

// Put num leases of the Network network in place of the ones before; leases NULL takes the report of the Network away.
// False when the network name is empty or too long, there is no memory, or CONTROL_MAX_DHCPS other Networks have a
// report.
bool ControlSetLeases(CONTROL_LEASES *l, const char *network, const CONTROL_LEASE *leases, UINT num) {
	CONTROL_LEASE *copy = NULL;
	bool ok = true;
	UINT i = 0;

	if (l == NULL || network == NULL || network[0] == 0 || strlen(network) >= CONTROL_NAME_SIZE)
		return false;

	num = (leases == NULL ? 0 : (num < CONTROL_MAX_LEASES ? num : CONTROL_MAX_LEASES));
	if (num != 0) {
		copy = ControlDhcpAlloc(sizeof(CONTROL_LEASE) * num);
		if (copy == NULL)
			return false;
		CopyMemory(copy, leases, sizeof(CONTROL_LEASE) * num);
	}

	AcquireSRWLockExclusive(&l->Lock);
	while (i < l->NumReports && strcmp(l->Reports[i].Network, network) != 0)
		i++;

	if (leases == NULL) {
		// The Network has no responder any more
		if (i < l->NumReports) {
			ControlDhcpFree(l->Reports[i].Leases);
			MoveMemory(&l->Reports[i], &l->Reports[i + 1], sizeof(CONTROL_LEASE_REPORT) * (l->NumReports - i - 1));
			l->NumReports--;
		}
	} else if (i == l->NumReports && l->NumReports == CONTROL_MAX_DHCPS) {
		ok = false;
	} else {
		CONTROL_LEASE_REPORT *r = &l->Reports[i];

		if (i == l->NumReports) {
			ZeroMemory(r, sizeof(CONTROL_LEASE_REPORT));
			strcpy_s(r->Network, sizeof(r->Network), network);
			l->NumReports++;
		}
		ControlDhcpFree(r->Leases);
		r->Leases = copy;
		r->NumLeases = num;
		r->Sent = false;
		copy = NULL;
	}
	ReleaseSRWLockExclusive(&l->Lock);

	ControlDhcpFree(copy);
	return ok;
}

// A new stream has none of the reports
void ControlLeasesResend(CONTROL_LEASES *l) {
	if (l == NULL)
		return;

	AcquireSRWLockExclusive(&l->Lock);
	for (UINT i = 0; i < l->NumReports; i++)
		l->Reports[i].Sent = false;
	ReleaseSRWLockExclusive(&l->Lock);
}

// The report r as a Leases message. A host name keeps its printable ASCII characters, so the message is valid UTF-8.
static void ControlLeasesMessage(ranz_control_v1_Leases *m, const CONTROL_LEASE_REPORT *r) {
	ZeroMemory(m, sizeof(ranz_control_v1_Leases));
	strcpy_s(m->network, sizeof(m->network), r->Network);

	for (UINT i = 0; i < r->NumLeases; i++) {
		const CONTROL_LEASE *src = &r->Leases[i];
		ranz_control_v1_Lease *dst = &m->leases[m->leases_count++];
		UINT k = 0;

		dst->mac.size = 6;
		CopyMemory(dst->mac.bytes, src->Mac, 6);
		dst->address.size = 4;
		CopyMemory(dst->address.bytes, src->Address, 4);
		dst->expires_ms = src->Expires;
		for (UINT j = 0; j < CONTROL_HOST_NAME_SIZE - 1 && src->HostName[j] != 0; j++) {
			UCHAR c = (UCHAR)src->HostName[j];

			if (c >= 0x20 && c < 0x7F)
				dst->host_name[k++] = (char)c;
		}
	}
}

// Write m as the body Leases of a ControlMessage, in one frame
static bool ControlLeasesSend(const ranz_control_v1_Leases *m, TRANSPORT_STREAM *s) {
	pb_ostream_t sizing = PB_OSTREAM_SIZING;

	if (pb_encode_tag(&sizing, PB_WT_STRING, ranz_control_v1_ControlMessage_leases_tag) == false || pb_encode_submessage(&sizing, ranz_control_v1_Leases_fields, m) == false)
		return false;

	UINT size = (UINT)sizing.bytes_written;
	UCHAR *frame = ControlDhcpAlloc(CONTROL_LEASES_HEADER + (SIZE_T)size);
	if (frame == NULL)
		return false;

	pb_ostream_t os = pb_ostream_from_buffer(frame + CONTROL_LEASES_HEADER, size);
	bool ok = pb_encode_tag(&os, PB_WT_STRING, ranz_control_v1_ControlMessage_leases_tag) && pb_encode_submessage(&os, ranz_control_v1_Leases_fields, m) && os.bytes_written == size;
	if (ok) {
		frame[0] = (UCHAR)(size >> 24);
		frame[1] = (UCHAR)(size >> 16);
		frame[2] = (UCHAR)(size >> 8);
		frame[3] = (UCHAR)size;
		ok = TransportWrite(s, frame, CONTROL_LEASES_HEADER + size);
	}

	ControlDhcpFree(frame);
	return ok;
}

// Write each report that the stream does not have yet, one frame each, on the thread of the client: false when a write
// failed, which ends the stream
bool ControlWriteLeases(CONTROL_LEASES *l, TRANSPORT_STREAM *s) {
	if (l == NULL)
		return true;

	while (true) {
		bool found = false;

		AcquireSRWLockExclusive(&l->Lock);
		for (UINT i = 0; i < l->NumReports && found == false; i++) {
			CONTROL_LEASE_REPORT *r = &l->Reports[i];

			if (r->Sent == false) {
				r->Sent = true;
				ControlLeasesMessage(l->Message, r);
				found = true;
			}
		}
		ReleaseSRWLockExclusive(&l->Lock);

		if (found == false)
			return true;
		if (ControlLeasesSend(l->Message, s) == false)
			return false;
	}
}
