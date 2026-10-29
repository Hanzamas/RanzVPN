// ControlOperation.c
// The live operations of an operator on the control stream (SDN-50-N, #492; Core/Control.h; ADR-0027 and ADR-0031
// amendments of 2026-10-27). The Controller asks a node to read or clear the MAC table or the IP table of one of its L2
// Networks with an Operation, which it sends only to a node that reports the Capability operations: the client reports it
// when its owner gives it the procedure of the operations (CONTROL_CONFIG.OperationProc). The client takes an Operation as it
// comes, on its thread (ControlTakeOperation). It answers no-network for a Network that the desired state that it applied
// does not give the node as an L2 Network, an L3 Network of that name among them, and failed for an Operation of a kind that
// it does not know, or with a MAC address or an address of a size that none has; it hands any other to its owner, which reads
// or clears the switch of the Network. The answer takes the place of the Operation in the message of the client, which
// writes it as one frame (ControlWriteOperationResult): an OperationResult of the same id, with the first
// CONTROL_MAX_ENTRIES entries of a table that it read and the total, in the TableEntry form of the control protocol. Its
// strings keep their printable ASCII characters, so that the frame is valid UTF-8, as the Controller reads it. An Operation
// is no desired state: the client keeps nothing of it, and the stream goes on after it, whatever the answer.

#include "Core/ControlInternal.h"

#include <pb_encode.h>

#include <string.h>

#define CONTROL_OPERATION_HEADER 4 // The size of a frame, big-endian, before its message (as Control.c writes them)

// The kinds and the statuses are the values of the schema, and the sizes of an answer are the ones of control.options
_Static_assert(CONTROL_OPERATION_MAC_TABLE == (UINT)ranz_control_v1_OperationKind_OPERATION_KIND_MAC_TABLE, "CONTROL_OPERATION_MAC_TABLE is OPERATION_KIND_MAC_TABLE of the control protocol");
_Static_assert(CONTROL_OPERATION_CLEAR_MAC_TABLE == (UINT)ranz_control_v1_OperationKind_OPERATION_KIND_CLEAR_MAC_TABLE, "CONTROL_OPERATION_CLEAR_MAC_TABLE is OPERATION_KIND_CLEAR_MAC_TABLE of the control protocol");
_Static_assert(CONTROL_OPERATION_IP_TABLE == (UINT)ranz_control_v1_OperationKind_OPERATION_KIND_IP_TABLE, "CONTROL_OPERATION_IP_TABLE is OPERATION_KIND_IP_TABLE of the control protocol");
_Static_assert(CONTROL_OPERATION_CLEAR_IP_TABLE == (UINT)ranz_control_v1_OperationKind_OPERATION_KIND_CLEAR_IP_TABLE, "CONTROL_OPERATION_CLEAR_IP_TABLE is OPERATION_KIND_CLEAR_IP_TABLE of the control protocol");
_Static_assert(CONTROL_OPERATION_OK == (UINT)ranz_control_v1_OperationStatus_OPERATION_STATUS_OK, "CONTROL_OPERATION_OK is OPERATION_STATUS_OK of the control protocol");
_Static_assert(CONTROL_OPERATION_NO_NETWORK == (UINT)ranz_control_v1_OperationStatus_OPERATION_STATUS_NO_NETWORK, "CONTROL_OPERATION_NO_NETWORK is OPERATION_STATUS_NO_NETWORK of the control protocol");
_Static_assert(CONTROL_OPERATION_FAILED == (UINT)ranz_control_v1_OperationStatus_OPERATION_STATUS_FAILED, "CONTROL_OPERATION_FAILED is OPERATION_STATUS_FAILED of the control protocol");
_Static_assert(CONTROL_MAX_ENTRIES == sizeof(((ranz_control_v1_OperationResult *)0)->entries) / sizeof(((ranz_control_v1_OperationResult *)0)->entries[0]), "an OperationResult holds CONTROL_MAX_ENTRIES entries");
_Static_assert(CONTROL_OPERATION_MESSAGE_SIZE == sizeof(((ranz_control_v1_OperationResult *)0)->message), "OperationResult.message holds CONTROL_OPERATION_MESSAGE_SIZE bytes");
_Static_assert(CONTROL_NAME_SIZE == sizeof(((ranz_control_v1_TableEntry *)0)->member), "TableEntry.member holds a name");
_Static_assert(CONTROL_NAME_SIZE == sizeof(((ranz_control_v1_Operation *)0)->network), "Operation.network holds a name");

static void *ControlOperationAlloc(SIZE_T size) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

static void ControlOperationFree(void *p) {
	if (p != NULL)
		HeapFree(GetProcessHeap(), 0, p);
}

// Copy the printable ASCII characters of the string src, of src_size bytes at most, into dst of dst_size bytes, so that a
// string of the answer is valid UTF-8
static void ControlOperationText(char *dst, UINT dst_size, const char *src, UINT src_size) {
	UINT k = 0;

	for (UINT i = 0; i < src_size && src[i] != 0 && k + 1 < dst_size; i++) {
		UCHAR ch = (UCHAR)src[i];

		if (ch >= 0x20 && ch < 0x7F)
			dst[k++] = (char)ch;
	}
	dst[k] = 0;
}

// Whether the objects of the desired state, num of them, give the node the L2 Network name; *l3 says whether they give it an
// L3 Network of that name
static bool ControlOperationHolds(const ranz_control_v1_Object *objects, UINT num, const char *name, bool *l3) {
	*l3 = false;

	for (UINT i = 0; i < num; i++) {
		if (objects[i].which_kind != ranz_control_v1_Object_network_tag)
			continue;

		const ranz_control_v1_Network *nw = &objects[i].kind.network;
		if (strcmp(nw->name, name) != 0)
			continue;
		if (nw->mode == ranz_control_v1_NetworkMode_NETWORK_MODE_L2)
			return true;
		*l3 = true;
	}

	return false;
}

// The Operation op as the owner takes it, into o: false, with why into message of size bytes, for an Operation of a kind
// that the node does not know, or with a MAC address or an address of a size that none has. Only a clear of the MAC table
// takes its MAC address, and only a clear of the IP table its address.
static bool ControlOperationOf(CONTROL_OPERATION *o, const ranz_control_v1_Operation *op, char *message, UINT size) {
	ZeroMemory(o, sizeof(CONTROL_OPERATION));
	o->Id = op->id;
	o->Kind = (UINT)op->kind;
	strncpy_s(o->Network, sizeof(o->Network), op->network, _TRUNCATE);

	if (o->Kind < CONTROL_OPERATION_MAC_TABLE || o->Kind > CONTROL_OPERATION_CLEAR_IP_TABLE) {
		strcpy_s(message, size, "an Operation of a kind that the node does not know");
		return false;
	}
	if (op->mac.size != 0 && op->mac.size != sizeof(o->Mac)) {
		strcpy_s(message, size, "a MAC address has 6 bytes");
		return false;
	}
	if (op->address.size != 0 && op->address.size != 4 && op->address.size != 16) {
		strcpy_s(message, size, "an address has 4 bytes for IPv4 or 16 bytes for IPv6");
		return false;
	}

	if (o->Kind == CONTROL_OPERATION_CLEAR_MAC_TABLE && op->mac.size != 0) {
		o->HasMac = true;
		CopyMemory(o->Mac, op->mac.bytes, sizeof(o->Mac));
	}
	if (o->Kind == CONTROL_OPERATION_CLEAR_IP_TABLE && op->address.size != 0) {
		o->AddressSize = op->address.size;
		CopyMemory(o->Address, op->address.bytes, op->address.size);
	}

	return true;
}

// The answer res to the Operation of the id id into m, in the place of the Operation: a status that is none of the three is
// failed, a read lists the first CONTROL_MAX_ENTRIES entries that the owner gave with a total of no fewer, and a clear only
// its total. An answer that is not ok lists nothing. res NULL: the client had no memory for the answer.
static void ControlOperationAnswer(ranz_control_v1_ControlMessage *m, UINT64 id, const CONTROL_OPERATION_RESULT *res, bool read) {
	ZeroMemory(m, sizeof(ranz_control_v1_ControlMessage));
	m->which_body = ranz_control_v1_ControlMessage_operation_result_tag;

	ranz_control_v1_OperationResult *r = &m->body.operation_result;
	r->id = id;
	r->status = ranz_control_v1_OperationStatus_OPERATION_STATUS_FAILED;
	if (res == NULL) {
		strcpy_s(r->message, sizeof(r->message), "the node had no memory for the answer");
		return;
	}

	if (res->Status == CONTROL_OPERATION_OK || res->Status == CONTROL_OPERATION_NO_NETWORK)
		r->status = (ranz_control_v1_OperationStatus)res->Status;
	ControlOperationText(r->message, sizeof(r->message), res->Message, sizeof(res->Message));
	if (r->status != ranz_control_v1_OperationStatus_OPERATION_STATUS_OK)
		return;

	r->total = res->Total;
	if (read == false)
		return;

	UINT num = (res->NumEntries < CONTROL_MAX_ENTRIES ? res->NumEntries : CONTROL_MAX_ENTRIES);
	for (UINT i = 0; i < num; i++) {
		const CONTROL_TABLE_ENTRY *e = &res->Entries[i];
		ranz_control_v1_TableEntry *t = &r->entries[i];

		t->vlan = e->Vlan;
		t->mac.size = 6;
		CopyMemory(t->mac.bytes, e->Mac, 6);
		if (e->AddressSize == 4 || e->AddressSize == 16) {
			t->address.size = (pb_size_t)e->AddressSize;
			CopyMemory(t->address.bytes, e->Address, e->AddressSize);
		}
		ControlOperationText(t->member, sizeof(t->member), e->Member, sizeof(e->Member));
		t->last_seen_ms = e->LastSeen;
	}
	r->entries_count = (pb_size_t)num;
	if (r->total < num)
		r->total = num;
}

// Take an Operation of the Controller, the body of m, as the client takes it from its stream: the node does it on its L2
// Network, and the OperationResult of the same id takes its place in m, for the client to write. True: the stream goes on,
// whatever the answer.
bool ControlTakeOperation(const CONTROL_CONFIG *cfg, const ranz_control_v1_Object *objects, UINT num, ranz_control_v1_ControlMessage *m) {
	CONTROL_OPERATION op;
	bool l3 = false;

	// The answer of up to CONTROL_MAX_ENTRIES entries is too large for the stack of the thread
	CONTROL_OPERATION_RESULT *res = ControlOperationAlloc(sizeof(CONTROL_OPERATION_RESULT));
	if (res == NULL) {
		ControlOperationAnswer(m, m->body.operation.id, NULL, false);
		return true;
	}

	bool valid = ControlOperationOf(&op, &m->body.operation, res->Message, sizeof(res->Message));
	bool read = (op.Kind == CONTROL_OPERATION_MAC_TABLE || op.Kind == CONTROL_OPERATION_IP_TABLE);

	if (ControlOperationHolds(objects, num, op.Network, &l3) == false) {
		res->Status = CONTROL_OPERATION_NO_NETWORK;
		strcpy_s(res->Message, sizeof(res->Message), (l3 ? "the Network is an L3 Network, which has no MAC table and no IP table" : "the node holds no L2 Network of that name"));
	} else if (valid == false) {
		res->Status = CONTROL_OPERATION_FAILED;
	} else if (cfg->OperationProc == NULL) {
		res->Status = CONTROL_OPERATION_FAILED;
		strcpy_s(res->Message, sizeof(res->Message), "the node does no live operations");
	} else {
		cfg->OperationProc(cfg->OperationParam, &op, res);
	}

	ControlOperationAnswer(m, op.Id, res, read);
	ControlOperationFree(res);

	return true;
}

// Write the answer r as the body OperationResult of a ControlMessage, in one frame: false when it could not be encoded or
// written, which ends the stream
bool ControlWriteOperationResult(const ranz_control_v1_OperationResult *r, TRANSPORT_STREAM *s) {
	pb_ostream_t sizing = PB_OSTREAM_SIZING;

	if (pb_encode_tag(&sizing, PB_WT_STRING, ranz_control_v1_ControlMessage_operation_result_tag) == false || pb_encode_submessage(&sizing, ranz_control_v1_OperationResult_fields, r) == false)
		return false;

	UINT size = (UINT)sizing.bytes_written;
	UCHAR *frame = ControlOperationAlloc(CONTROL_OPERATION_HEADER + (SIZE_T)size);
	if (frame == NULL)
		return false;

	pb_ostream_t os = pb_ostream_from_buffer(frame + CONTROL_OPERATION_HEADER, size);
	bool ok = pb_encode_tag(&os, PB_WT_STRING, ranz_control_v1_ControlMessage_operation_result_tag) && pb_encode_submessage(&os, ranz_control_v1_OperationResult_fields, r) && os.bytes_written == size;
	if (ok) {
		frame[0] = (UCHAR)(size >> 24);
		frame[1] = (UCHAR)(size >> 16);
		frame[2] = (UCHAR)(size >> 8);
		frame[3] = (UCHAR)size;
		ok = TransportWrite(s, frame, CONTROL_OPERATION_HEADER + size);
	}

	ControlOperationFree(frame);
	return ok;
}
