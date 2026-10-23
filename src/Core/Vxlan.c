// Vxlan.c
// The VXLAN module (RFC 7348): the VNIs that the module carries, each with its flood list, the sends of a frame to one
// VTEP or to each VTEP of a flood list, and VxlanInput, the one ingress of every datagram from a VTEP.

#include "Core/Vxlan.h"

#include <stdlib.h>
#include <string.h>

// One VNI that the module carries, and its flood list
typedef struct VXLAN_VNI {
	UINT Vni;          // The VNI
	UINT NumVteps;     // The VTEPs of its flood list
	VXLAN_ADDR *Vteps; // ... each once, sorted; NULL for none
} VXLAN_VNI;

// The VXLAN module of a node
struct VXLAN {
	VXLAN_SEND_PROC *Send;                    // Sends a datagram
	void *SendParam;                          // ... its first parameter
	VXLAN_RECV_PROC *Recv;                    // Takes the frames of the VNIs that the module carries, or NULL
	void *RecvParam;                          // ... its second parameter
	SRWLOCK Lock;                             // The VNIs: shared on the data path, exclusive for changes
	VXLAN_VNI *Vnis;                          // The VNIs that the module carries, sorted by VNI, in room for VXLAN_MAX_VNIS
	UINT NumVnis;                             // ... their number
	volatile LONG64 Sent;                     // Datagrams sent
	volatile LONG64 Delivered;                // Frames handed to the receiver
	volatile LONG64 Drops[VXLAN_NUM_REASONS]; // What the module dropped, by reason
};

// Count a datagram that the module dropped
static void VxlanDrop(VXLAN *v, UINT reason) {
	if (reason < VXLAN_NUM_REASONS)
		InterlockedIncrement64(&v->Drops[reason]);
}

// The order of two VTEPs: by address, then by port
static int VxlanCompareAddr(const void *p1, const void *p2) {
	const VXLAN_ADDR *a = (const VXLAN_ADDR *)p1;
	const VXLAN_ADDR *b = (const VXLAN_ADDR *)p2;
	int c = memcmp(a->Ip, b->Ip, sizeof(a->Ip));

	if (c != 0)
		return c;

	return (int)a->Port - (int)b->Port;
}

// Where the VNI vni is among the VNIs of the module, or would be; *found tells which. The caller holds the lock.
static UINT VxlanIndex(VXLAN *v, UINT vni, bool *found) {
	UINT lo = 0;
	UINT hi = v->NumVnis;

	*found = false;
	while (lo < hi) {
		UINT mid = lo + (hi - lo) / 2;

		if (v->Vnis[mid].Vni == vni) {
			*found = true;
			return mid;
		}
		if (v->Vnis[mid].Vni > vni)
			hi = mid;
		else
			lo = mid + 1;
	}

	return lo;
}

// The VNI vni among the VNIs of the module, NULL when the module does not carry it. The caller holds the lock.
static const VXLAN_VNI *VxlanFind(VXLAN *v, UINT vni) {
	bool found;
	UINT i = VxlanIndex(v, vni, &found);

	return (found ? &v->Vnis[i] : NULL);
}

// The datagram of a frame on the VNI vni, in buf of buf_size bytes: the VXLAN header with the I flag and the reserved
// bits zero (RFC 7348 section 5), then the frame as it is. Its size; 0 when vni has more than 24 bits, or the frame is
// shorter than VXLAN_MIN_FRAME, longer than VXLAN_MAX_FRAME or larger than buf.
static UINT VxlanEncode(UINT vni, const void *frame, UINT size, UCHAR *buf, UINT buf_size) {
	if (vni > VXLAN_MAX_VNI || frame == NULL || size < VXLAN_MIN_FRAME || size > VXLAN_MAX_FRAME || buf_size < VXLAN_HEADER_SIZE + size)
		return 0;

	ZeroMemory(buf, VXLAN_HEADER_SIZE);
	buf[0] = VXLAN_FLAG_VNI;
	buf[4] = (UCHAR)(vni >> 16);
	buf[5] = (UCHAR)(vni >> 8);
	buf[6] = (UCHAR)vni;
	CopyMemory(buf + VXLAN_HEADER_SIZE, frame, size);

	return VXLAN_HEADER_SIZE + size;
}

// Send one datagram and count it
static bool VxlanSendRaw(VXLAN *v, const VXLAN_ADDR *to, const UCHAR *data, UINT size) {
	if (v->Send(v->SendParam, to, data, size)) {
		InterlockedIncrement64(&v->Sent);
		return true;
	}

	VxlanDrop(v, VXLAN_DROP_SEND);
	return false;
}

// The VXLAN module of a node. send sends its datagrams, with send_param as its first parameter; recv takes the frames
// of the VNIs that the module carries and may be NULL. The module carries no VNI yet. NULL when there is no memory.
VXLAN *VxlanNew(VXLAN_SEND_PROC *send, void *send_param, VXLAN_RECV_PROC *recv, void *recv_param) {
	if (send == NULL)
		return NULL;

	VXLAN *v = (VXLAN *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(VXLAN));
	if (v == NULL)
		return NULL;

	v->Vnis = (VXLAN_VNI *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(VXLAN_VNI) * VXLAN_MAX_VNIS);
	if (v->Vnis == NULL) {
		HeapFree(GetProcessHeap(), 0, v);
		return NULL;
	}

	InitializeSRWLock(&v->Lock);
	v->Send = send;
	v->SendParam = send_param;
	v->Recv = recv;
	v->RecvParam = recv_param;

	return v;
}

// Free the module. The I/O that calls VxlanInput, and every sender, must have stopped before.
void VxlanFree(VXLAN *v) {
	if (v == NULL)
		return;

	// Each list through a local: HeapFree invalidates the pointer that it is given, which /analyze would then see in
	// every element of the array
	for (UINT i = 0; i < v->NumVnis; i++) {
		VXLAN_ADDR *vteps = v->Vnis[i].Vteps;

		if (vteps != NULL)
			HeapFree(GetProcessHeap(), 0, vteps);
	}

	HeapFree(GetProcessHeap(), 0, v->Vnis);
	HeapFree(GetProcessHeap(), 0, v);
}

// Carry the VNI vni, with the flood list of the num VTEPs of vteps (0 for none) in place of the list it had; a VTEP
// given twice gets one copy of a frame. The module takes the datagrams of a VNI it carries also while its flood list
// is empty. The change holds from the next send and the next datagram on, while the module runs: a frame that a
// VxlanSend sends meanwhile goes to the whole old list or the whole new one. False when vni has more than 24 bits, num
// is above VXLAN_MAX_VTEPS, the module carries VXLAN_MAX_VNIS other VNIs, or there is no memory; the VNIs stay as they
// were then.
bool VxlanSetVni(VXLAN *v, UINT vni, const VXLAN_ADDR *vteps, UINT num) {
	VXLAN_ADDR *list = NULL;
	VXLAN_ADDR *old = NULL;
	UINT n = 0;
	bool ok = false;

	if (v == NULL || vni > VXLAN_MAX_VNI || num > VXLAN_MAX_VTEPS || (vteps == NULL && num != 0))
		return false;

	if (num != 0) {
		list = (VXLAN_ADDR *)HeapAlloc(GetProcessHeap(), 0, sizeof(VXLAN_ADDR) * num);
		if (list == NULL)
			return false;

		CopyMemory(list, vteps, sizeof(VXLAN_ADDR) * num);
		if (num > 1)
			qsort(list, num, sizeof(VXLAN_ADDR), VxlanCompareAddr);

		// One entry per VTEP
		for (UINT i = 0; i < num; i++) {
			if (n != 0 && VxlanCompareAddr(&list[n - 1], &list[i]) == 0)
				continue;
			list[n++] = list[i];
		}
	}

	AcquireSRWLockExclusive(&v->Lock);
	{
		bool found;
		UINT i = VxlanIndex(v, vni, &found);

		if (found) {
			old = v->Vnis[i].Vteps;
			v->Vnis[i].NumVteps = n;
			v->Vnis[i].Vteps = list;
			ok = true;
		} else if (v->NumVnis < VXLAN_MAX_VNIS) {
			MoveMemory(&v->Vnis[i + 1], &v->Vnis[i], sizeof(VXLAN_VNI) * (v->NumVnis - i));
			v->Vnis[i].Vni = vni;
			v->Vnis[i].NumVteps = n;
			v->Vnis[i].Vteps = list;
			v->NumVnis++;
			ok = true;
		}
	}
	ReleaseSRWLockExclusive(&v->Lock);

	// The list that went, or the new one when there was no room for the VNI
	if (ok == false)
		old = list;
	if (old != NULL)
		HeapFree(GetProcessHeap(), 0, old);

	return ok;
}

// Stop carrying the VNI vni: its flood list goes, and the datagrams that VTEPs send on it are dropped from now on.
// False when the module does not carry it.
bool VxlanDelVni(VXLAN *v, UINT vni) {
	VXLAN_ADDR *old = NULL;
	bool found = false;

	if (v == NULL)
		return false;

	AcquireSRWLockExclusive(&v->Lock);
	{
		UINT i = VxlanIndex(v, vni, &found);

		if (found) {
			old = v->Vnis[i].Vteps;
			MoveMemory(&v->Vnis[i], &v->Vnis[i + 1], sizeof(VXLAN_VNI) * (v->NumVnis - i - 1));
			v->NumVnis--;
		}
	}
	ReleaseSRWLockExclusive(&v->Lock);

	if (old != NULL)
		HeapFree(GetProcessHeap(), 0, old);

	return found;
}

// Send frame, size bytes, on the VNI vni to each VTEP of its flood list: one datagram for each (ingress replication),
// under the shared lock, so the list stays whole while the frame goes out. False when the module does not carry vni,
// its flood list is empty, the frame is shorter than VXLAN_MIN_FRAME or longer than VXLAN_MAX_FRAME, or a datagram could
// not be sent.
bool VxlanSend(VXLAN *v, UINT vni, const void *frame, UINT size) {
	UCHAR buf[VXLAN_MAX_DATAGRAM];
	bool ok = false;

	if (v == NULL)
		return false;

	UINT len = VxlanEncode(vni, frame, size, buf, sizeof(buf));
	if (len == 0)
		return false;

	AcquireSRWLockShared(&v->Lock);
	{
		const VXLAN_VNI *e = VxlanFind(v, vni);

		if (e != NULL && e->NumVteps != 0) {
			ok = true;
			for (UINT i = 0; i < e->NumVteps; i++)
				if (VxlanSendRaw(v, &e->Vteps[i], buf, len) == false)
					ok = false;
		}
	}
	ReleaseSRWLockShared(&v->Lock);

	return ok;
}

// Send frame, size bytes, on the VNI vni to the one VTEP vtep, whether the module carries vni or not: a Mirror to its
// sensor, the EVPN gateway to the VTEP of a known MAC. False when vni has more than 24 bits, the frame is shorter than
// VXLAN_MIN_FRAME or longer than VXLAN_MAX_FRAME, or the datagram could not be sent.
bool VxlanSendTo(VXLAN *v, UINT vni, const VXLAN_ADDR *vtep, const void *frame, UINT size) {
	UCHAR buf[VXLAN_MAX_DATAGRAM];

	if (v == NULL || vtep == NULL)
		return false;

	UINT len = VxlanEncode(vni, frame, size, buf, sizeof(buf));
	if (len == 0)
		return false;

	return VxlanSendRaw(v, vtep, buf, len);
}

// The one ingress of the module: every datagram that the node receives from a VTEP, from the address from. A datagram
// with the I flag, a VNI that the module carries and a frame of VXLAN_MIN_FRAME to VXLAN_MAX_FRAME bytes goes to the
// receiver; the reserved bits are not looked at (RFC 7348 section 5). A datagram on any other VNI is dropped as
// VXLAN_DROP_VNI, anything else as VXLAN_DROP_MALFORMED.
void VxlanInput(VXLAN *v, const VXLAN_ADDR *from, const UCHAR *data, UINT size) {
	bool known = false;

	if (v == NULL || from == NULL || data == NULL)
		return;

	if (size < VXLAN_HEADER_SIZE + VXLAN_MIN_FRAME || size > VXLAN_MAX_DATAGRAM || (data[0] & VXLAN_FLAG_VNI) == 0) {
		VxlanDrop(v, VXLAN_DROP_MALFORMED);
		return;
	}

	UINT vni = ((UINT)data[4] << 16) | ((UINT)data[5] << 8) | data[6];

	AcquireSRWLockShared(&v->Lock);
	{
		known = (VxlanFind(v, vni) != NULL);
	}
	ReleaseSRWLockShared(&v->Lock);

	if (known == false) {
		VxlanDrop(v, VXLAN_DROP_VNI);
		return;
	}

	InterlockedIncrement64(&v->Delivered);
	if (v->Recv != NULL)
		v->Recv(v, v->RecvParam, vni, from, data + VXLAN_HEADER_SIZE, size - VXLAN_HEADER_SIZE);
}

void VxlanGetStats(VXLAN *v, VXLAN_STATS *st) {
	if (st == NULL)
		return;

	ZeroMemory(st, sizeof(VXLAN_STATS));
	if (v == NULL)
		return;

	st->Sent = (UINT64)ReadAcquire64(&v->Sent);
	st->Delivered = (UINT64)ReadAcquire64(&v->Delivered);
	for (UINT i = 0; i < VXLAN_NUM_REASONS; i++)
		st->Drops[i] = (UINT64)ReadAcquire64(&v->Drops[i]);

	AcquireSRWLockShared(&v->Lock);
	{
		st->NumVnis = v->NumVnis;
	}
	ReleaseSRWLockShared(&v->Lock);
}

void VxlanAddrSetV4(VXLAN_ADDR *a, UCHAR b0, UCHAR b1, UCHAR b2, UCHAR b3, USHORT port) {
	if (a == NULL)
		return;

	ZeroMemory(a, sizeof(VXLAN_ADDR));
	a->Ip[10] = 0xFF;
	a->Ip[11] = 0xFF;
	a->Ip[12] = b0;
	a->Ip[13] = b1;
	a->Ip[14] = b2;
	a->Ip[15] = b3;
	a->Port = port;
}
