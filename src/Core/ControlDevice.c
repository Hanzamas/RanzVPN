// ControlDevice.c
// The WireGuard Devices on the control stream (SDN-80, #375; Core/Control.h). The Device objects of a state become the
// Devices of the state that the client hands to its owner (ControlCopyDevices), each with its addresses, its tags and
// its gateway, and with its WireGuard key in the state of its gateway, which also takes the UDP port of its WireGuard
// interface from its NodeConfig. The gateway reports the last handshake and the traffic of each of its Devices
// (ControlSetDevices): the client sends all of them in one Telemetry message after each Hello, so a controller that the
// node reaches anew has them, and whenever they changed, at most every CONTROL_DEVICE_REPORT ms.

#include "Core/ControlInternal.h"

#include <pb_encode.h>

#include <stdlib.h>
#include <string.h>

#define CONTROL_DEVICES_HEADER 4 // The size of a frame, big-endian, before its message (as Control.c writes them)

// The counters that a client reports
struct CONTROL_DEVICES {
	// The counters and their state
	SRWLOCK Lock;
	// The Devices whose counters the owner set last
	UINT NumCounters;
	CONTROL_DEVICE_COUNTERS Counters[CONTROL_MAX_DEVICES];
	// They changed since the client sent them
	bool Changed;
	// When the client sent them last, 0 for never on the stream that runs
	UINT64 Sent;
	// The message that the thread of the client writes
	ranz_control_v1_Telemetry *Message;
};

static void *ControlDeviceAlloc(SIZE_T size) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

static void ControlDeviceFree(void *p) {
	if (p != NULL)
		HeapFree(GetProcessHeap(), 0, p);
}

//
// The Devices of a state
//

static int ControlCompareDevices(const void *a, const void *b) {
	return strcmp(((const CONTROL_DEVICE *)a)->Name, ((const CONTROL_DEVICE *)b)->Name);
}

// Copy a Device object into d: false for one without a name or without an address that is IPv4 or IPv6, or with a key
// that is not one
static bool ControlCopyDevice(CONTROL_DEVICE *d, const ranz_control_v1_Device *src) {
	ZeroMemory(d, sizeof(CONTROL_DEVICE));
	strncpy_s(d->Name, sizeof(d->Name), src->name, _TRUNCATE);
	strncpy_s(d->Gateway, sizeof(d->Gateway), src->gateway, _TRUNCATE);
	d->VrfId = src->vrf_id;

	// An address that is not IPv4 or IPv6 is skipped, so i is bounded by the array of the message too
	for (pb_size_t i = 0; i < src->addresses_count && i < ARRAYSIZE(src->addresses) && d->NumAddresses < CONTROL_DEVICE_ADDRESSES; i++) {
		const ranz_control_v1_Address *a = &src->addresses[i];
		CONTROL_ADDRESS *c = &d->Addresses[d->NumAddresses];

		if (a->has_prefix == false || (a->prefix.address.size != 4 && a->prefix.address.size != 16))
			continue;

		strncpy_s(c->Network, sizeof(c->Network), a->network, _TRUNCATE);
		c->VrfId = a->vrf_id;
		CopyMemory(c->Address, a->prefix.address.bytes, a->prefix.address.size);
		c->AddressSize = a->prefix.address.size;
		c->Length = c->AddressSize * 8;
		d->NumAddresses++;
	}

	for (pb_size_t i = 0; i < src->tags_count && d->NumTags < CONTROL_MAX_TAGS; i++)
		strncpy_s(d->Tags[d->NumTags++], CONTROL_NAME_SIZE, src->tags[i], _TRUNCATE);

	if (src->public_key.size != 0) {
		if (src->public_key.size != NOISE_KEY_SIZE)
			return false;

		CopyMemory(d->Key, src->public_key.bytes, NOISE_KEY_SIZE);
		d->HasKey = true;
	}

	return (d->Name[0] != 0 && d->NumAddresses != 0);
}

// Put into st the UDP port of the WireGuard interface of the node from its NodeConfig and the Devices of the num
// objects, sorted by name. A Device that cannot be read whole is left out. With no memory for the Devices, the state has
// none.
void ControlCopyDevices(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num) {
	UINT max = 0;

	for (UINT i = 0; i < num; i++) {
		if (objects[i].which_kind == ranz_control_v1_Object_node_tag)
			st->WireGuardPort = objects[i].kind.node.wireguard_port;
		else if (objects[i].which_kind == ranz_control_v1_Object_device_tag)
			max++;
	}

	st->NumDevices = 0;
	st->Devices = ControlDeviceAlloc(sizeof(CONTROL_DEVICE) * (max != 0 ? max : 1));
	if (st->Devices == NULL)
		return;

	for (UINT i = 0; i < num && st->NumDevices < max; i++) {
		if (objects[i].which_kind != ranz_control_v1_Object_device_tag)
			continue;

		if (ControlCopyDevice(&st->Devices[st->NumDevices], &objects[i].kind.device))
			st->NumDevices++;
	}

	// A delta appends the objects it adds, so the Devices are sorted here
	qsort(st->Devices, st->NumDevices, sizeof(CONTROL_DEVICE), ControlCompareDevices);
}

// Free the Devices that ControlCopyDevices put into st
void ControlFreeStateDevices(CONTROL_STATE *st) {
	if (st->Devices == NULL)
		return;

	SecureZeroMemory(st->Devices, sizeof(CONTROL_DEVICE) * (st->NumDevices != 0 ? st->NumDevices : 1));
	ControlDeviceFree(st->Devices);
	st->Devices = NULL;
	st->NumDevices = 0;
}

//
// The counters
//

CONTROL_DEVICES *ControlNewDevices() {
	CONTROL_DEVICES *d = ControlDeviceAlloc(sizeof(CONTROL_DEVICES));

	if (d == NULL)
		return NULL;

	InitializeSRWLock(&d->Lock);
	d->Message = ControlDeviceAlloc(sizeof(ranz_control_v1_Telemetry));
	if (d->Message == NULL) {
		ControlDeviceFree(d);
		return NULL;
	}

	return d;
}

void ControlFreeDevices(CONTROL_DEVICES *d) {
	if (d == NULL)
		return;

	ControlDeviceFree(d->Message);
	ControlDeviceFree(d);
}

// Put the counters of num Devices in place of the ones before, CONTROL_MAX_DEVICES at most: the client sends them when
// they differ from the ones it sent
void ControlSetDevices(CONTROL_DEVICES *d, const CONTROL_DEVICE_COUNTERS *counters, UINT num) {
	if (d == NULL || (counters == NULL && num != 0))
		return;

	num = (num < CONTROL_MAX_DEVICES ? num : CONTROL_MAX_DEVICES);

	AcquireSRWLockExclusive(&d->Lock);
	if (num != d->NumCounters || (num != 0 && memcmp(d->Counters, counters, sizeof(CONTROL_DEVICE_COUNTERS) * num) != 0)) {
		if (num != 0)
			CopyMemory(d->Counters, counters, sizeof(CONTROL_DEVICE_COUNTERS) * num);
		d->NumCounters = num;
		d->Changed = true;
	}
	ReleaseSRWLockExclusive(&d->Lock);
}

// A new stream has none of the counters
void ControlDevicesResend(CONTROL_DEVICES *d) {
	if (d == NULL)
		return;

	AcquireSRWLockExclusive(&d->Lock);
	d->Changed = (d->NumCounters != 0);
	d->Sent = 0;
	ReleaseSRWLockExclusive(&d->Lock);
}

// Write m as the body Telemetry of a ControlMessage, in one frame
static bool ControlDevicesSend(const ranz_control_v1_Telemetry *m, TRANSPORT_STREAM *s) {
	pb_ostream_t sizing = PB_OSTREAM_SIZING;

	if (pb_encode_tag(&sizing, PB_WT_STRING, ranz_control_v1_ControlMessage_telemetry_tag) == false || pb_encode_submessage(&sizing, ranz_control_v1_Telemetry_fields, m) == false)
		return false;

	UINT size = (UINT)sizing.bytes_written;
	UCHAR *frame = ControlDeviceAlloc(CONTROL_DEVICES_HEADER + (SIZE_T)size);
	if (frame == NULL)
		return false;

	pb_ostream_t os = pb_ostream_from_buffer(frame + CONTROL_DEVICES_HEADER, size);
	bool ok = pb_encode_tag(&os, PB_WT_STRING, ranz_control_v1_ControlMessage_telemetry_tag) && pb_encode_submessage(&os, ranz_control_v1_Telemetry_fields, m) && os.bytes_written == size;
	if (ok) {
		frame[0] = (UCHAR)(size >> 24);
		frame[1] = (UCHAR)(size >> 16);
		frame[2] = (UCHAR)(size >> 8);
		frame[3] = (UCHAR)size;
		ok = TransportWrite(s, frame, CONTROL_DEVICES_HEADER + size);
	}

	ControlDeviceFree(frame);
	return ok;
}

// Write the counters as one Telemetry message when they changed since the client sent them and CONTROL_DEVICE_REPORT ms
// passed since then, on the thread of the client: false when the write failed, which ends the stream
bool ControlWriteDevices(CONTROL_DEVICES *d, TRANSPORT_STREAM *s) {
	bool due = false;
	UINT64 now = GetTickCount64();

	if (d == NULL)
		return true;

	AcquireSRWLockExclusive(&d->Lock);
	if (d->Changed && (d->Sent == 0 || now - d->Sent >= CONTROL_DEVICE_REPORT)) {
		ranz_control_v1_Telemetry *m = d->Message;

		ZeroMemory(m, sizeof(ranz_control_v1_Telemetry));
		for (UINT i = 0; i < d->NumCounters; i++) {
			const CONTROL_DEVICE_COUNTERS *c = &d->Counters[i];
			ranz_control_v1_DeviceCounters *dc = &m->devices[m->devices_count++];

			strncpy_s(dc->device, sizeof(dc->device), c->Name, _TRUNCATE);
			dc->last_handshake_ms = c->LastHandshake;
			dc->tx_bytes = c->TxBytes;
			dc->rx_bytes = c->RxBytes;
		}
		d->Changed = false;
		d->Sent = now;
		due = true;
	}
	ReleaseSRWLockExclusive(&d->Lock);

	return (due == false || ControlDevicesSend(d->Message, s));
}
