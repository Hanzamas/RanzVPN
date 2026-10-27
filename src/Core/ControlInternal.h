// ControlInternal.h
// Module-internal declarations of the control module (Control.c, ControlDhcp.c, ControlDns.c, ControlListener.c, ControlDevice.c, ControlEndpoint.c, ControlLink.c, ControlPins.c, ControlSignal.c): only its own
// files include this
// header, after the messages that nanopb generates from the schema

#ifndef CORE_CONTROL_INTERNAL_H
#define CORE_CONTROL_INTERNAL_H

#include "Core/Control.h"

#include "ranz/control/v1/control.pb.h"

// Control.c: the decode of the message of a frame of the controller into the Message of a client, and the apply of an
// Update to the objects of the client, which ControlInput runs
bool ControlDecode(CONTROL_CLIENT *c, const UCHAR *data, UINT size);
bool ControlApply(CONTROL_CLIENT *c, const ranz_control_v1_Update *u);

// ControlDhcp.c
void ControlCopyDhcps(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num);
void ControlLeasesResend(CONTROL_LEASES *l);

// ControlDns.c
void ControlCopyZones(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num);
void ControlFreeZones(CONTROL_STATE *st);

// ControlListener.c
void ControlCopyListener(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num);
void ControlFreeListener(CONTROL_STATE *st);

// ControlPins.c
void ControlCopyTlsPins(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num);

// ControlDevice.c
void ControlCopyDevices(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num);
void ControlFreeStateDevices(CONTROL_STATE *st);
void ControlDevicesResend(CONTROL_DEVICES *d);

// ControlEndpoint.c
void ControlCopyEndpoints(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num);

// ControlLink.c
void ControlCopyLinks(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num);

// ControlSignal.c
void ControlCopyRelays(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num);
void ControlTakeSignal(const CONTROL_CONFIG *cfg, const ranz_control_v1_Signal *sig);

#endif // CORE_CONTROL_INTERNAL_H
