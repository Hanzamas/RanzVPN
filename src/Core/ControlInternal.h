// ControlInternal.h
// Module-internal declarations of the control module (Control.c, ControlDhcp.c): only its own files include this
// header, after the messages that nanopb generates from the schema

#ifndef CORE_CONTROL_INTERNAL_H
#define CORE_CONTROL_INTERNAL_H

#include "Core/Control.h"

#include "ranz/control/v1/control.pb.h"

// ControlDhcp.c
void ControlCopyDhcps(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num);
void ControlLeasesResend(CONTROL_LEASES *l);

// ControlDevice.c
void ControlCopyDevices(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num);
void ControlFreeStateDevices(CONTROL_STATE *st);
void ControlDevicesResend(CONTROL_DEVICES *d);

#endif // CORE_CONTROL_INTERNAL_H
