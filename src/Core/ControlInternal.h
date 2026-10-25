// ControlInternal.h
// Module-internal declarations of the control module (Control.c, ControlDhcp.c, ControlDns.c): only its own files include this
// header, after the messages that nanopb generates from the schema

#ifndef CORE_CONTROL_INTERNAL_H
#define CORE_CONTROL_INTERNAL_H

#include "Core/Control.h"

#include "ranz/control/v1/control.pb.h"

// ControlDhcp.c
void ControlCopyDhcps(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num);
void ControlLeasesResend(CONTROL_LEASES *l);

// ControlDns.c
void ControlCopyZones(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num);
void ControlFreeZones(CONTROL_STATE *st);

#endif // CORE_CONTROL_INTERNAL_H
