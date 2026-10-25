// ControlPolicy.h
// The policy of the VRFs in a desired state (ControlPolicy.c; SDN-8, #184), for Control.c: the module's own header,
// which the nanopb messages need

#ifndef CORE_CONTROL_POLICY_H
#define CORE_CONTROL_POLICY_H

#include "Core/Control.h"

#include "ranz/control/v1/control.pb.h"

void ControlCopyPolicy(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num);
void ControlFreePolicy(CONTROL_STATE *st);

#endif // CORE_CONTROL_POLICY_H
