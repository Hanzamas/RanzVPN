// ControlPins.c
// The TLS fingerprints of the certificate of the Controller on the control stream (SDN-92, #397; Core/Control.h). The
// NodeConfig of a state that carries controller_tls gives the state the fingerprints (CONTROL_STATE.TlsPins) while the owner
// takes the state, so that a node that pinned the fingerprint of the certificate in use takes the one of the certificate that
// comes next before the Controller serves it. A value that is not 64 hex digits is left out.

#include "Core/ControlInternal.h"

#include <string.h>

// Whether s is 64 hex digits and nothing else
static bool ControlTlsPinOk(const char *s) {
	UINT i;

	for (i = 0; s[i] != 0; i++)
		if (i >= CONTROL_TLS_PIN_SIZE - 1 || ((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f') || (s[i] >= 'A' && s[i] <= 'F')) == false)
			return false;

	return (i == CONTROL_TLS_PIN_SIZE - 1);
}

// The fingerprints of the NodeConfig among num objects into the state, in lower case, each once, in the order the Controller
// sent them: the first one is the certificate in use. A state whose NodeConfig has none has none.
void ControlCopyTlsPins(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num) {
	st->NumTlsPins = 0;

	for (UINT i = 0; i < num; i++) {
		const ranz_control_v1_Object *o = &objects[i];

		if (o->which_kind != ranz_control_v1_Object_node_tag)
			continue;

		for (pb_size_t j = 0; j < o->kind.node.controller_tls_count && st->NumTlsPins < CONTROL_TLS_PINS; j++) {
			const char *pin = o->kind.node.controller_tls[j];
			char *dst = st->TlsPins[st->NumTlsPins];
			bool again = false;

			if (ControlTlsPinOk(pin) == false)
				continue;

			for (UINT k = 0; k < CONTROL_TLS_PIN_SIZE - 1; k++)
				dst[k] = (char)(pin[k] >= 'A' && pin[k] <= 'F' ? pin[k] + ('a' - 'A') : pin[k]);
			dst[CONTROL_TLS_PIN_SIZE - 1] = 0;

			for (UINT k = 0; k < st->NumTlsPins && again == false; k++)
				again = (strcmp(st->TlsPins[k], dst) == 0);
			if (again == false)
				st->NumTlsPins++;
		}

		return;
	}
}
