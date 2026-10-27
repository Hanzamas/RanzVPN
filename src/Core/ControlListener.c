// ControlListener.c
// The Listener of a node on the control stream (SDN-45, #238; ADR-0035; Core/Control.h). The NodeConfig of a state that
// carries a Listener gives the state its Listener (CONTROL_STATE.Listener) while the owner takes the state
// (ControlCopyListener), and the Listener goes with the state (ControlFreeListener). The node listens where it says.

#include "Core/ControlInternal.h"

#include <string.h>

// The source of the certificate of src into l: CONTROL_CERT_NONE for a Listener that names none
static void ControlCopyCertificate(CONTROL_LISTENER *l, const ranz_control_v1_Listener *src) {
	switch (src->which_certificate) {
	case ranz_control_v1_Listener_file_tag:
		l->Source = CONTROL_CERT_FILE;
		strncpy_s(l->Path, sizeof(l->Path), src->certificate.file.path, _TRUNCATE);
		strncpy_s(l->PasswordFile, sizeof(l->PasswordFile), src->certificate.file.password_file, _TRUNCATE);
		break;
	case ranz_control_v1_Listener_ksp_tag:
		l->Source = CONTROL_CERT_KSP;
		strncpy_s(l->Thumbprint, sizeof(l->Thumbprint), src->certificate.ksp, _TRUNCATE);
		break;
	case ranz_control_v1_Listener_acme_tag:
		l->Source = CONTROL_CERT_ACME;
		strncpy_s(l->Directory, sizeof(l->Directory), src->certificate.acme.directory, _TRUNCATE);
		strncpy_s(l->Email, sizeof(l->Email), src->certificate.acme.email, _TRUNCATE);
		for (pb_size_t i = 0; i < src->certificate.acme.names_count && l->NumNames < CONTROL_ACME_NAMES; i++) {
			if (src->certificate.acme.names[i][0] == 0)
				continue;

			strncpy_s(l->Names[l->NumNames], sizeof(l->Names[l->NumNames]), src->certificate.acme.names[i], _TRUNCATE);
			l->NumNames++;
		}
		l->HttpPort = src->certificate.acme.http_port;
		strncpy_s(l->CaFile, sizeof(l->CaFile), src->certificate.acme.ca_file, _TRUNCATE);
		l->RenewDays = src->certificate.acme.renew_days;
		break;
	default:
		l->Source = CONTROL_CERT_NONE;
		break;
	}
}

// The Listener of the NodeConfig among num objects into the state. A state whose NodeConfig has none has none, and so
// has one whose Listener names no source of a certificate, a port above 65535, or an ACME source without a name; a
// Listener that cannot be allocated is left out.
void ControlCopyListener(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num) {
	st->Listener = NULL;

	for (UINT i = 0; i < num; i++) {
		const ranz_control_v1_Object *o = &objects[i];

		if (o->which_kind != ranz_control_v1_Object_node_tag || o->kind.node.has_listener == false)
			continue;

		const ranz_control_v1_Listener *src = &o->kind.node.listener;
		CONTROL_LISTENER *l = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CONTROL_LISTENER));
		if (l == NULL)
			return;

		strncpy_s(l->Name, sizeof(l->Name), src->name, _TRUNCATE);
		l->Port = src->port;
		l->QuicPort = src->quic_port;
		strncpy_s(l->Decoy, sizeof(l->Decoy), src->decoy, _TRUNCATE);
		ControlCopyCertificate(l, src);

		if (l->Source == CONTROL_CERT_NONE || l->Port > 65535 || l->QuicPort > 65535 || (l->Source == CONTROL_CERT_ACME && l->NumNames == 0)) {
			HeapFree(GetProcessHeap(), 0, l);
			return;
		}

		st->Listener = l;
		return;
	}
}

// Free the Listener of a state, once its owner took it
void ControlFreeListener(CONTROL_STATE *st) {
	if (st->Listener != NULL)
		HeapFree(GetProcessHeap(), 0, st->Listener);
	st->Listener = NULL;
}
