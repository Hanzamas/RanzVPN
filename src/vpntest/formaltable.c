// formaltable.c
// Named test of vpntest ("formaltable" command, AUD-5 #389)
//
// The table from the formal model of the handshake to the code (tests/formal/model-to-code.tsv, docs/formal-model.md)
// names the functions of the code that stand for each message and field of the models. This file refers to every C
// function of the table that is not static, so a function that the code loses or renames, or that leaves a module
// vpntest links, is an error of this program and not a row of the table that nobody read again: the change that does it
// has to change the table with it. .github/scripts/formal.py check keeps the list below equal to the public C functions
// of the table, in both directions. A static function cannot be referred to from here; that check finds it in its file.
//
// The test also pins what the models take from the code and the ADRs do not say: the protocol name of the suite that
// every caller selects, the layout of the prologue of a session (the label, the binding type and the binding), the
// labels of the two exporters, and that the TLS transport negotiates TLS 1.2 by default (D6 of the page). A change that
// makes one of them different makes this test fail, which is the reminder that the model and its expected results
// (tests/formal/expected.tsv) are to change too.
// Prints "FORMALTABLE TEST OK" only when every check passes.

#include "testlist.h"

#include "Cedar/Cedar.h"
#include "Cedar/Connection.h"
#include "Cedar/Node.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"
#include "Core/Crypto.h"
#include "Core/Noise.h"
#include "Core/Peer.h"
#include "Core/Transport.h"

#include <string.h>

typedef void (*FORMAL_FUNCTION)(void);

// A function of the table and where it is in this program
typedef struct FORMAL_ENTRY
{
	char *Name;
	FORMAL_FUNCTION Address;
} FORMAL_ENTRY;

#define	FORMAL(f)	{#f, (FORMAL_FUNCTION)(f)}

// The C functions of tests/formal/model-to-code.tsv that are not static
static FORMAL_ENTRY formal_functions[] =
{
	FORMAL(CryptoCertEndPoint),
	FORMAL(CryptoCertThumbprint),
	FORMAL(CryptoIdentityDh),
	FORMAL(CryptoIdentityPublicKey),
	FORMAL(CryptoX25519PublicKey),
	FORMAL(NodeAcceptSession),
	FORMAL(NodeLogin),
	FORMAL(NodeLoginPinned),
	FORMAL(NodeOverlayInput),
	FORMAL(NoiseCipherDecrypt),
	FORMAL(NoiseCipherEncrypt),
	FORMAL(NoiseHandshakeInit),
	FORMAL(NoiseHandshakeRead),
	FORMAL(NoiseHandshakeSplit),
	FORMAL(NoiseHandshakeWrite),
	FORMAL(NoiseLoginEncode),
	FORMAL(NoiseLoginParse),
	FORMAL(NoisePrologue),
	FORMAL(NoiseSessionAccept),
	FORMAL(NoiseSessionConnect),
	FORMAL(NoiseSessionFinish),
	FORMAL(NoiseSessionPoll),
	FORMAL(NoiseSessionReceive),
	FORMAL(NoiseSessionSend),
	FORMAL(NoiseSuiteName),
	FORMAL(NoiseTunnelId),
	FORMAL(NoiseTunnelInit),
	FORMAL(NoiseTunnelJoin),
	FORMAL(PeerEnvelopeOpen),
	FORMAL(PeerEnvelopeSeal),
	FORMAL(PeerInput),
	FORMAL(PeerOpenSignal),
	FORMAL(PeerSealSignal),
	FORMAL(PeerSend),
	FORMAL(PeerSignalEncode),
	FORMAL(TransportBinding),
	FORMAL(TransportNoiseAccept),
	FORMAL(TransportNoiseConnect),
	FORMAL(TransportNoiseSend),
	FORMAL(TransportTlsDefaultConfig),
	FORMAL(TransportTlsSetGroups),
	FORMAL(TunnelJoin),
	FORMAL(TunnelStart),
};

static UINT formaltable_test_failed = 0;

// Record one check: print [PASS] or [FAIL] and the check
static void FormalTableCheck(bool ok, char *what)
{
	Print("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
	if (ok == false)
	{
		formaltable_test_failed++;
	}
}

RANZ_TEST("formaltable", formaltable_test, "Formal model: the functions that the table from the model to the code names are in the program, and the facts of the code that the models take (suite name, prologue, exporter labels, TLS versions) are as the models have them.");
void formaltable_test(UINT num, char **arg)
{
	UCHAR binding[NOISE_EXPORTER_SIZE];
	UCHAR prologue[NOISE_MAX_PROLOGUE];
	TRANSPORT_TLS_CONFIG tls;
	UINT label = sizeof(NOISE_PROLOGUE_LABEL) - 1;
	UINT size, i;
	UINT missing = 0;

	formaltable_test_failed = 0;

	for (i = 0; i < sizeof(formal_functions) / sizeof(formal_functions[0]); i++)
	{
		if (formal_functions[i].Address == NULL)
		{
			Print("  the function %s has no address\n", formal_functions[i].Name);
			missing++;
		}
	}
	FormalTableCheck(missing == 0, "every public C function of the table is in the program");

	FormalTableCheck(strcmp(NoiseSuiteName(NOISE_SUITE_IK), "Noise_IK_25519_AESGCM_SHA256") == 0,
		"the suite that every caller selects is Noise_IK_25519_AESGCM_SHA256, the protocol name that the models hash into h");

	// The prologue of a session: the label, the binding type, the binding
	for (i = 0; i < sizeof(binding); i++)
	{
		binding[i] = (UCHAR)(0xA0 + i);
	}
	size = NoisePrologue(prologue, sizeof(prologue), NOISE_BINDING_EXPORTER, binding, sizeof(binding));
	FormalTableCheck(size == label + 1 + sizeof(binding) && memcmp(prologue, NOISE_PROLOGUE_LABEL, label) == 0 &&
		prologue[label] == NOISE_BINDING_EXPORTER && memcmp(prologue + label + 1, binding, sizeof(binding)) == 0,
		"the prologue of a session is the label, the binding type and the binding, as the models have it");
	FormalTableCheck(NoisePrologue(prologue, sizeof(prologue), NOISE_BINDING_NONE, binding, sizeof(binding)) == 0 &&
		NoisePrologue(prologue, sizeof(prologue), NOISE_BINDING_EXPORTER, binding, sizeof(binding) - 1) == 0,
		"a binding of the wrong size for its type is no prologue");

	FormalTableCheck(strcmp(NOISE_EXPORTER_LABEL, "EXPORTER-ranz-session-noise") == 0 &&
		strcmp(CONTROL_EXPORTER_LABEL, "EXPORTER-ranz-control-noise") == 0 && strcmp(NOISE_EXPORTER_LABEL, CONTROL_EXPORTER_LABEL) != 0,
		"the exporter of a session and the exporter of the control stream have two labels, which the controller computes the same");

	// D6: the TLS transport negotiates TLS 1.2 as well as TLS 1.3 until the default changes
	TransportTlsDefaultConfig(&tls, "0000000000000000000000000000000000000000", false);
	FormalTableCheck(tls.Versions == (TRANSPORT_TLS_12 | TRANSPORT_TLS_13),
		"the TLS transport negotiates TLS 1.2 and TLS 1.3 by default (D6 of docs/formal-model.md: change the page when this changes)");

	if (formaltable_test_failed == 0)
	{
		Print("FORMALTABLE TEST OK\n");
	}
	else
	{
		Print("FORMALTABLE TEST FAILED (%u checks failed)\n", formaltable_test_failed);
	}
}
