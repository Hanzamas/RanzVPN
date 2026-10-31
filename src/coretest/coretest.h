// coretest.h
// Shared helpers of the coretest named tests (coretest.c)

#ifndef CORETEST_H
#define CORETEST_H

#include "Core/Crypto.h"
#include "Core/Peer.h"

#include "natsim.h"

#include <stdio.h>

// Print one check as [PASS] or [FAIL] and count the failures of the running test
bool coretest_check(bool passed, const char *what);

// Print an informational line, which never fails a test
void coretest_info(const char *format, ...);

// Compare size bytes with a hex string; on a mismatch print both
bool coretest_check_hex(const void *got, UINT size, const char *expect_hex, const char *what);

// Hex string to bytes: the number of bytes written, at most size
UINT coretest_unhex(UCHAR *dst, UINT size, const char *hex);

// Whether the process runs elevated: the identity, certificate and store tests then use the
// machine key set and the LocalMachine store, as the service does; else the current user's
bool coretest_elevated();

// The scope flags and its name for the tests above
UINT coretest_scope();
const char *coretest_scope_name();

// Named tests: kat.c, hybrid.c, cert.c, schannel.c; noise.c, session.c, interop.c; envelope.c, relay.c; ice.c
void rand_test();
void sha256_test();
void hmac_test();
void hkdf_test();
void aesgcm_test();
void x25519_test();
void identity_test();
void mlkem_test();
void cryptorefusal_test();
void selfsign_test();
void pfx_test();
void certstore_test();
void schannel_test();
void noise_test();
void noisehfs_test();
void noisesession_test();
void noisetunnel_test();
void noiseinterop_test();
void envelope_test();
void relay_test();
void relaypolicy_test();
void iceupgrade_test();
void icesymmetric_test();
void iceanswer_test();
void iceinput_test();
void punch_test();
void peersession_test();
void frontdoor_test();
// The msquic of the exporter of a QUIC connection (quicexporter.c; CORE-H5-R, #443)
void quicexporter_test();
// The fallback after a handshake, on loopback transports (fallback.c; CORE-H5-R, #443)
void fallback_test();

// The processes of the front door test (frontdoor.c): coretest frontdoor-child node ... or owner ..., which the test
// starts itself; main runs them before anything else
#define CORETEST_FRONTDOOR_CHILD "frontdoor-child"
int frontdoor_child(int argc, char *argv[]);

// The static key of the X25519 scalar first, first + 1, ..., first + 31: the fixed keys of the peer tests, the same
// as fixedKey of the controller's tests (controller/internal/controller)
void coretest_fixed_key(PEER_KEY *k, UCHAR first);

// The OpenSSL 3 PKCS #12 file of pfx_test and schannel_test (cert.c)
extern const UCHAR coretest_pfx[];
extern const UINT coretest_pfx_size;
#define CORETEST_PFX_PASSWORD   L"ranz-test"
#define CORETEST_PFX_THUMBPRINT "5A68384C647FA7B2B48FF75E2DF558A0D27C6D4F"

#endif // CORETEST_H
