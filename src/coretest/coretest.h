// coretest.h
// Shared helpers of the coretest named tests (coretest.c)

#ifndef CORETEST_H
#define CORETEST_H

#include "Core/Crypto.h"
#include "Core/Peer.h"

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
void punch_test();
void frontdoor_test();

// The processes of the front door test (frontdoor.c): coretest frontdoor-child node ... or owner ..., which the test
// starts itself; main runs them before anything else
#define CORETEST_FRONTDOOR_CHILD "frontdoor-child"
int frontdoor_child(int argc, char *argv[]);

// The NAT simulator (natsim.c): an in-process datagram network of hosts, each on the public side or behind a
// simulated NAT, that carries the datagrams of the peer layer in place of UDP sockets
typedef struct NATSIM NATSIM;
typedef struct NATSIM_NAT NATSIM_NAT;
typedef struct NATSIM_HOST NATSIM_HOST;

#define NATSIM_MAP_ENDPOINT_INDEPENDENT      1 // One public port for every destination (RFC 4787 section 4.1)
#define NATSIM_MAP_ADDRESS_PORT_DEPENDENT    2 // One public port per destination address and port: a symmetric NAT
#define NATSIM_FILTER_ENDPOINT_INDEPENDENT   1 // In from anywhere to a mapping (RFC 4787 section 5)
#define NATSIM_FILTER_ADDRESS_PORT_DEPENDENT 2 // In only from an address and port that the mapping sent to

// How a NAT picks the public port of a new mapping, which the port prediction of CORE-S5-4 (#266) learns
#define NATSIM_ALLOC_SEQUENTIAL 1 // The next port after the last, so a peer can predict it
#define NATSIM_ALLOC_PRESERVING 2 // The private source port, where it is free, else sequential
#define NATSIM_ALLOC_RANDOM     3 // A port a seeded generator picks, which no peer can predict

NATSIM *NatSimNew();
void NatSimFree(NATSIM *s);
NATSIM_NAT *NatSimAddNat(NATSIM *s, UCHAR b0, UCHAR b1, UCHAR b2, UCHAR b3, UINT mapping, UINT filtering);
void NatSimSetAllocation(NATSIM_NAT *n, UINT allocation, UINT32 seed);
NATSIM_HOST *NatSimAddHost(NATSIM *s, NATSIM_NAT *nat, const PEER_ADDR *addr);
void NatSimAttach(NATSIM_HOST *h, PEER_AGENT *a);
bool NatSimSend(void *param, const PEER_ADDR *dst, const void *data, UINT size);
bool NatSimWaitIdle(NATSIM *s, UINT timeout);
UINT NatSimFiltered(NATSIM_NAT *n);
UINT NatSimUnroutable(NATSIM *s);
bool NatSimMapped(NATSIM_NAT *n, const PEER_ADDR *inside, PEER_ADDR *pub);

// The simulated home gateway of the ICE tests (homegw.c): a UPnP Internet Gateway Device that libplum finds with
// SSDP, and the port forwarding of the mapping it grants, from its WAN side on the IPv4 loopback to the home
// network on the IPv6 loopback
typedef struct HOMEGW HOMEGW;

HOMEGW *HomeGwNew();
void HomeGwFree(HOMEGW *g);
bool HomeGwMapped(HOMEGW *g, USHORT *external, USHORT *internal);
void HomeGwSetLink(HOMEGW *g, bool up);
UINT HomeGwForwarded(HOMEGW *g);
UINT HomeGwSearches(HOMEGW *g);

// The static key of the X25519 scalar first, first + 1, ..., first + 31: the fixed keys of the peer tests, the same
// as fixedKey of the controller's tests (controller/internal/controller)
void coretest_fixed_key(PEER_KEY *k, UCHAR first);

// The OpenSSL 3 PKCS #12 file of pfx_test and schannel_test (cert.c)
extern const UCHAR coretest_pfx[];
extern const UINT coretest_pfx_size;
#define CORETEST_PFX_PASSWORD   L"ranz-test"
#define CORETEST_PFX_THUMBPRINT "5A68384C647FA7B2B48FF75E2DF558A0D27C6D4F"

#endif // CORETEST_H
