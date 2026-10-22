// envelope.c
// Known-answer and tamper tests of the envelopes of the peer layer (src/Core/PeerSignal.c, CORE-S5-2 #78): binds
// and signals sealed by one node's static key to another's with Noise_K_25519_AESGCM_SHA256. The known answers
// were computed by an implementation of the Noise framework independent of the module (Python with the
// cryptography package); the controller's test of the same envelopes (controller/internal/control, flynn/noise)
// holds them too, so the C node and the Go controller seal and open the same bytes. A signal of a node with ICE on
// also carries the credentials of its ICE session (CORE-S5-3, #79).

#include "coretest.h"

#include <string.h>

// The fixed keys: the sender is branch-1 of the controller's tests (scalar 1, 2, ..., 32), the receiver branch-2
// (33, 34, ...), the relay the scalar 129, 130, ...; the ephemeral key of the known answers is the scalar 97, 98, ...
static const char sender_pub[] = "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c";
static const char receiver_pub[] = "5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b";
static const char ephemeral_pub[] = "244fe3b963e899dd295baffce248d3530f3a9a7479ba063002680ebfe7adad49";
static const char relay_pub[] = "883186b800b41d5cf0429695da9b3cc4f328ebcd184a6e482fa578c103f06c77";

// An offer of sequence 0x0102030405060708 that names the relay at 192.0.2.10:7000, with a host candidate
// 10.0.0.2:5000 and a server reflexive candidate 198.51.100.7:40001; then its envelope from branch-1 to branch-2
static const char signal_payload[] = "01010102030405060708883186b800b41d5cf0429695da9b3cc4f328ebcd184a6e482fa578c103f06c7700000000000000000000ffffc000020a1b58020100000000000000000000ffff0a00000213880200000000000000000000ffffc63364079c41";
static const char signal_envelope[] = "0407a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c244fe3b963e899dd295baffce248d3530f3a9a7479ba063002680ebfe7adad49529bf345ba812669a43343fe55f5bdebfa1fd20846a6b5d96b0efe2ebaabc1b2f8e61fd05853d2e30edaa0107cab08f15d22975a1970ba0956de502d94c629a92543f49c5206a51e61b47e1c6263a7345cae0aa14d13bfd2d6f1f2049ea5a1ef584e6d2014829b4ea20ba9afc1f865290e2a82";

// A bind of sequence 0x1122334455667788 from branch-1 to the relay, and its envelope
static const char bind_payload[] = "011122334455667788";
static const char bind_envelope[] = "0207a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c244fe3b963e899dd295baffce248d3530f3a9a7479ba063002680ebfe7adad498b4b5ccb906d23b5b95c9a9b3beeb6779a7126787517d53658";

void coretest_fixed_key(PEER_KEY *k, UCHAR first) {
	UCHAR priv[PEER_KEY_SIZE];

	for (UINT i = 0; i < PEER_KEY_SIZE; i++)
		priv[i] = (UCHAR)(first + i);

	if (PeerKeyFromScalar(k, priv) == false)
		ZeroMemory(k, sizeof(PEER_KEY));

	SecureZeroMemory(priv, sizeof(priv));
}

// The scalar of a fixed key
static void envelope_scalar(UCHAR *priv, UCHAR first) {
	for (UINT i = 0; i < PEER_KEY_SIZE; i++)
		priv[i] = (UCHAR)(first + i);
}

// The signal of the known answer
static void envelope_signal(PEER_SIGNAL *s, const UCHAR *relay) {
	ZeroMemory(s, sizeof(PEER_SIGNAL));
	s->Type = PEER_SIGNAL_OFFER;
	s->Sequence = 0x0102030405060708ULL;
	CopyMemory(s->RelayKey, relay, PEER_KEY_SIZE);
	PeerAddrSetV4(&s->Relay, 192, 0, 2, 10, 7000);
	s->NumCandidates = 2;
	s->Candidates[0].Type = PEER_CANDIDATE_HOST;
	PeerAddrSetV4(&s->Candidates[0].Addr, 10, 0, 0, 2, 5000);
	s->Candidates[1].Type = PEER_CANDIDATE_SRFLX;
	PeerAddrSetV4(&s->Candidates[1].Addr, 198, 51, 100, 7, 40001);
}

// Whether two signals hold the same type, sequence, relay and candidates
static bool envelope_same_signal(const PEER_SIGNAL *a, const PEER_SIGNAL *b) {
	if (a->Type != b->Type || a->Sequence != b->Sequence || memcmp(a->RelayKey, b->RelayKey, PEER_KEY_SIZE) != 0 || PeerAddrEqual(&a->Relay, &b->Relay) == false || a->NumCandidates != b->NumCandidates)
		return false;

	for (UINT i = 0; i < a->NumCandidates; i++)
		if (a->Candidates[i].Type != b->Candidates[i].Type || PeerAddrEqual(&a->Candidates[i].Addr, &b->Candidates[i].Addr) == false)
			return false;

	return true;
}

// Opens of env with each one of its bits flipped: the number that the receiver took
static UINT envelope_flips(PEER_KEY *receiver, UCHAR *env, UINT size) {
	UCHAR sender[PEER_KEY_SIZE];
	UCHAR out[PEER_MAX_ENVELOPE];
	UINT len = 0;
	UINT taken = 0;

	for (UINT i = 0; i < size; i++) {
		for (UINT bit = 0; bit < 8; bit++) {
			env[i] ^= (UCHAR)(1 << bit);
			if (PeerEnvelopeOpen(receiver, env, size, sender, out, sizeof(out), &len))
				taken++;
			env[i] ^= (UCHAR)(1 << bit);
		}
	}

	return taken;
}

// The known answers in the key storage provider: the sender's and the receiver's scalars stored as identity keys
static void envelope_identity(const UCHAR *payload, UINT payload_size) {
	UCHAR priv[PEER_KEY_SIZE];
	UCHAR ephemeral[PEER_KEY_SIZE];
	UCHAR env[PEER_MAX_ENVELOPE];
	UCHAR out[PEER_MAX_ENVELOPE];
	UCHAR sender[PEER_KEY_SIZE];
	CRYPTO_IDENTITY id_sender, id_receiver;
	wchar_t name_sender[64], name_receiver[64];
	PEER_KEY ksp_sender, ksp_receiver, receiver;
	UINT scope = coretest_scope();
	UINT len = 0;

	coretest_info("identity keys: %s", coretest_scope_name());
	_snwprintf_s(name_sender, sizeof(name_sender) / sizeof(wchar_t), _TRUNCATE, L"Ranz-coretest-envelope-sender-%lu", GetCurrentProcessId());
	_snwprintf_s(name_receiver, sizeof(name_receiver) / sizeof(wchar_t), _TRUNCATE, L"Ranz-coretest-envelope-receiver-%lu", GetCurrentProcessId());

	envelope_scalar(ephemeral, 97);
	coretest_fixed_key(&receiver, 33);

	envelope_scalar(priv, 1);
	bool have_sender = coretest_check(CryptoIdentityImport(&id_sender, name_sender, priv, scope), "The sender's scalar stored as an identity key");
	envelope_scalar(priv, 33);
	bool have_receiver = coretest_check(CryptoIdentityImport(&id_receiver, name_receiver, priv, scope), "The receiver's scalar stored as an identity key");
	SecureZeroMemory(priv, sizeof(priv));

	if (have_sender) {
		ZeroMemory(&ksp_sender, sizeof(ksp_sender));
		ksp_sender.Identity = &id_sender;
		CryptoIdentityPublicKey(&id_sender, ksp_sender.Public);

		UINT size = PeerEnvelopeSeal(&ksp_sender, receiver.Public, PEER_MSG_SIGNAL, ephemeral, payload, payload_size, env, sizeof(env));
		coretest_check(size == 180, "The sender's identity key seals the signal");
		coretest_check_hex(env, size, signal_envelope, "Sealed by the key in the provider, the envelope is the known answer");

		if (have_receiver && size != 0) {
			ZeroMemory(&ksp_receiver, sizeof(ksp_receiver));
			ksp_receiver.Identity = &id_receiver;
			CryptoIdentityPublicKey(&id_receiver, ksp_receiver.Public);

			bool ok = PeerEnvelopeOpen(&ksp_receiver, env, size, sender, out, sizeof(out), &len);
			coretest_check(ok && len == payload_size && memcmp(out, payload, len) == 0 && memcmp(sender, ksp_sender.Public, PEER_KEY_SIZE) == 0, "The receiver's identity key opens it");

			env[size - 1] ^= 1;
			coretest_check(PeerEnvelopeOpen(&ksp_receiver, env, size, sender, out, sizeof(out), &len) == false, "... and refuses it with its tag altered");
		}
	}

	if (have_sender)
		coretest_check(CryptoIdentityDelete(&id_sender), "The sender's identity key deleted");
	if (have_receiver)
		coretest_check(CryptoIdentityDelete(&id_receiver), "The receiver's identity key deleted");

	SecureZeroMemory(ephemeral, sizeof(ephemeral));
	PeerKeyClose(&receiver);
}

void envelope_test() {
	PEER_KEY sender, receiver, relay, forged;
	PEER_SIGNAL s, got;
	UCHAR ephemeral[PEER_KEY_SIZE];
	UCHAR payload[PEER_MAX_ENVELOPE];
	UCHAR env[PEER_MAX_ENVELOPE];
	UCHAR env2[PEER_MAX_ENVELOPE];
	UCHAR out[PEER_MAX_ENVELOPE];
	UCHAR from[PEER_KEY_SIZE];
	UCHAR eph_pub[PEER_KEY_SIZE];
	UINT len = 0;

	coretest_fixed_key(&sender, 1);
	coretest_fixed_key(&receiver, 33);
	coretest_fixed_key(&relay, 129);
	envelope_scalar(ephemeral, 97);

	coretest_check_hex(sender.Public, PEER_KEY_SIZE, sender_pub, "The sender is branch-1 of the controller's tests");
	coretest_check_hex(receiver.Public, PEER_KEY_SIZE, receiver_pub, "The receiver is branch-2 of the controller's tests");
	coretest_check_hex(relay.Public, PEER_KEY_SIZE, relay_pub, "The relay key");
	coretest_check(CryptoX25519PublicKey(eph_pub, ephemeral), "The ephemeral key of the known answers");
	coretest_check_hex(eph_pub, PEER_KEY_SIZE, ephemeral_pub, "... its public key");

	// The payload of a signal
	envelope_signal(&s, relay.Public);
	UINT payload_size = PeerSignalEncode(&s, payload, sizeof(payload));
	coretest_check(payload_size == 99, "A signal with two candidates is 99 bytes");
	coretest_check_hex(payload, payload_size, signal_payload, "The signal encodes to the known payload");
	coretest_check(PeerSignalDecode(payload, payload_size, &got) && envelope_same_signal(&got, &s), "... and decodes back to the same signal");

	// The envelope: kind, sender key, ephemeral key, ciphertext, tag
	UINT size = PeerEnvelopeSeal(&sender, receiver.Public, PEER_MSG_SIGNAL, ephemeral, payload, payload_size, env, sizeof(env));
	coretest_check(size == PEER_ENVELOPE_HEADER + payload_size + PEER_ENVELOPE_TAG, "The envelope of the signal is its kind, the two keys, 99 bytes of ciphertext and the tag");
	coretest_check_hex(env, size, signal_envelope, "Noise_K_25519_AESGCM_SHA256 of the signal reproduces the known answer");

	bool ok = PeerEnvelopeOpen(&receiver, env, size, from, out, sizeof(out), &len);
	coretest_check(ok && len == payload_size && memcmp(out, payload, len) == 0 && memcmp(from, sender.Public, PEER_KEY_SIZE) == 0, "The receiver opens it: the payload, and the sender's key");
	coretest_check(PeerSignalDecode(out, len, &got) && envelope_same_signal(&got, &s), "The payload it opened is the signal");

	// Forged, altered, redirected
	coretest_check(envelope_flips(&receiver, env, size) == 0, "Every one of the 1440 envelopes with one bit flipped (kind, sender key, ephemeral key, ciphertext, tag) is refused");
	coretest_check(PeerEnvelopeOpen(&relay, env, size, from, out, sizeof(out), &len) == false, "Another node than the receiver cannot open it: a signal cannot be redirected");
	coretest_check(PeerEnvelopeOpen(&receiver, env, size - 1, from, out, sizeof(out), &len) == false && PeerEnvelopeOpen(&receiver, env, PEER_ENVELOPE_HEADER + PEER_ENVELOPE_TAG - 1, from, out, sizeof(out), &len) == false, "A truncated envelope is refused");
	coretest_check(PeerEnvelopeOpen(&receiver, env, size, from, out, payload_size - 1, &len) == false, "An envelope whose payload does not fit the buffer is refused");

	forged = relay;
	CopyMemory(forged.Public, sender.Public, PEER_KEY_SIZE);
	UINT size2 = PeerEnvelopeSeal(&forged, receiver.Public, PEER_MSG_SIGNAL, NULL, payload, payload_size, env2, sizeof(env2));
	coretest_check(size2 == size && memcmp(env2 + 1, sender.Public, PEER_KEY_SIZE) == 0 && PeerEnvelopeOpen(&receiver, env2, size2, from, out, sizeof(out), &len) == false, "An envelope that names the sender's key, sealed without its private key, is refused");

	env[0] = PEER_MSG_BIND;
	coretest_check(PeerEnvelopeOpen(&receiver, env, size, from, out, sizeof(out), &len) == false, "A signal does not open as a bind: the kind is in the prologue");
	env[0] = PEER_MSG_DATA;
	coretest_check(PeerEnvelopeOpen(&receiver, env, size, from, out, sizeof(out), &len) == false, "A data datagram is no envelope");
	env[0] = PEER_MSG_SIGNAL;

	// A new ephemeral key for every envelope
	UINT size3 = PeerEnvelopeSeal(&sender, receiver.Public, PEER_MSG_SIGNAL, NULL, payload, payload_size, env2, sizeof(env2));
	coretest_check(size3 == size && memcmp(env2 + 1 + PEER_KEY_SIZE, env + 1 + PEER_KEY_SIZE, PEER_KEY_SIZE) != 0 && PeerEnvelopeOpen(&receiver, env2, size3, from, out, sizeof(out), &len), "Without a fixed ephemeral key every envelope has a new one, and opens");

	// A bind to the relay
	UCHAR bind[PEER_KEY_SIZE];
	UINT bind_size = coretest_unhex(bind, sizeof(bind), bind_payload);
	size = PeerEnvelopeSeal(&sender, relay.Public, PEER_MSG_BIND, ephemeral, bind, bind_size, env, sizeof(env));
	coretest_check(size == 90, "A bind envelope is 90 bytes");
	coretest_check_hex(env, size, bind_envelope, "The bind reproduces its known answer");
	ok = PeerEnvelopeOpen(&relay, env, size, from, out, sizeof(out), &len);
	coretest_check(ok && len == bind_size && memcmp(out, bind, bind_size) == 0 && memcmp(from, sender.Public, PEER_KEY_SIZE) == 0, "The relay opens the bind");
	coretest_check(envelope_flips(&relay, env, size) == 0, "Every one of the 720 binds with one bit flipped is refused");

	// Signals that do not decode
	s.NumCandidates = PEER_MAX_CANDIDATES + 1;
	coretest_check(PeerSignalEncode(&s, payload, sizeof(payload)) == 0, "A signal with too many candidates is not encoded");
	envelope_signal(&s, relay.Public);
	payload_size = PeerSignalEncode(&s, payload, sizeof(payload));
	coretest_check(PeerSignalDecode(payload, payload_size - 1, &got) == false && PeerSignalDecode(payload, payload_size + 1, &got) == false, "A signal payload of the wrong size does not decode");
	payload[0] = 2;
	coretest_check(PeerSignalDecode(payload, payload_size, &got) == false, "A signal payload of another version does not decode");
	payload[0] = 1;
	payload[1] = 3;
	coretest_check(PeerSignalDecode(payload, payload_size, &got) == false, "A signal payload of an unknown type does not decode");
	payload[1] = 1;
	coretest_check(PeerSignalDecode(payload, payload_size, &got), "The signal decodes again once restored");
	// The relay port, bytes 58 and 59
	payload[58] = 0;
	payload[59] = 0;
	coretest_check(PeerSignalDecode(payload, payload_size, &got) == false, "A signal that names a relay without its port does not decode");

	// The credentials of an ICE session (CORE-S5-3, #79): after the candidates, the length and the characters of
	// the username fragment, then those of the password
	envelope_signal(&s, relay.Public);
	s.Candidates[1].Type = PEER_CANDIDATE_MAPPED;
	strcpy_s(s.IceUfrag, sizeof(s.IceUfrag), "Ab1+");
	strcpy_s(s.IcePwd, sizeof(s.IcePwd), "abcdefghijklmnopqrstu/");
	payload_size = PeerSignalEncode(&s, payload, sizeof(payload));
	coretest_check(payload_size == 99 + 2 + 4 + 22 && payload[99] == 4 && memcmp(payload + 100, "Ab1+", 4) == 0 && payload[104] == 22, "A signal with the credentials of an ICE session carries them after its candidates, each with its length");
	coretest_check(PeerSignalDecode(payload, payload_size, &got) && envelope_same_signal(&got, &s) && strcmp(got.IceUfrag, s.IceUfrag) == 0 && strcmp(got.IcePwd, s.IcePwd) == 0, "... and decodes back to the same signal and credentials, with the public port of a home gateway as a candidate");
	coretest_check(PeerSignalDecode(payload, payload_size - 1, &got) == false && PeerSignalDecode(payload, payload_size + 1, &got) == false, "... but not with a byte too few or too many");
	payload[100] = '-';
	coretest_check(PeerSignalDecode(payload, payload_size, &got) == false, "A username fragment with a character that is no ice-char does not decode");
	payload[100] = 'A';
	payload[99] = 3;
	coretest_check(PeerSignalDecode(payload, payload_size, &got) == false, "Credentials whose lengths do not add up to the rest of the payload do not decode");
	s.IcePwd[21] = 0;
	coretest_check(PeerSignalEncode(&s, payload, sizeof(payload)) == 0, "A password shorter than 22 characters is not encoded");

	envelope_signal(&s, relay.Public);
	payload_size = PeerSignalEncode(&s, payload, sizeof(payload));
	envelope_identity(payload, payload_size);

	SecureZeroMemory(ephemeral, sizeof(ephemeral));
	PeerKeyClose(&sender);
	PeerKeyClose(&receiver);
	PeerKeyClose(&relay);
	PeerKeyClose(&forged);
}
