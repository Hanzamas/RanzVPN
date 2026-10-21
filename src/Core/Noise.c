// Noise.c
// The Noise handshake of the session module: the cipher state, the symmetric state and the
// handshake state of the Noise Protocol Framework (revision 34, sections 5.1 to 5.3) for the IK
// pattern, and the e1 and ekem1 tokens of the hfs extension (Noise HFS, revision 1) for IKhfs.
// DH is X25519, the cipher AES-GCM with the nonce 0^32 || n as a 64-bit big-endian number, the
// hash SHA-256 and HKDF the one of RFC 5869 (equal to the HKDF of Noise section 4.3), all on CNG
// through the crypto module. The known-answer test is the Noise_IK_25519_AESGCM_SHA256 vector of
// the cacophony test vectors (coretest noise); the interop check runs it against flynn/noise
// (coretest noiseinterop).

#include "Core/Noise.h"

#include <string.h>

// The protocol names (Noise section 8); the hfs one names the KEM after the DH (Noise HFS section 6)
static const char noise_name_ik[] = "Noise_IK_25519_AESGCM_SHA256";
static const char noise_name_ikhfs[] = "Noise_IKhfs_25519+MLKEM768_AESGCM_SHA256";

// The nonce that Encrypt and Decrypt never use: REKEY encrypts with it (Noise section 11.3)
#define NOISE_MAX_NONCE 0xFFFFFFFFFFFFFFFFULL

const char *NoiseSuiteName(UINT suite) {
	switch (suite) {
	case NOISE_SUITE_IK:
		return noise_name_ik;
	case NOISE_SUITE_IKHFS:
		return noise_name_ikhfs;
	}

	return NULL;
}

bool NoiseSuiteAvailable(UINT suite) {
	if (CryptoInit() == false)
		return false;

	return suite == NOISE_SUITE_IK || (suite == NOISE_SUITE_IKHFS && CryptoMlKemAvailable());
}

// The 12-byte AES-GCM nonce of message n: 32 bits of zeros, then n big-endian (Noise section 12.4)
static void NoiseNonce(UCHAR *nonce, UINT64 n) {
	ZeroMemory(nonce, 4);
	for (UINT i = 0; i < 8; i++)
		nonce[4 + i] = (UCHAR)(n >> (56 - 8 * i));
}

//
// The cipher state
//

bool NoiseCipherInit(NOISE_CIPHER *c, const UCHAR *key) {
	if (c == NULL)
		return false;

	c->Aead.Key = NULL;
	c->Nonce = 0;
	if (key == NULL)
		return false;

	return CryptoAeadInit(&c->Aead, key, NOISE_KEY_SIZE);
}

void NoiseCipherFree(NOISE_CIPHER *c) {
	if (c == NULL)
		return;

	CryptoAeadFree(&c->Aead);
	c->Nonce = 0;
}

bool NoiseCipherEncrypt(NOISE_CIPHER *c, const void *ad, UINT ad_size, const void *src, UINT size, UCHAR *dst) {
	UCHAR nonce[CRYPTO_AES_GCM_NONCE_SIZE];

	if (c == NULL || c->Aead.Key == NULL || dst == NULL || (src == NULL && size != 0) || size > NOISE_MAX_MESSAGE - NOISE_TAG_SIZE)
		return false;

	// n = 2^64 - 1 is reserved for REKEY: the cipher state is used up before it
	if (c->Nonce == NOISE_MAX_NONCE)
		return false;

	NoiseNonce(nonce, c->Nonce);
	if (CryptoAeadSeal(&c->Aead, nonce, ad, ad_size, src != NULL ? src : dst, size, dst, dst + size) == false)
		return false;

	c->Nonce++;
	return true;
}

bool NoiseCipherDecrypt(NOISE_CIPHER *c, const void *ad, UINT ad_size, const UCHAR *src, UINT size, void *dst) {
	UCHAR nonce[CRYPTO_AES_GCM_NONCE_SIZE];
	UCHAR empty[1];

	if (c == NULL || c->Aead.Key == NULL || src == NULL || size < NOISE_TAG_SIZE || size > NOISE_MAX_MESSAGE ||
	    (dst == NULL && size != NOISE_TAG_SIZE) || c->Nonce == NOISE_MAX_NONCE)
		return false;

	// An empty plaintext still goes to a buffer: BCryptDecrypt without an output buffer only
	// reports the size, and would not check the tag
	NoiseNonce(nonce, c->Nonce);
	if (CryptoAeadOpen(&c->Aead, nonce, ad, ad_size, src, size - NOISE_TAG_SIZE, src + size - NOISE_TAG_SIZE, dst != NULL ? dst : empty) == false)
		return false;

	c->Nonce++;
	return true;
}

// REKEY(k): the first 32 bytes of ENCRYPT(k, maxnonce, zerolen, zeros), the 32 zero bytes
// encrypted under the reserved nonce without their tag; the nonce stays (Noise section 11.3)
bool NoiseCipherRekey(NOISE_CIPHER *c) {
	UCHAR nonce[CRYPTO_AES_GCM_NONCE_SIZE];
	UCHAR zeros[NOISE_KEY_SIZE];
	UCHAR key[NOISE_KEY_SIZE];
	UCHAR tag[NOISE_TAG_SIZE];
	CRYPTO_AEAD next;
	bool ok = false;

	if (c == NULL || c->Aead.Key == NULL)
		return false;

	ZeroMemory(zeros, sizeof(zeros));
	NoiseNonce(nonce, NOISE_MAX_NONCE);
	if (CryptoAeadSeal(&c->Aead, nonce, NULL, 0, zeros, sizeof(zeros), key, tag) && CryptoAeadInit(&next, key, sizeof(key))) {
		CryptoAeadFree(&c->Aead);
		c->Aead = next;
		ok = true;
	}

	SecureZeroMemory(key, sizeof(key));
	SecureZeroMemory(tag, sizeof(tag));

	return ok;
}

//
// The symmetric state
//

// MixHash(data): h = HASH(h || data)
static bool NoiseMixHash(NOISE_HANDSHAKE *hs, const void *data, UINT size) {
	CRYPTO_SHA256 s;

	if (CryptoSha256Begin(&s) == false)
		return false;

	bool ok = CryptoSha256Update(&s, hs->H, NOISE_KEY_SIZE) && CryptoSha256Update(&s, data, size);

	return CryptoSha256End(&s, ok ? hs->H : NULL) && ok;
}

// MixKey(ikm): ck, temp_k = HKDF(ck, ikm, 2), then k = temp_k with n = 0
static bool NoiseMixKey(NOISE_HANDSHAKE *hs, const UCHAR *ikm, UINT ikm_size) {
	UCHAR out[2 * NOISE_KEY_SIZE];
	bool ok = false;

	if (CryptoHkdf(out, sizeof(out), hs->Ck, NOISE_KEY_SIZE, ikm, ikm_size, NULL, 0)) {
		CopyMemory(hs->Ck, out, NOISE_KEY_SIZE);
		NoiseCipherFree(&hs->Cipher);
		ok = NoiseCipherInit(&hs->Cipher, out + NOISE_KEY_SIZE);
	}

	SecureZeroMemory(out, sizeof(out));
	return ok;
}

// EncryptAndHash(plaintext) into dst: the ciphertext under h as associated data, or the plaintext
// while there is no key yet; then MixHash of what was written. *size receives its size.
static bool NoiseEncryptAndHash(NOISE_HANDSHAKE *hs, const void *src, UINT src_size, UCHAR *dst, UINT max, UINT *size) {
	UINT out = src_size + (hs->Cipher.Aead.Key != NULL ? NOISE_TAG_SIZE : 0);

	if (out > max)
		return false;

	if (hs->Cipher.Aead.Key != NULL) {
		if (NoiseCipherEncrypt(&hs->Cipher, hs->H, NOISE_KEY_SIZE, src, src_size, dst) == false)
			return false;
	} else if (src_size != 0) {
		MoveMemory(dst, src, src_size);
	}

	*size = out;
	return NoiseMixHash(hs, dst, out);
}

// DecryptAndHash(ciphertext) into dst, then MixHash of the ciphertext. *size receives the plaintext size.
static bool NoiseDecryptAndHash(NOISE_HANDSHAKE *hs, const UCHAR *src, UINT src_size, void *dst, UINT max, UINT *size) {
	UINT out = src_size;

	if (hs->Cipher.Aead.Key != NULL) {
		if (src_size < NOISE_TAG_SIZE)
			return false;
		out -= NOISE_TAG_SIZE;
	}
	if (out > max)
		return false;

	if (hs->Cipher.Aead.Key != NULL) {
		if (NoiseCipherDecrypt(&hs->Cipher, hs->H, NOISE_KEY_SIZE, src, src_size, dst) == false)
			return false;
	} else if (out != 0) {
		CopyMemory(dst, src, out);
	}

	*size = out;
	return NoiseMixHash(hs, src, src_size);
}

// DecryptAndHash of a token of a fixed size, such as s, e1 or ekem1
static bool NoiseDecryptToken(NOISE_HANDSHAKE *hs, const UCHAR *src, UINT src_size, UCHAR *dst, UINT dst_size) {
	UINT size = 0;

	return NoiseDecryptAndHash(hs, src, src_size, dst, dst_size, &size) && size == dst_size;
}

// The size of a token of size bytes in a message: with its tag once there is a key
static UINT NoiseTokenSize(const NOISE_HANDSHAKE *hs, UINT size) {
	return size + (hs->Cipher.Aead.Key != NULL ? NOISE_TAG_SIZE : 0);
}

//
// The Diffie-Hellman functions of the handshake
//

// DH(s, pub) with the local static key: in the key storage provider, or the scalar
static bool NoiseDhStatic(NOISE_HANDSHAKE *hs, UCHAR *shared, const UCHAR *pub) {
	if (hs->Identity != NULL)
		return CryptoIdentityDh(hs->Identity, shared, pub);

	return CryptoX25519(shared, hs->StaticKey, pub);
}

// MixKey(DH(...)) of one of the tokens ee, es, se and ss. local_static: the local key of the DH is
// s, not e. A public key of low order gives no secret (CryptoX25519), which fails the handshake.
static bool NoiseMixDh(NOISE_HANDSHAKE *hs, bool local_static, const UCHAR *remote) {
	UCHAR shared[CRYPTO_X25519_SIZE];

	bool ok = (local_static ? NoiseDhStatic(hs, shared, remote) : CryptoX25519(shared, hs->EphemeralKey, remote)) &&
	          NoiseMixKey(hs, shared, sizeof(shared));

	SecureZeroMemory(shared, sizeof(shared));
	return ok;
}

// The e token of a written message: a fresh ephemeral key, unless a test fixed it
static bool NoiseNewEphemeral(NOISE_HANDSHAKE *hs) {
	if (hs->FixedEphemeral)
		return true;

	return CryptoX25519GenerateKey(hs->EphemeralKey, hs->EphemeralPub);
}

//
// The handshake state
//

bool NoiseHandshakeInit(NOISE_HANDSHAKE *hs, UINT suite, bool initiator, const void *prologue, UINT prologue_size,
                        const UCHAR *static_key, CRYPTO_IDENTITY *identity, const UCHAR *remote_static) {
	const char *name = NoiseSuiteName(suite);

	if (hs == NULL)
		return false;

	SecureZeroMemory(hs, sizeof(NOISE_HANDSHAKE));
	hs->Failed = true;
	if (name == NULL || NoiseSuiteAvailable(suite) == false || (prologue == NULL && prologue_size != 0) ||
	    (static_key == NULL) == (identity == NULL) || (initiator && remote_static == NULL))
		return false;

	hs->Suite = suite;
	hs->Initiator = initiator;
	hs->Identity = identity;

	// The local static key and its public half
	if (identity != NULL) {
		if (CryptoIdentityPublicKey(identity, hs->StaticPub) == false)
			return false;
	} else {
		CopyMemory(hs->StaticKey, static_key, NOISE_KEY_SIZE);
		if (CryptoX25519PublicKey(hs->StaticPub, hs->StaticKey) == false) {
			NoiseHandshakeFree(hs);
			return false;
		}
	}

	// InitializeSymmetric(protocol_name): h is the name padded with zeros to HASHLEN, or its hash
	// when longer; ck = h
	UINT name_size = (UINT)strlen(name);
	if (name_size <= NOISE_KEY_SIZE)
		CopyMemory(hs->H, name, name_size);
	else if (CryptoSha256(hs->H, name, name_size) == false) {
		NoiseHandshakeFree(hs);
		return false;
	}
	CopyMemory(hs->Ck, hs->H, NOISE_KEY_SIZE);

	// MixHash(prologue), then the pre-message of IK: <- s, the responder's static key
	if (initiator)
		CopyMemory(hs->RemoteStatic, remote_static, NOISE_KEY_SIZE);
	if (NoiseMixHash(hs, prologue, prologue_size) == false || NoiseMixHash(hs, initiator ? hs->RemoteStatic : hs->StaticPub, NOISE_KEY_SIZE) == false) {
		NoiseHandshakeFree(hs);
		return false;
	}

	hs->Failed = false;
	return true;
}

void NoiseHandshakeSetEphemeral(NOISE_HANDSHAKE *hs, const UCHAR *priv) {
	if (hs == NULL || priv == NULL)
		return;

	CopyMemory(hs->EphemeralKey, priv, NOISE_KEY_SIZE);
	hs->FixedEphemeral = CryptoX25519PublicKey(hs->EphemeralPub, hs->EphemeralKey);
	if (hs->FixedEphemeral == false)
		hs->Failed = true;
}

void NoiseHandshakeFree(NOISE_HANDSHAKE *hs) {
	if (hs == NULL)
		return;

	NoiseCipherFree(&hs->Cipher);
	CryptoMlKemFree(&hs->Kem);
	SecureZeroMemory(hs, sizeof(NOISE_HANDSHAKE));
	hs->Failed = true;
}

// A failed message ends the handshake: its keys are wiped, the peer's keys kept for the log
static bool NoiseHandshakeFail(NOISE_HANDSHAKE *hs) {
	NoiseCipherFree(&hs->Cipher);
	CryptoMlKemFree(&hs->Kem);
	SecureZeroMemory(hs->Ck, sizeof(hs->Ck));
	SecureZeroMemory(hs->StaticKey, sizeof(hs->StaticKey));
	SecureZeroMemory(hs->EphemeralKey, sizeof(hs->EphemeralKey));
	hs->Failed = true;

	return false;
}

// -> e, es, [e1,] s, ss (initiator)
static bool NoiseWriteMessage1(NOISE_HANDSHAKE *hs, UCHAR *msg, UINT max, UINT *pos) {
	UINT size = 0;

	if (max < NOISE_KEY_SIZE || NoiseNewEphemeral(hs) == false)
		return false;
	CopyMemory(msg, hs->EphemeralPub, NOISE_KEY_SIZE);
	*pos = NOISE_KEY_SIZE;
	if (NoiseMixHash(hs, hs->EphemeralPub, NOISE_KEY_SIZE) == false || NoiseMixDh(hs, false, hs->RemoteStatic) == false)
		return false;

	if (hs->Suite == NOISE_SUITE_IKHFS) {
		UCHAR encaps_key[CRYPTO_MLKEM768_ENCAPS_KEY_SIZE];

		if (CryptoMlKemGenerate(&hs->Kem, encaps_key) == false ||
		    NoiseEncryptAndHash(hs, encaps_key, sizeof(encaps_key), msg + *pos, max - *pos, &size) == false)
			return false;
		*pos += size;
	}

	if (NoiseEncryptAndHash(hs, hs->StaticPub, NOISE_KEY_SIZE, msg + *pos, max - *pos, &size) == false)
		return false;
	*pos += size;

	return NoiseMixDh(hs, true, hs->RemoteStatic);
}

// -> e, es, [e1,] s, ss (responder); *pos receives the offset of the payload
static bool NoiseReadMessage1(NOISE_HANDSHAKE *hs, const UCHAR *msg, UINT msg_size, UINT *pos) {
	UINT min = hs->Suite == NOISE_SUITE_IKHFS ? NOISE_IKHFS_MESSAGE1_SIZE : NOISE_IK_MESSAGE1_SIZE;

	if (msg_size < min)
		return false;

	CopyMemory(hs->RemoteEphemeral, msg, NOISE_KEY_SIZE);
	*pos = NOISE_KEY_SIZE;
	if (NoiseMixHash(hs, hs->RemoteEphemeral, NOISE_KEY_SIZE) == false || NoiseMixDh(hs, true, hs->RemoteEphemeral) == false)
		return false;

	if (hs->Suite == NOISE_SUITE_IKHFS) {
		UINT size = NoiseTokenSize(hs, CRYPTO_MLKEM768_ENCAPS_KEY_SIZE);
		if (NoiseDecryptToken(hs, msg + *pos, size, hs->RemoteKem, sizeof(hs->RemoteKem)) == false)
			return false;
		*pos += size;
	}

	UINT size = NoiseTokenSize(hs, NOISE_KEY_SIZE);
	if (NoiseDecryptToken(hs, msg + *pos, size, hs->RemoteStatic, NOISE_KEY_SIZE) == false)
		return false;
	*pos += size;

	return NoiseMixDh(hs, true, hs->RemoteStatic);
}

// <- e, ee, [ekem1,] se (responder)
static bool NoiseWriteMessage2(NOISE_HANDSHAKE *hs, UCHAR *msg, UINT max, UINT *pos) {
	UINT size = 0;

	if (max < NOISE_KEY_SIZE || NoiseNewEphemeral(hs) == false)
		return false;
	CopyMemory(msg, hs->EphemeralPub, NOISE_KEY_SIZE);
	*pos = NOISE_KEY_SIZE;
	if (NoiseMixHash(hs, hs->EphemeralPub, NOISE_KEY_SIZE) == false || NoiseMixDh(hs, false, hs->RemoteEphemeral) == false)
		return false;

	if (hs->Suite == NOISE_SUITE_IKHFS) {
		UCHAR ciphertext[CRYPTO_MLKEM768_CIPHERTEXT_SIZE];
		UCHAR secret[CRYPTO_MLKEM_SECRET_SIZE];

		bool ok = CryptoMlKemEncapsulate(ciphertext, secret, hs->RemoteKem) &&
		          NoiseEncryptAndHash(hs, ciphertext, sizeof(ciphertext), msg + *pos, max - *pos, &size) &&
		          NoiseMixKey(hs, secret, sizeof(secret));
		SecureZeroMemory(secret, sizeof(secret));
		if (ok == false)
			return false;
		*pos += size;
	}

	// se: DH of the initiator's static key and the responder's ephemeral key
	return NoiseMixDh(hs, false, hs->RemoteStatic);
}

// <- e, ee, [ekem1,] se (initiator); *pos receives the offset of the payload
static bool NoiseReadMessage2(NOISE_HANDSHAKE *hs, const UCHAR *msg, UINT msg_size, UINT *pos) {
	UINT min = hs->Suite == NOISE_SUITE_IKHFS ? NOISE_IKHFS_MESSAGE2_SIZE : NOISE_IK_MESSAGE2_SIZE;

	if (msg_size < min)
		return false;

	CopyMemory(hs->RemoteEphemeral, msg, NOISE_KEY_SIZE);
	*pos = NOISE_KEY_SIZE;
	if (NoiseMixHash(hs, hs->RemoteEphemeral, NOISE_KEY_SIZE) == false || NoiseMixDh(hs, false, hs->RemoteEphemeral) == false)
		return false;

	if (hs->Suite == NOISE_SUITE_IKHFS) {
		UCHAR ciphertext[CRYPTO_MLKEM768_CIPHERTEXT_SIZE];
		UCHAR secret[CRYPTO_MLKEM_SECRET_SIZE];
		UINT size = NoiseTokenSize(hs, sizeof(ciphertext));

		bool ok = NoiseDecryptToken(hs, msg + *pos, size, ciphertext, sizeof(ciphertext)) &&
		          CryptoMlKemDecapsulate(&hs->Kem, secret, ciphertext) && NoiseMixKey(hs, secret, sizeof(secret));
		SecureZeroMemory(secret, sizeof(secret));
		if (ok == false)
			return false;
		*pos += size;
	}

	return NoiseMixDh(hs, true, hs->RemoteEphemeral);
}

bool NoiseHandshakeWrite(NOISE_HANDSHAKE *hs, const void *payload, UINT payload_size, UCHAR *msg, UINT max, UINT *msg_size) {
	UINT pos = 0;
	UINT size = 0;

	if (msg_size != NULL)
		*msg_size = 0;
	if (hs == NULL || hs->Failed || msg == NULL || msg_size == NULL || (payload == NULL && payload_size != 0))
		return false;
	// The initiator writes the first message, the responder the second
	if ((hs->Initiator && hs->Messages != 0) || (hs->Initiator == false && hs->Messages != 1))
		return false;
	if (max > NOISE_MAX_MESSAGE)
		max = NOISE_MAX_MESSAGE;

	bool ok = hs->Initiator ? NoiseWriteMessage1(hs, msg, max, &pos) : NoiseWriteMessage2(hs, msg, max, &pos);
	if (ok == false || NoiseEncryptAndHash(hs, payload, payload_size, msg + pos, max - pos, &size) == false) {
		SecureZeroMemory(msg, pos);
		return NoiseHandshakeFail(hs);
	}

	hs->Messages++;
	*msg_size = pos + size;
	return true;
}

bool NoiseHandshakeRead(NOISE_HANDSHAKE *hs, const UCHAR *msg, UINT msg_size, void *payload, UINT max, UINT *payload_size) {
	UINT pos = 0;
	UINT size = 0;

	if (payload_size != NULL)
		*payload_size = 0;
	if (hs == NULL || hs->Failed || msg == NULL || payload_size == NULL || (payload == NULL && max != 0))
		return false;
	// The responder reads the first message, the initiator the second
	if ((hs->Initiator && hs->Messages != 1) || (hs->Initiator == false && hs->Messages != 0))
		return false;

	bool ok = msg_size <= NOISE_MAX_MESSAGE && (hs->Initiator ? NoiseReadMessage2(hs, msg, msg_size, &pos) : NoiseReadMessage1(hs, msg, msg_size, &pos));
	if (ok == false || NoiseDecryptAndHash(hs, msg + pos, msg_size - pos, payload, max, &size) == false) {
		if (payload != NULL && max != 0)
			SecureZeroMemory(payload, max);
		return NoiseHandshakeFail(hs);
	}

	hs->Messages++;
	*payload_size = size;
	return true;
}

// Split(): temp_k1, temp_k2 = HKDF(ck, zerolen, 2); the initiator sends with the first and
// receives with the second, the responder the other way round
bool NoiseHandshakeSplit(NOISE_HANDSHAKE *hs, NOISE_CIPHER *send, NOISE_CIPHER *recv) {
	UCHAR out[2 * NOISE_KEY_SIZE];
	bool ok = false;

	if (send != NULL)
		send->Aead.Key = NULL;
	if (recv != NULL)
		recv->Aead.Key = NULL;
	if (hs == NULL || hs->Failed || hs->Messages != 2 || send == NULL || recv == NULL)
		return false;

	if (CryptoHkdf(out, sizeof(out), hs->Ck, NOISE_KEY_SIZE, NULL, 0, NULL, 0)) {
		const UCHAR *k1 = out;
		const UCHAR *k2 = out + NOISE_KEY_SIZE;

		ok = NoiseCipherInit(send, hs->Initiator ? k1 : k2) && NoiseCipherInit(recv, hs->Initiator ? k2 : k1);
		if (ok == false) {
			NoiseCipherFree(send);
			NoiseCipherFree(recv);
		}
	}

	SecureZeroMemory(out, sizeof(out));
	return ok;
}
