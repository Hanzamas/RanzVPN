# fuzz_peer_punch.py
# Seeds of fuzz_peer (src/fuzz/fuzz_peer.c) for the symmetric-NAT punch of the peer layer (src/Core/PeerPunch.c,
# CORE-S5-7 #413). fuzz_peer.c seals an input of the size of a punch message as the payload of one, from B to A and from
# A to B, at an A and a B that have a punch open with each other, A leading as the end of the lower key; and it seals an
# input that is a punch offer or a punch answer as that signal, at an A behind a cone and a B behind a sequential NAT.
#
# A punch message is 42 bytes: the version 1, the sequence (fuzz_peer.c writes a fresh one), the type (1 a probe, 2 a
# challenge, 3 a response, 4 a proof, 5 a keepalive), a nonce of the sender and the echo of a nonce of the receiver, 16
# bytes each. A response at A and a proof at B reach the check of the echo (PeerPunchEcho), which the fuzz-reach line of
# fuzz_peer.c names.
#
# A punch signal is the version, the type (3 a punch offer, 4 a punch answer), the sequence (fuzz_peer.c writes a fresh
# one), the key and the address of the relay R of the two nodes, the number of candidates and the candidates (a type, an
# IPv4-mapped address and a port each: 2 server reflexive, 4 predicted, 5 toward), then the NAT of the sender (1 cone, 2
# sequential, 3 random).
#
# make_seeds.py runs make_seeds(h), h being make_seeds.py itself with write_seed and PEER_RELAY.

import struct

NONCE = bytes(range(0x10, 0x20))
ECHO = bytes(range(0x40, 0x50))


def punch(kind, nonce=bytes(16), echo=bytes(16), version=1):
    # The payload of a punch message
    return bytes([version]) + struct.pack('>Q', 1) + bytes([kind]) + nonce + echo


def addr(a, b, c, d, port):
    # An IPv4 address as the peer layer writes one: IPv4-mapped IPv6, then the port
    return bytes(10) + b'\xff\xff' + bytes([a, b, c, d]) + struct.pack('>H', port)


def signal(kind, relay_key, relay, candidates, nat):
    # The payload of a punch offer or a punch answer
    return (bytes([1, kind]) + struct.pack('>Q', 1) + relay_key + relay + bytes([len(candidates)]) +
            b''.join(bytes([t]) + a for t, a in candidates) + bytes([nat]))


def make_seeds(h):
    def seed(name, data):
        h.write_seed('fuzz_peer', name, data)

    # A punch message of each type, and two that the parser refuses: a type past the last one and another version
    seed('punch_probe.bin', punch(1))
    seed('punch_challenge.bin', punch(2, nonce=NONCE))
    seed('punch_response.bin', punch(3, nonce=NONCE, echo=ECHO))
    seed('punch_proof.bin', punch(4, echo=ECHO))
    seed('punch_keepalive.bin', punch(5))
    seed('punch_unknown_type.bin', punch(6))
    seed('punch_version_2.bin', punch(1, version=2))

    # The punch signals, with R of fuzz_peer.c as their relay: a sequential NAT with its prediction and the port of its
    # mapping towards the reflexive address of the receiver, which a node behind a cone sweeps around; a cone; a random
    # NAT, which only a cone takes; and an answer, which a node takes only for its own offer
    relay = addr(192, 0, 2, 10, 7000)
    srflx = (2, addr(203, 0, 113, 10, 40000))
    predicted = (4, addr(203, 0, 113, 10, 40003))
    toward = (5, addr(203, 0, 113, 10, 40002))
    seed('punch_offer_sequential.bin', signal(3, h.PEER_RELAY, relay, [srflx, predicted, toward], 2))
    seed('punch_offer_cone.bin', signal(3, h.PEER_RELAY, relay, [srflx], 1))
    seed('punch_offer_random.bin', signal(3, h.PEER_RELAY, relay, [srflx], 3))
    seed('punch_answer_sequential.bin', signal(4, h.PEER_RELAY, relay, [srflx, predicted], 2))
