# fuzz_control.py
# Seeds of fuzz_control (src/fuzz/fuzz_control.c): the control stream of a node (src/Core/Control.c, SDN-3 #179). They are
# the control messages of the controller tests: the conformance tests of controller/internal/controller and the cluster
# tests of controller/cluster_test.go write every frame that their simulated nodes sent and received into the directory
# that RANZ_CONTROL_WIRE names, one file per frame (<test>-<node>-<index>-<recv|sent>.bin), and these are the files that
# tests/control/nanopb_roundtrip.c decodes in CI (the nanopb round trip of ranz.yml). Each message is a seed of its own
# (wire-<file>), which fuzz_control reads as one message; and the messages that one simulated node received, in their
# order, make one stream (stream-<test>-<node>.bin), each the size of its message in 4 bytes (big-endian) and the message,
# as the controller sends them, so that the deltas of a stream apply to the state before them. A seed whose bytes an
# earlier one has is left out.
#
# The seeds of src/fuzz/corpus/fuzz_control are the frames of the tests of 2026-10-27 (AUD1-DT-12 #460), written with
#   RANZ_CONTROL_WIRE=<dir> RQLITED=<rqlited of the pinned rqlite> go test -count=1 ./controller/internal/controller ./controller
#   RANZ_CONTROL_WIRE=<dir> python -I src/fuzz/make_seeds.py
# Without RANZ_CONTROL_WIRE this file writes the security seeds alone, and the other seeds stay as they are.
#
# The security seeds (SDN-41 #234) hold the L2Security of the L2 Networks of a state, which no frame of those tests holds,
# so that inputs reach ControlCopySecurities: an Update of an L2 Network with one, an L3 Network with one that the node
# leaves out and an L2 Network without one (security-state.bin), and that Update then two deltas, which give the third
# Network one and take the first one's away, as a stream (security-stream.bin).
#
# make_seeds.py runs make_seeds(h), h being make_seeds.py itself with write_seed.

import hashlib
import os
import re
import struct


def varint(v):
    out = b''
    while v >= 0x80:
        out += bytes([(v & 0x7F) | 0x80])
        v >>= 7
    return out + bytes([v])


def field(number, value):
    # A varint field of the protobuf wire format
    return varint(number << 3) + varint(value)


def message(number, data):
    # A field of length-delimited data: a string or a message
    return varint((number << 3) | 2) + varint(len(data)) + data


def l2_security(checks, gateways):
    # An L2Security: the MAC and IP checks with the limits 2 and 4 and ARP and DHCP only when checks, the DHCP and RA
    # guards, and the gateways
    s = b''
    if checks:
        s += field(1, 1) + field(2, 1) + field(3, 2) + field(4, 4) + field(5, 1)
    s += field(6, 1) + field(7, 1)
    for gateway in gateways:
        s += message(8, gateway.encode('ascii'))
    return s


def network(name, mode, security=None):
    # An Object of the Network name of VRF 10 and of the mode mode (1 for L3, 2 for L2), with the L2Security security
    nw = message(1, name.encode('ascii')) + field(2, 10) + field(3, mode)
    if security is not None:
        nw += message(7, security)
    return message(3, nw)


def update(generation, base, objects):
    # A ControlMessage with the Update to generation from base (0 for a full state) that sets objects
    u = field(1, generation)
    if base:
        u += field(2, base)
    for o in objects:
        u += message(3, o)
    return message(2, u)


def make_security_seeds(h):
    state = update(1, 0, [network('lan', 2, l2_security(True, ['gw-a', 'gw-b'])), network('wan', 1, l2_security(True, ['gw-a'])),
                          network('dmz', 2)])
    gives = update(2, 1, [network('dmz', 2, l2_security(False, ['gw-a']))])
    takes = update(3, 2, [network('lan', 2)])
    h.write_seed('fuzz_control', 'security-state.bin', state)
    h.write_seed('fuzz_control', 'security-stream.bin', b''.join(struct.pack('>I', len(m)) + m for m in (state, gives, takes)))


def make_seeds(h):
    make_security_seeds(h)

    directory = os.environ.get('RANZ_CONTROL_WIRE')
    if not directory or not os.path.isdir(directory):
        return

    seen = set()
    streams = {}

    def seed(name, data):
        digest = hashlib.sha256(data).digest()
        if digest not in seen:
            seen.add(digest)
            h.write_seed('fuzz_control', name, data)

    for name in sorted(os.listdir(directory)):
        m = re.match(r'^(.+)-(\d+)-(recv|sent)\.bin$', name)
        if m is None:
            continue
        with open(os.path.join(directory, name), 'rb') as f:
            data = f.read()
        seed('wire-' + name, data)
        if m.group(3) == 'recv':
            streams.setdefault(m.group(1), []).append((int(m.group(2)), data))

    for key in sorted(streams):
        frames = sorted(streams[key])
        seed('stream-%s.bin' % key, b''.join(struct.pack('>I', len(data)) + data for _, data in frames))
