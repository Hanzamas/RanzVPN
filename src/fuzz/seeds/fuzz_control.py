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
# Without RANZ_CONTROL_WIRE this file writes the security, the operation and the peering seeds alone, and the other seeds
# stay as they are.
#
# The security seeds (SDN-41 #234) hold the L2Security of the L2 Networks of a state, which no frame of those tests holds,
# so that inputs reach ControlCopySecurities: an Update of an L2 Network with one, an L3 Network with one that the node
# leaves out and an L2 Network without one (security-state.bin), and that Update then two deltas, which give the third
# Network one and take the first one's away, as a stream (security-stream.bin).
#
# The operation seeds (SDN-50-N #492) hold the Operations of the live operations, which the frames of those tests of
# 2026-10-27 do not, so that inputs reach ControlTakeOperation: a read of the MAC table of an L2 Network alone
# (operation-read.bin), and a state of the L2 Network lan and the L3 Network wan followed by an Operation of each kind on
# lan, the clears with and without their entry, one on wan and one on dmz, which the node holds as no L2 Network, and three
# that it refuses: of a kind that it does not know, and with a MAC address and an address of sizes that none has, as a
# stream (operation-stream.bin).
#
# The peering seeds (SDN-77 #357) hold the BGP peering of the standard mode, which the frames of those tests of 2026-10-27 do
# not, so that inputs reach ControlCopyPeerings: a state whose VRFs dc and lab peer by BGP, with the peering of the node
# gw-1 and of its peers db, whose sidecar is on IPv4, and lab-1, on IPv6 and in both VRFs (peering-state.bin); and that
# state followed by a delta with what the node cannot read (a router id of 3 bytes, an address of a sidecar of 5 bytes, a
# peering of a peer without a VRF, prefixes without an address, of 3 bytes or longer than their address, and lab without
# the peering), a delta that takes the peering of the node and the peer lab-1 away, and one that brings them back, as a
# stream (peering-stream.bin).
#
# make_seeds.py runs make_seeds(h), h being make_seeds.py itself with write_seed.

import hashlib
import ipaddress
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


def update(generation, base, objects, removes=()):
    # A ControlMessage with the Update to generation from base (0 for a full state) that sets objects and removes the
    # objects of the ObjectKeys removes
    u = field(1, generation)
    if base:
        u += field(2, base)
    for o in objects:
        u += message(3, o)
    for k in removes:
        u += message(4, k)
    return message(2, u)


def make_security_seeds(h):
    state = update(1, 0, [network('lan', 2, l2_security(True, ['gw-a', 'gw-b'])), network('wan', 1, l2_security(True, ['gw-a'])),
                          network('dmz', 2)])
    gives = update(2, 1, [network('dmz', 2, l2_security(False, ['gw-a']))])
    takes = update(3, 2, [network('lan', 2)])
    h.write_seed('fuzz_control', 'security-state.bin', state)
    h.write_seed('fuzz_control', 'security-stream.bin', b''.join(struct.pack('>I', len(m)) + m for m in (state, gives, takes)))


def operation(op_id, kind, name, mac=b'', address=b''):
    # A ControlMessage with the Operation op_id of the kind kind (1 and 2 the MAC table, 3 and 4 the IP table, the second a
    # clear) on the Network name, with the MAC address mac or the address address of a clear
    o = field(1, op_id) + field(2, kind) + message(3, name.encode('ascii'))
    if mac:
        o += message(4, mac)
    if address:
        o += message(5, address)
    return message(9, o)


def make_operation_seeds(h):
    state = update(1, 0, [network('lan', 2), network('wan', 1)])
    mac = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x0A])
    v4 = bytes([10, 20, 0, 8])
    v6 = bytes([0xFD, 0x00] + [0x00] * 13 + [0x08])
    operations = [operation(1, 1, 'lan'), operation(2, 3, 'lan'), operation(3, 2, 'lan', mac=mac), operation(4, 4, 'lan', address=v4),
                  operation(5, 4, 'lan', address=v6), operation(6, 2, 'lan'), operation(7, 4, 'lan'), operation(8, 1, 'wan'),
                  operation(9, 3, 'dmz'), operation(10, 9, 'lan'), operation(11, 2, 'lan', mac=mac[:5]),
                  operation(12, 4, 'lan', address=v4[:3])]
    h.write_seed('fuzz_control', 'operation-read.bin', operations[0])
    h.write_seed('fuzz_control', 'operation-stream.bin', b''.join(struct.pack('>I', len(m)) + m for m in [state] + operations))


def packed(number, values):
    # A repeated varint field, packed as proto3 writes it
    return message(number, b''.join(varint(v) for v in values))


def ip(text):
    # The bytes of an IPv4 or an IPv6 address
    return ipaddress.ip_address(text).packed


def raw_route(vrf_id, address, length):
    # A Route of the VRF vrf_id whose Prefix has the bytes address and the length length, or none for address None
    r = field(1, vrf_id)
    if address is not None:
        r += message(2, message(1, address) + field(2, length))
    return r


def route(vrf_id, prefix):
    # A Route of the prefix ADDRESS/LENGTH of the VRF vrf_id
    address, length = prefix.split('/')
    return raw_route(vrf_id, ip(address), int(length))


def vrf(name, vrf_id, peering):
    # An Object of the VRF name with the id vrf_id and links of kind vxlan on the VNI 5000 + vrf_id, whose nodes peer by BGP
    # when peering
    v = message(1, name.encode('ascii')) + field(2, vrf_id) + field(8, 1) + field(9, 5000 + vrf_id)
    if peering:
        v += field(13, 1)
    return message(2, v)


def node_peering(router_id, address, announce):
    # A NodePeering in the AS of the overlay with the router id and the address of the bytes router_id and address, which
    # announces the Routes announce
    p = field(1, 4200000000) + message(2, router_id) + message(3, address)
    for r in announce:
        p += message(4, r)
    return p


def node(name, peering=None):
    # An Object of the NodeConfig of the node name, with the NodePeering peering
    n = message(1, name.encode('ascii'))
    if peering is not None:
        n += message(14, peering)
    return message(1, n)


def peer_peering(address, hold_time, vrf_ids, accept):
    # A PeerPeering with the sidecar of the bytes address, the hold time hold_time (0 for none), the VRFs vrf_ids and the
    # Routes accept
    p = message(1, address)
    if hold_time:
        p += field(2, hold_time)
    if vrf_ids:
        p += packed(3, vrf_ids)
    for r in accept:
        p += message(4, r)
    return p


def peer(name, key, vrf_ids, peering=None):
    # An Object of the Peer name with the static key key, 32 bytes, in the VRFs vrf_ids, with the PeerPeering peering
    p = message(1, name.encode('ascii')) + message(2, key) + packed(3, vrf_ids)
    if peering is not None:
        p += message(12, peering)
    return message(4, p)


def object_key(kind, name):
    # An ObjectKey of the object of the kind kind, the tag of its kind in Object, and of the name name
    return field(1, kind) + message(2, name.encode('ascii'))


def make_peering_seeds(h):
    gw = ip('10.1.0.1')
    db_key = bytes([0x02] * 32)
    lab_key = bytes([0x03] * 32)
    own = node_peering(gw, gw, [route(30, '192.168.10.0/24'), route(31, '192.168.11.0/24')])
    db = peer_peering(ip('10.1.0.2'), 9, [30], [route(30, '10.30.0.2/32'), route(30, '192.168.20.0/24')])
    lab = peer_peering(ip('fd00::2'), 0, [30, 31], [route(30, '10.30.0.3/32'), route(31, 'fd00:31::/64')])
    objects = [node('gw-1', own), vrf('dc', 30, True), vrf('lab', 31, True), peer('db', db_key, [30], db),
               peer('lab-1', lab_key, [30, 31], lab)]
    state = update(1, 0, objects)
    cannot = update(2, 1, [node('gw-1', node_peering(gw[:3], gw, [route(30, '192.168.10.0/24')])), vrf('lab', 31, False),
                           peer('db', db_key, [30], peer_peering(gw + b'\x00', 9, [30], [route(30, '10.30.0.2/32')])),
                           peer('lab-1', lab_key, [30, 31],
                                peer_peering(ip('fd00::2'), 0, [], [raw_route(31, None, 0), raw_route(31, gw[:3], 24),
                                                                   raw_route(30, ip('10.30.0.0'), 40)]))])
    takes = update(3, 2, [node('gw-1')], [object_key(4, 'lab-1')])
    back = update(4, 3, objects)
    h.write_seed('fuzz_control', 'peering-state.bin', state)
    h.write_seed('fuzz_control', 'peering-stream.bin', b''.join(struct.pack('>I', len(m)) + m for m in (state, cannot, takes, back)))


def make_seeds(h):
    make_security_seeds(h)
    make_operation_seeds(h)
    make_peering_seeds(h)

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
