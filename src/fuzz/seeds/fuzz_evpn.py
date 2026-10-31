# Seeds of fuzz_evpn, run by make_seeds.py (h is that module).
#
# The EVPN of a gateway node (src/Cedar/NodeEvpn.c): the first byte, modulo 3, picks the parser of fuzz_evpn.c: 0 the
# messages of the BGP sidecar, 1 a frame of the fabric, 2 the outer source of a frame against the VTEPs of the routes. The
# messages, one JSON object per line as ranz-bgp/internal/sidecar/evpn.go writes them: a learned IP prefix route of IPv4 and
# of IPv6, a withdrawn one, a learned route of the unicast table without a vni, which is no route of an EVPN VRF, a run of
# them, and learned messages that the node cannot take: a VNI of 25 bits, the router MAC of a group, a prefix that is none,
# and no next hop. The frames, as a VTEP of a fabric sends them on the L3 VNI of a VRF: an IPv4 and an IPv6 packet to the
# router MAC of the gateway, a frame to another MAC address, a tagged one, an IPv6 packet behind the EtherType of IPv4, and a
# frame cut in its IP header. The outer sources (SDN-25-R1 #549), each the VRF of a frame and the address that it came from
# in front of the routes of a run, whose VTEPs the gateway knows: 192.0.2.10 for VRF 101, by two routes, 192.0.2.11 for VRF
# 102 and 2001:db8::10 for VRF 101. The IPv4 VTEP of VRF 101 and the IPv6 one are known; the IPv4 VTEP of VRF 101 in VRF
# 102 and an address of no route are not.

import json
import struct

ROUTER_MAC = bytes.fromhex('02525a000005')
FABRIC_MAC = bytes.fromhex('02005e100001')


def message(**fields):
    # As Go's encoding/json writes a Message: no spaces, the fields in the order of the struct
    return json.dumps(fields, separators=(',', ':')).encode()


def learned(**changes):
    fields = dict(type='learned', prefix='172.16.1.0/24', next_hop='192.0.2.10', vrf=101, peer='192.0.2.10', vni=10101,
                  router_mac='02:00:5e:10:00:01')
    fields.update(changes)
    return message(**{k: v for k, v in fields.items() if v is not None})


def make_seeds(h):
    def seed(file_name, data):
        h.write_seed('fuzz_evpn', file_name, data)

    withdrawn = message(type='withdrawn', prefix='172.16.1.0/24', vrf=101, peer='192.0.2.10', vni=10101)
    unicast = message(type='learned', prefix='198.51.100.0/24', next_hop='192.0.2.2', peer='192.0.2.2')
    learned6 = learned(prefix='2001:db8:16::/48', next_hop='2001:db8::10', peer='2001:db8::10')

    seed('learned.bin', b'0' + learned())
    seed('learned6.bin', b'0' + learned6)
    seed('withdrawn.bin', b'0' + withdrawn)
    seed('unicast.bin', b'0' + unicast)
    seed('session.bin', b'0' + b'\n'.join([unicast, learned(), learned6, withdrawn]))
    seed('vni_25_bits.bin', b'0' + learned(vni=0x1000000))
    seed('group_mac.bin', b'0' + learned(router_mac='01:00:5e:00:00:01'))
    seed('bad_prefix.bin', b'0' + learned(prefix='172.16.1.1/33'))
    seed('no_next_hop.bin', b'0' + learned(next_hop=None))

    a, b = [172, 16, 1, 10], [10, 10, 0, 1]
    packet = h.ipv4(a, b, 17, h.udp(a, b, 53, 5000, b'ranz-evpn'))
    src6 = bytes.fromhex('20010db8001600000000000000000010')
    dst6 = bytes.fromhex('20010db8001000000000000000000001')
    datagram6 = struct.pack('>HHHH', 53, 5000, 8 + 9, 0) + b'ranz-evpn'
    packet6 = struct.pack('>IHBB', 0x60000000, len(datagram6), 17, 64) + src6 + dst6 + datagram6

    seed('frame_ipv4.bin', b'1' + h.eth(ROUTER_MAC, FABRIC_MAC, 0x0800, packet))
    seed('frame_ipv6.bin', b'1' + h.eth(ROUTER_MAC, FABRIC_MAC, 0x86DD, packet6))
    seed('frame_not_ours.bin', b'1' + h.eth(FABRIC_MAC, ROUTER_MAC, 0x0800, packet))
    seed('frame_tagged.bin', b'1' + h.eth(ROUTER_MAC, FABRIC_MAC, 0x8100, struct.pack('>HH', 10, 0x0800) + packet))
    seed('frame_version_mismatch.bin', b'1' + h.eth(ROUTER_MAC, FABRIC_MAC, 0x0800, packet6))
    seed('frame_cut.bin', b'1' + h.eth(ROUTER_MAC, FABRIC_MAC, 0x0800, packet[:12]))

    # The address of an outer source as the node holds it: an IPv4 address as an IPv4-mapped one
    def mapped(*b):
        return bytes(10) + b'\xff\xff' + bytes(b)

    routes = b'\n'.join([learned(), learned(prefix='172.16.2.0/24'),
                         learned(vrf=102, next_hop='192.0.2.11', peer='192.0.2.11'), learned6, withdrawn])

    def source(vrf, address):
        return b'2' + struct.pack('>I', vrf) + address + routes

    seed('vtep_known.bin', source(101, mapped(192, 0, 2, 10)))
    seed('vtep_ipv6.bin', source(101, bytes.fromhex('20010db8000000000000000000000010')))
    seed('vtep_other_vrf.bin', source(102, mapped(192, 0, 2, 10)))
    seed('vtep_stranger.bin', source(101, mapped(192, 0, 2, 99)))
