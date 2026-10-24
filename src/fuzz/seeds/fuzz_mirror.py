# fuzz_mirror.py
# Seeds of fuzz_mirror (src/fuzz/fuzz_mirror.c): the Mirrors of the Node module (src/Cedar/NodeMirror.c, SDN-23 #199).
# The first byte picks the VRF (its two low bits: 101, 202, 303, and 16777216, an id of 25 bits) and the way (bit 2: a
# packet of the host), the rest is an IP packet. fuzz_mirror.c has the Mirrors of UDP port 53 in VRF 101, of TCP port
# 8080 in every VRF, of ICMP in VRF 202, and of every packet of every VRF.
#
# make_seeds.py runs make_seeds(h), h being make_seeds.py itself with write_seed and the packet helpers.

import struct


def make_seeds(h):
    out, vrf101, vrf202, vrf303, vrf25bit = 0x04, 0, 1, 2, 3
    a, b = [10, 0, 0, 1], [10, 0, 0, 2]
    a6, b6 = bytes.fromhex('fd000000000000000000000000000001'), bytes.fromhex('fd000000000000000000000000000002')
    data = b'ranz-mirror-data'

    def seed(name, way, packet):
        h.write_seed('fuzz_mirror', name, bytes([way]) + packet)

    def ipv6_fragment(src, dst, nh, offset, more, payload):
        # An IPv6 packet behind a fragment header of the offset (in units of 8 bytes) and the M flag
        frag = struct.pack('>BBHI', nh, 0, (offset << 3) | (1 if more else 0), 0x52414E5A)
        return struct.pack('>IHBB', 6 << 28, len(frag) + len(payload), 44, 64) + bytes(src) + bytes(dst) + frag + payload

    # UDP port 53 in VRF 101, each way, IPv4 and IPv6, behind a hop-by-hop options header and in the first fragment
    seed('dns_query_out.bin', vrf101 | out, h.ipv4(a, b, 17, h.udp(a, b, 40000, 53, data)))
    seed('dns_answer_in.bin', vrf101, h.ipv4(b, a, 17, h.udp(b, a, 53, 40000, data)))
    seed('dns6_hop_by_hop_out.bin', vrf101 | out, h.ipv6(a6, b6, 17, h.udp6(a6, b6, 40001, 53, data), ext=bytes([17, 0, 1, 4, 0, 0, 0, 0])))
    seed('dns6_first_fragment_out.bin', vrf101 | out, ipv6_fragment(a6, b6, 17, 0, True, h.udp6(a6, b6, 40002, 53, data)))
    # Later fragments, which hold no ports: IPv4 and IPv6
    later = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(data), 1, 185, 64, 17, 0, bytes(b), bytes(a))
    seed('dns_later_fragment_in.bin', vrf101, later[:10] + struct.pack('>H', h.csum(later)) + later[12:] + data)
    seed('dns6_later_fragment_in.bin', vrf101, ipv6_fragment(b6, a6, 17, 185, False, data))
    # TCP port 8080 in VRF 303, and in the VRF whose id no VNI holds
    seed('tcp_8080_out.bin', vrf303 | out, h.ipv4(a, b, 6, h.tcp(a, b, 40003, 8080, 0x01020304, 0, 0x10, data)))
    seed('tcp_8080_vrf25bit_in.bin', vrf25bit, h.ipv4(b, a, 6, h.tcp(b, a, 8080, 40003, 0x05060708, 0x01020305, 0x10, data)))
    # ICMP and ICMPv6 in VRF 202
    seed('ping_out.bin', vrf202 | out, h.ipv4(a, b, 1, h.icmp4(8, 0, 0x4D490001, data)))
    seed('ping6_in.bin', vrf202, h.ipv6(b6, a6, 58, h.icmp6(b6, a6, 128, 0, 0x4D490001, data)))
    # A packet cut short in its extension headers, one cut short in its ports, no IP packet, and a packet whose copy
    # does not fit in a VXLAN frame
    seed('ipv6_cut_in_header_out.bin', vrf101 | out, h.ipv6(a6, b6, 17, h.udp6(a6, b6, 40004, 53, data), ext=bytes([17, 0, 1, 4, 0, 0, 0, 0]))[:44])
    seed('udp_cut_in_ports_in.bin', vrf101, h.ipv4(b, a, 17, h.udp(b, a, 53, 40000, data))[:22])
    seed('not_ip_out.bin', vrf101 | out, b'\x50' + bytes(39))
    seed('jumbo_dns_out.bin', vrf101 | out, h.ipv4(a, b, 17, h.udp(a, b, 40005, 53, bytes(9172))))
