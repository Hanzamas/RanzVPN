# fuzz_egress.py
# Seeds of fuzz_egress (src/fuzz/fuzz_egress.c): the internet exit of the Node module (src/Cedar/NodeEgress.c; SDN-12 #188).
# A seed is an IPv4 packet of a peer to an address outside its VRF, as NodeEgressParse reads it: a TCP segment or a UDP
# datagram, which the proxy gives its own ends and back, an ICMP echo request, which gets its echo reply, and the packets
# that the Egress does not carry: another ICMP message, a fragment, IPv6 and headers that the packet does not hold.
#
# make_seeds.py runs make_seeds(h), h being make_seeds.py itself with write_seed and the packet helpers.

import struct


def make_seeds(h):
    peer, outside = [10, 0, 0, 7], [198, 51, 100, 9]
    data = b'ranz-egress-data'

    def seed(name, packet):
        h.write_seed('fuzz_egress', name, packet)

    # TCP: the SYN of a connection with an MSS option, and a segment of data
    seed('tcp_syn.bin', h.ipv4(peer, outside, 6, h.tcp_syn(peer, outside, 40000, 443, 1000, bytes([2, 4, 5, 0xb4]))))
    seed('tcp_data.bin', h.ipv4(peer, outside, 6, h.tcp(peer, outside, 40000, 443, 1001, 5001, 0x18, data)))
    # UDP with and without a checksum, and a datagram whose length is past the packet
    seed('udp.bin', h.ipv4(peer, outside, 17, h.udp(peer, outside, 40001, 53, data)))
    udp_none = bytearray(h.udp(peer, outside, 40002, 53, data))
    udp_none[6:8] = b'\x00\x00'
    seed('udp_no_checksum.bin', h.ipv4(peer, outside, 17, bytes(udp_none)))
    udp_long = bytearray(h.udp(peer, outside, 40003, 53, data))
    udp_long[4:6] = struct.pack('>H', 8 + len(data) + 1)
    seed('udp_length_past.bin', h.ipv4(peer, outside, 17, bytes(udp_long)))
    # ICMP: an echo request, and a message that the Egress does not carry (a destination unreachable)
    seed('echo_request.bin', h.ipv4(peer, outside, 1, h.icmp4(8, 0, 0x45470001, data)))
    seed('unreachable.bin', h.ipv4(peer, outside, 1, h.icmp4(3, 3, 0, data)))
    # An IPv4 header with options, a fragment, a total length past the packet and a header that the packet does not hold
    options = bytearray(h.ipv4(peer, outside, 17, h.udp(peer, outside, 40004, 53, data)))
    options = bytes([0x46]) + options[1:2] + struct.pack('>H', len(options) + 4) + options[4:20] + b'\x01\x01\x01\x00' + options[20:]
    seed('ipv4_options.bin', options)
    fragment = bytearray(h.ipv4(peer, outside, 17, h.udp(peer, outside, 40005, 53, data)))
    fragment[6] = 0x20
    seed('fragment.bin', bytes(fragment))
    seed('total_past.bin', h.ipv4(peer, outside, 6, h.tcp(peer, outside, 40006, 443, 1, 0, 0x02, b''))[:30])
    seed('short.bin', h.ipv4(peer, outside, 6, h.tcp(peer, outside, 40007, 443, 1, 0, 0x02, b''))[:19])
    # IPv6, which the Egress leaves alone
    seed('ipv6.bin', h.ipv6(bytes.fromhex('fd000000000000000000000000000007'), bytes.fromhex('20010db8000000000000000000000009'), 17, b'\x00' * 8))
