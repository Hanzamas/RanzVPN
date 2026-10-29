# fuzz_nodeprofile.py
# Seeds of fuzz_nodeprofile (src/fuzz/fuzz_nodeprofile.c): the session profiles of the Node module
# (src/Cedar/NodeProfile.c, SDN-40 #233). An input is a list of packets, each after a byte that picks the way (bit 0: a
# packet of the host to the peer; bit 3: a packet that the node, as a hub, sends on from the next hop of bits 1 and 2 to the
# one of bits 4 and 5) and the next hop (bits 1 and 2: 0 the peer under a profile, 1 the peer under none, 2 the leaked
# route of the first, 3 a next hop that the tables do not have), and its size in 2 bytes. The node is 10.0.0.1 and
# fd00::1, its peers 10.0.0.2 and fd00::2 (under the profile) and 10.0.0.3 and fd00::3; the profile limits the IPv4
# addresses of a session to 2 and its IPv6 addresses to 1, and has no-routing, no-server and the privacy filter.
#
# make_seeds.py runs make_seeds(h), h being make_seeds.py itself with write_seed and the packet helpers.

import struct

OUT, IN = 0x01, 0x00
PROFILED, PLAIN, LEAKED, NO_HOP = 0 << 1, 1 << 1, 2 << 1, 3 << 1


def make_seeds(h):
    node, peer, other = [10, 0, 0, 1], [10, 0, 0, 2], [10, 0, 0, 3]
    node6, peer6 = bytes.fromhex('fd000000000000000000000000000001'), bytes.fromhex('fd000000000000000000000000000002')
    data = b'ranz-profile-data'

    def packet(pick, p):
        return bytes([pick]) + struct.pack('>H', len(p)) + p

    def seed(name, *packets):
        h.write_seed('fuzz_nodeprofile', name, b''.join(packets))

    def tcp(src, dst, flags):
        return h.ipv4(src, dst, 6, h.tcp(src, dst, 40000, 443, 0x01020304, 0, flags, b''))

    def tcp6(src, dst, flags, ext=b''):
        seg = struct.pack('>HHIIBBHHH', 40000, 443, 0x01020304, 0, 5 << 4, flags, 65535, 0, 0)
        return h.ipv6(src, dst, 6, seg, ext=ext)

    hop_by_hop_tcp = bytes([6, 0, 1, 4, 0, 0, 0, 0])

    # No-server: a SYN to the peer and a SYN-ACK from it, in IPv4 and behind a hop-by-hop header of IPv6; an ACK passes
    seed('syn_to_peer.bin', packet(OUT | PROFILED, tcp(node, peer, 0x02)))
    seed('syn_ack_from_peer.bin', packet(IN | PROFILED, tcp(peer, node, 0x12)))
    seed('syn6_hop_by_hop_to_peer.bin', packet(OUT | PROFILED, tcp6(node6, peer6, 0x02, ext=hop_by_hop_tcp)))
    seed('ack_to_peer.bin', packet(OUT | PROFILED, tcp(node, peer, 0x10)))
    # The node's own no-server: a SYN to its host from the peer under none, a SYN-ACK of its host
    seed('syn_from_plain.bin', packet(IN | PLAIN, tcp(other, node, 0x02)), packet(OUT | PLAIN, tcp(node, other, 0x12)))
    # A TCP header cut short before its flags, and a later fragment over them
    seed('tcp_cut_short.bin', packet(OUT | PROFILED, tcp(node, peer, 0x02)[:30]))
    over = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 28, 7, 1, 64, 6, 0, bytes(peer), bytes(node)) + bytes(8)
    seed('tcp_fragment_over_flags.bin', packet(IN | PROFILED, over))
    # The counts: four IPv4 and two IPv6 sources of the peer, then the first again
    seed('sources.bin', *[packet(IN | PROFILED, h.ipv4(src, node, 17, h.udp(src, node, 40000 + i, 53, data)))
                          for i, src in enumerate([peer, [10, 0, 0, 12], [10, 0, 0, 22], [10, 0, 0, 32], peer])],
         packet(IN | PROFILED, h.ipv6(peer6, node6, 17, h.udp6(peer6, node6, 40010, 53, data))),
         packet(IN | PROFILED, h.ipv6(bytes.fromhex('fd000000000000000000000000000012'), node6, 17, h.udp6(peer6, node6, 40011, 53, data))))
    # No-routing: to and from an address of the peer that is not its own, on the leaked route too
    seed('routed.bin', packet(OUT | PROFILED, h.ipv4(node, [10, 9, 0, 5], 17, h.udp(node, [10, 9, 0, 5], 40020, 53, data))),
         packet(IN | LEAKED, h.ipv4([10, 9, 0, 5], node, 17, h.udp([10, 9, 0, 5], node, 40021, 53, data))))
    # The privacy filter, an echo each way; a next hop that the tables do not have; no IP packet
    seed('echo.bin', packet(OUT | PROFILED, h.ipv4(node, peer, 1, h.icmp4(8, 0, 0x50520001, data))),
         packet(IN | PROFILED, h.ipv4(peer, node, 1, h.icmp4(8, 0, 0x50520002, data))))
    seed('no_hop.bin', packet(IN | NO_HOP, tcp(peer, node, 0x02)))
    seed('not_ip.bin', packet(OUT | PROFILED, b'\x50' + bytes(39)), packet(IN | PLAIN, b''))
