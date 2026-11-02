# fuzz_routed.py
# Seeds of fuzz_routed (src/fuzz/fuzz_routed.c): the routed networks of the server role of the Node module
# (src/Cedar/NodeRouted.c; CORE-S6-1 #80), on the network 198.18.81.0/24 and fd81:a::/64 with the gateways 198.18.81.1 and
# fd81:a::1. The first byte of a seed, modulo 3, picks what follows: 0, a frame that the host sends out of the KM-TEST adapter
# of the network, which NodeRoutedParseFrame reads; 1, an IP packet of a member, which NodeRoutedFrame takes into a frame for
# the host; 2, the Routed setting as text, which NodeRoutedParseSetting reads for the network lab.
#
# make_seeds.py runs make_seeds(h), h being make_seeds.py itself with write_seed and the packet helpers.

import struct

# The MAC addresses of the fuzz target: the adapter, and the member side of its port, which has the last bit flipped
ADAPTER = bytes([0x02, 0x52, 0x4f, 0x55, 0x54, 0x45])
MEMBER = bytes([0x02, 0x52, 0x4f, 0x55, 0x54, 0x44])
BROADCAST = b'\xff' * 6


def arp(op, sender_mac, sender_ip, target_mac, target_ip):
    return struct.pack('>HHBBH', 1, 0x0800, 6, 4, op) + sender_mac + bytes(sender_ip) + target_mac + bytes(target_ip)


def nd(h, src, dst, icmp_type, target, options):
    # A neighbor discovery message of IPv6: hop limit 255, ICMPv6 with the target after its reserved word
    msg = h.icmp6(src, dst, icmp_type, 0, 0, bytes(target) + options)
    return struct.pack('>IHBB', 6 << 28, len(msg), 58, 255) + bytes(src) + bytes(dst) + msg


def make_seeds(h):
    gw4 = [198, 18, 81, 1]
    member4 = [198, 18, 81, 10]
    other4 = [198, 18, 82, 10]
    gw6 = [0xfd, 0x81, 0, 0x0a] + [0] * 11 + [1]
    member6 = [0xfd, 0x81, 0, 0x0a] + [0] * 11 + [0x10]
    other6 = [0xfd, 0x81, 0, 0x0b] + [0] * 11 + [0x10]
    unspecified = [0] * 16
    solicited = [0xff, 0x02] + [0] * 9 + [1, 0xff, 0, 0, 0x10]
    solicited_mac = bytes([0x33, 0x33, 0xff, 0, 0, 0x10])
    source_option = bytes([1, 1]) + ADAPTER
    payload = b'ranz-routed'

    def frame(name, data):
        h.write_seed('fuzz_routed', name, b'\x00' + data)

    def packet(name, data):
        h.write_seed('fuzz_routed', name, b'\x01' + data)

    def setting(name, text):
        h.write_seed('fuzz_routed', name, b'\x02' + text.encode('ascii'))

    # ARP of the host: a request for a member, broadcast and unicast; one for the gateway, as its own probe; one for an address
    # of another network; a reply
    frame('arp_member.bin', h.eth(BROADCAST, ADAPTER, 0x0806, arp(1, ADAPTER, gw4, b'\0' * 6, member4)))
    frame('arp_unicast.bin', h.eth(MEMBER, ADAPTER, 0x0806, arp(1, ADAPTER, gw4, MEMBER, member4)))
    frame('arp_gateway.bin', h.eth(BROADCAST, ADAPTER, 0x0806, arp(1, ADAPTER, gw4, b'\0' * 6, gw4)))
    frame('arp_other.bin', h.eth(BROADCAST, ADAPTER, 0x0806, arp(1, ADAPTER, gw4, b'\0' * 6, other4)))
    frame('arp_reply.bin', h.eth(MEMBER, ADAPTER, 0x0806, arp(2, ADAPTER, gw4, MEMBER, member4)))
    frame('arp_short.bin', h.eth(BROADCAST, ADAPTER, 0x0806, arp(1, ADAPTER, gw4, b'\0' * 6, member4)[:27]))

    # IP of the host to the member side: IPv4 routed from another network, with the padding of a short frame, and IPv6; to the
    # broadcast address; a total length past the frame; a short frame
    frame('ipv4_member.bin', h.eth(MEMBER, ADAPTER, 0x0800, h.ipv4(other4, member4, 17, h.udp(other4, member4, 40001, 40002, payload))))
    frame('ipv4_padded.bin', h.eth(MEMBER, ADAPTER, 0x0800, h.ipv4(other4, member4, 17, h.udp(other4, member4, 40001, 40002, b''))) + bytes(18))
    frame('ipv6_member.bin', h.eth(MEMBER, ADAPTER, 0x86dd, h.ipv6(other6, member6, 17, h.udp6(other6, member6, 40003, 40004, payload))))
    frame('ipv4_broadcast.bin', h.eth(BROADCAST, ADAPTER, 0x0800, h.ipv4(gw4, [198, 18, 81, 255], 17, h.udp(gw4, [198, 18, 81, 255], 137, 137, payload))))
    long_total = bytearray(h.ipv4(other4, member4, 17, h.udp(other4, member4, 40001, 40002, payload)))
    long_total[2:4] = struct.pack('>H', 1400)
    frame('ipv4_total_past.bin', h.eth(MEMBER, ADAPTER, 0x0800, bytes(long_total)))
    frame('short.bin', h.eth(MEMBER, ADAPTER, 0x0800, b'')[:13])

    # Neighbor Solicitations of the host: for a member, multicast with its source link-layer address option, and unicast
    # without one; of the duplicate address detection of the gateway; for the gateway; for an address of another network;
    # one with an option of length 0
    frame('ns_member.bin', h.eth(solicited_mac, ADAPTER, 0x86dd, nd(h, gw6, solicited, 135, member6, source_option)))
    frame('ns_unicast.bin', h.eth(MEMBER, ADAPTER, 0x86dd, nd(h, gw6, member6, 135, member6, b'')))
    frame('ns_dad.bin', h.eth(solicited_mac, ADAPTER, 0x86dd, nd(h, unspecified, solicited, 135, gw6, b'')))
    frame('ns_gateway.bin', h.eth(solicited_mac, ADAPTER, 0x86dd, nd(h, gw6, solicited, 135, gw6, source_option)))
    frame('ns_other.bin', h.eth(solicited_mac, ADAPTER, 0x86dd, nd(h, gw6, solicited, 135, other6, source_option)))
    frame('ns_zero_option.bin', h.eth(solicited_mac, ADAPTER, 0x86dd, nd(h, gw6, solicited, 135, member6, bytes([1, 0]) + ADAPTER)))
    frame('na.bin', h.eth(MEMBER, ADAPTER, 0x86dd, nd(h, gw6, member6, 136, gw6, bytes([2, 1]) + ADAPTER)))

    # Packets of members: IPv4 and IPv6 from a member, from an address of another network, from the gateway; no IP version; a
    # total length past the packet; a header length under 20; a packet of 19 bytes
    packet('member4.bin', h.ipv4(member4, other4, 17, h.udp(member4, other4, 40001, 40002, payload)))
    packet('member4_empty.bin', h.ipv4(member4, other4, 17, b''))
    packet('member6.bin', h.ipv6(member6, other6, 17, h.udp6(member6, other6, 40003, 40004, payload)))
    packet('spoofed4.bin', h.ipv4(other4, member4, 17, h.udp(other4, member4, 40005, 40006, payload)))
    packet('spoofed6.bin', h.ipv6(other6, member6, 17, h.udp6(other6, member6, 40007, 40008, payload)))
    packet('gateway4.bin', h.ipv4(gw4, other4, 17, h.udp(gw4, other4, 40009, 40010, payload)))
    packet('version5.bin', bytes([0x50]) + bytes(39))
    past = bytearray(h.ipv4(member4, other4, 17, h.udp(member4, other4, 40011, 40012, payload)))
    past[2:4] = struct.pack('>H', 1500)
    packet('total_past.bin', bytes(past))
    short_header = bytearray(h.ipv4(member4, other4, 17, h.udp(member4, other4, 40013, 40014, payload)))
    short_header[0] = 0x44
    packet('header_short.bin', bytes(short_header))
    packet('short.bin', h.ipv4(member4, other4, 17, b'')[:19])

    # The Routed setting: lab with an IPv4 and an IPv6 gateway and NAT; lab named in capitals; only another network; a /31; a
    # loopback, a link-local and a multicast gateway; a gateway without its prefix length; five gateways; no array; no JSON
    setting('lab.bin', '{"networks": [{"name": "lab", "gateways": ["198.18.81.1/24", "fd81:a::1/64"], "nat": true}]}')
    setting('lab_capitals.bin', '{"networks": [{"name": "LAB", "gateways": ["10.81.0.1/16"]}]}')
    setting('other.bin', '{"networks": [{"name": "other", "gateways": ["198.18.82.1/24"]}]}')
    setting('slash31.bin', '{"networks": [{"name": "lab", "gateways": ["198.18.81.1/31"]}]}')
    setting('loopback.bin', '{"networks": [{"name": "lab", "gateways": ["127.0.0.1/8"]}]}')
    setting('link_local.bin', '{"networks": [{"name": "lab", "gateways": ["fe80::1/64"]}]}')
    setting('multicast.bin', '{"networks": [{"name": "lab", "gateways": ["224.0.0.1/24"]}]}')
    setting('no_length.bin', '{"networks": [{"name": "lab", "gateways": ["198.18.81.1"]}]}')
    setting('five.bin', '{"networks": [{"name": "lab", "gateways": ["10.1.0.1/24", "10.2.0.1/24", "10.3.0.1/24", "10.4.0.1/24", "10.5.0.1/24"]}]}')
    setting('not_array.bin', '{"networks": {"name": "lab", "gateways": ["198.18.81.1/24"]}}')
    setting('not_json.bin', 'networks: lab 198.18.81.1/24')
