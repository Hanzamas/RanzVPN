# fuzz_tagmac.py
# Seeds of fuzz_tagmac (src/fuzz/fuzz_tagmac.c): the datagrams of Geneve of a link of a VRF in the tag mode hmac (src/Cedar/
# NodeTagMac.c; SDN-88 #387). A datagram is the Geneve header, the option of the authenticated source group (the class 0xfff0,
# the type 1, 28 bytes of data: the group ID, the ID of the key, the tag set, the group generation, the timestamp and the MAC),
# the Ethernet header of a frame of a link and the IP packet. The MAC is the first 8 bytes of HMAC-SHA256 under the key, over
# the VNI 5101, the fields of the option before the MAC and the inner IP and L4 headers of the packet. The target holds key 1,
# the bytes 0x00 to 0x1f, and key 2, the bytes 0x40 to 0x5f, and its clock is 0x65000000.
#
# make_seeds.py runs make_seeds(h), h being make_seeds.py itself with write_seed and the packet helpers.

import hashlib
import hmac
import struct

VNI = 5101
NOW = 0x65000000
KEYS = {1: bytes(range(0x00, 0x20)), 2: bytes(range(0x40, 0x60))}
MAC = bytes([0x02, 0x52, 0x5A, 0x00, 0x00, 0x03])


def headers(packet):
    # The bytes of the inner IP and L4 headers that the MAC covers, as NodeTagMacHeaders gives them
    if not packet:
        return 0
    later, version = False, packet[0] >> 4
    if version == 4:
        ihl = (packet[0] & 0x0F) * 4
        if len(packet) < 20 or ihl < 20 or ihl > len(packet):
            return len(packet)
        off, nxt = ihl, packet[9]
        later = (struct.unpack('>H', packet[6:8])[0] & 0x1FFF) != 0
    elif version == 6:
        if len(packet) < 40:
            return len(packet)
        off, nxt = 40, packet[6]
        for _ in range(8):
            if later:
                break
            if nxt == 44:
                if len(packet) - off < 8:
                    return len(packet)
                later = (struct.unpack('>H', packet[off + 2:off + 4])[0] & 0xFFF8) != 0
                nxt, off = packet[off], off + 8
            elif nxt in (0, 43, 60):
                if len(packet) - off < 2:
                    return len(packet)
                length = (packet[off + 1] + 1) * 8
                if length > len(packet) - off:
                    return len(packet)
                nxt, off = packet[off], off + length
            else:
                break
    else:
        return 0
    l4 = 0
    if not later and nxt == 6:
        l4 = 20
        if len(packet) - off > 12 and (packet[off + 12] >> 4) * 4 > l4:
            l4 = (packet[off + 12] >> 4) * 4
    elif not later and nxt in (17, 1, 58):
        l4 = 8
    return len(packet) if l4 > len(packet) - off else off + l4


def mac(key, group, key_id, tags, generation, time, packet):
    fields = struct.pack('>IHHQII', VNI, group, key_id, tags, generation, time)
    return hmac.new(key, fields + packet[:headers(packet)], hashlib.sha256).digest()[:8]


def datagram(packet, option=b''):
    # The Geneve header with the length of the option in words, the option, and the frame of a link
    ethertype = 0x86DD if packet and packet[0] >> 4 == 6 else 0x0800
    header = struct.pack('>BBH', len(option) // 4, 0, 0x6558) + struct.pack('>I', VNI)[1:] + b'\x00'
    return header + option + MAC + MAC + struct.pack('>H', ethertype) + packet


def option(group, key_id, tags, generation, time, tag):
    # The option of the authenticated source group with the MAC tag
    return struct.pack('>HBBHHQII', 0xFFF0, 0x01, 7, group, key_id, tags, generation, time) + tag


def signed(packet, group, key_id, tags, generation, time, key=None):
    # The datagram of the packet with the option of the source group under the key of key_id, or under key
    tag = mac(key if key is not None else KEYS[key_id], group, key_id, tags, generation, time, packet)
    return datagram(packet, option(group, key_id, tags, generation, time, tag))


def make_seeds(h):
    def seed(name, data):
        h.write_seed('fuzz_tagmac', name, data)

    a, b = [10, 0, 0, 1], [10, 0, 0, 2]
    a6 = bytes.fromhex('fd000000000000000000000000000001')
    b6 = bytes.fromhex('fd000000000000000000000000000002')
    udp4 = h.ipv4(a, b, 17, h.udp(a, b, 20000, 9000, bytes(range(72))))
    syn4 = h.ipv4(a, b, 6, h.tcp_syn(a, b, 40000, 443, 1, bytes([2, 4, 5, 0xB4, 1, 3, 3, 7])))
    udp6 = h.ipv6(a6, b6, 17, h.udp6(a6, b6, 20001, 9000, b'ranz-tag-mac'), bytes([17, 0, 1, 4, 0, 0, 0, 0]))
    fragment = bytes(udp4[:6]) + struct.pack('>H', 0x00B9) + bytes(udp4[8:])

    # MACs that a node of the VRF takes: under key 2, the key to send with, and key 1, the other one, inside the window
    seed('key2_udp.bin', signed(udp4, 3, 2, 0x4, 5, NOW))
    seed('key1_tcp_syn.bin', signed(syn4, 1, 1, 0x1, 1, NOW - 10))
    seed('key2_udp6_hop_by_hop.bin', signed(udp6, 2, 2, 0x2, 7, NOW + 30))
    seed('key2_fragment.bin', signed(fragment, 65535, 2, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF, NOW - 30))
    # MACs that it does not take: a timestamp outside the window, a key that it does not hold, a key of the right ID that is
    # not its key, a forged MAC, and the option of trusted-underlay, without a MAC
    seed('stale.bin', signed(udp4, 3, 2, 0x4, 5, NOW - 31))
    seed('unknown_key.bin', signed(udp4, 3, 9, 0x4, 5, NOW, KEYS[2]))
    seed('wrong_key.bin', signed(udp4, 3, 2, 0x4, 5, NOW, bytes(32)))
    seed('forged.bin', datagram(udp4, option(1, 2, 0x1, 5, NOW, bytes(8))))
    seed('plain_option.bin', datagram(udp4, struct.pack('>HBBHHQI', 0xFFF0, 0x01, 4, 1, 0, 0x1, 5)))
    # No option, a packet that ends inside its headers, and IPv6 behind many extension headers
    seed('no_option.bin', datagram(udp4))
    seed('short_packet.bin', signed(udp4[:24], 3, 2, 0x4, 5, NOW))
    extensions = bytes([60, 0, 1, 4, 0, 0, 0, 0]) * 3 + bytes([17, 0, 1, 4, 0, 0, 0, 0])
    many = h.ipv6(a6, b6, 17, h.udp6(a6, b6, 1, 2, b'x'), bytes([60]) + extensions[1:])
    seed('ipv6_extensions.bin', signed(many, 4, 1, 0x8, 2, NOW))
