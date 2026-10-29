# fuzz_geneve.py
# Seeds of fuzz_geneve (src/fuzz/fuzz_geneve.c): Geneve in the VXLAN module of the new core (src/Core/VxlanGeneve.c
# VxlanParseGeneve and Vxlan.c VxlanInput, RFC 8926; SDN-71 #347). A seed is a datagram of a VTEP of Geneve: the fixed
# header of 8 bytes (the version in the two high bits of byte 0 and the option length in words in its six low bits, the
# O bit 0x80 and the C bit 0x40 of byte 1 with six reserved bits, the protocol, the VNI in 3 bytes, a reserved byte),
# then the options, each a header of 4 bytes (the class, the type, whose high bit is the critical bit, 3 reserved bits
# and the length of the data in words) and its data, then an Ethernet frame. fuzz_geneve.c carries VNI 6001 and VNI
# 16777215 (0xFFFFFF); VNI 7777 is none of its VNIs.
#
# make_seeds.py runs make_seeds(h), h being make_seeds.py itself with write_seed and the packet helpers.

import struct


def option(cls, typ, data=b'', reserved=0):
    # One option: its class, its type, the reserved bits and the length of its data in words, then the data
    return struct.pack('>HBB', cls, typ, (reserved << 5) | (len(data) // 4)) + data


def geneve(vni, frame, options=b'', flags=0x00, protocol=0x6558, version=0, words=None, last=0):
    # The fixed header with the option length of the options (or words), then the options and the frame
    words = len(options) // 4 if words is None else words
    return (bytes([(version << 6) | words, flags]) + struct.pack('>H', protocol) + struct.pack('>I', vni)[1:] +
            bytes([last]) + options + frame)


def make_seeds(h):
    a, b = [10, 0, 0, 1], [10, 0, 0, 2]
    echo = struct.pack('>BBHHH', 8, 0, 0, 0x4242, 1) + b'ranz-geneve-ping'
    echo = echo[:2] + struct.pack('>H', h.csum(echo)) + echo[4:]
    untagged = h.eth(h.MAC_B, h.MAC_A, 0x0800, h.ipv4(a, b, 1, echo, 7))
    tagged = h.eth(h.MAC_B, h.MAC_A, 0x8100, struct.pack('>HH', 10, 0x0800) + h.ipv4(a, b, 1, echo, 8))
    arp = struct.pack('>HHBBH', 1, 0x0800, 6, 4, 1) + h.MAC_A + bytes(a) + b'\0' * 6 + bytes(b)
    ovn = option(0x0102, 0x01, b'\xde\xad\xbe\xef')

    def seed(name, data):
        h.write_seed('fuzz_geneve', name, data)

    # Without options: an untagged frame, an 802.1Q-tagged one, an ARP request on the largest VNI, a VNI that the module
    # does not carry, and every reserved bit set, which a receiver ignores
    seed('untagged.bin', geneve(6001, untagged))
    seed('vlan_tagged.bin', geneve(6001, tagged))
    seed('vni_max_arp.bin', geneve(0xFFFFFF, h.eth(h.BROADCAST, h.MAC_A, 0x0806, arp)))
    seed('unknown_vni.bin', geneve(7777, untagged))
    seed('reserved_bits.bin', geneve(6001, untagged, flags=0x3F, last=0xFF))
    # Options that are not critical: OVN's, one with its reserved bits set, the largest that an option holds (124 bytes
    # of data); and the longest options, 63 words as 63 options without data
    seed('options.bin', geneve(6001, untagged, ovn + option(0xFF00, 0x7F, reserved=7) + option(0x0104, 0x05, bytes(range(124)))))
    seed('options_63.bin', geneve(6001, untagged, b''.join(option(0xFF00 + i, i) for i in range(63))))
    # A critical option that the module does not know, after one that is not critical with the C bit, and alone without
    # it; a control message, the O bit
    seed('critical.bin', geneve(6001, untagged, ovn + option(0xFF01, 0x81), flags=0x40))
    seed('critical_without_c.bin', geneve(6001, untagged, option(0xFF01, 0x81)))
    seed('control.bin', geneve(6001, untagged, flags=0x80))
    # No datagram to take: version 1, an option whose data runs past the option length, an option length past the end
    # of the datagram, an IPv4 packet behind the protocol 0x0800, a frame one byte short of an Ethernet header
    seed('version_1.bin', geneve(6001, untagged, version=1))
    seed('option_past_length.bin', geneve(6001, untagged, option(0xFF00, 0x01, bytes(8)), words=2))
    seed('length_past_datagram.bin', geneve(6001, untagged[:20], words=63))
    seed('ipv4_payload.bin', geneve(6001, h.ipv4(a, b, 1, echo, 9), protocol=0x0800))
    seed('short.bin', geneve(6001, untagged[:13]))
    # The option of the source group (SDN-87 #386; Vxlan.h): the class 0xFFF0 of Experimental Use, the type 1 with the
    # critical bit clear and 16 bytes of data, the group ID, two reserved bytes, the tag set and the group generation of
    # the sender. Alone, after OVN's, with the critical bit set, which the module does not know, and with data of another
    # length, which is no such option
    source_group = struct.pack('>HHQI', 3, 0, 0x4, 1)
    seed('source_group.bin', geneve(6001, untagged, option(0xFFF0, 0x01, source_group)))
    seed('source_group_after_ovn.bin', geneve(6001, untagged, ovn + option(0xFFF0, 0x01, source_group)))
    seed('source_group_critical.bin', geneve(6001, untagged, option(0xFFF0, 0x81, source_group)))
    seed('source_group_short.bin', geneve(6001, untagged, option(0xFFF0, 0x01, source_group[:4])))
