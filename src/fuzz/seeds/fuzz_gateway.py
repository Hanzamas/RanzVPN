# fuzz_gateway.py
# Seeds of fuzz_gateway (src/fuzz/fuzz_gateway.c): the gateway HA of the Node module (src/Cedar/NodeGateway.c; SDN-19 #195).
# The first byte of a seed, modulo 3, picks what follows: 0, a control record of the Noise session between two peers,
# which NodeGatewayParseProbe reads as a probe (kind 1) or its answer (kind 2), each the kind, the sequence in 4 bytes and
# the time of the prober in 8 bytes, big-endian; 1, an IP packet of the host, whose flow hash NodeGatewayFlowHash takes over
# its addresses, its protocol and the ports of TCP, UDP and SCTP, and over the flow label of IPv6; 2, a record of the datagram
# path of the peer agent, which NodeGatewayParseDatagram reads as a control record when it starts with the VRF tag of no VRF,
# 0, and the kind 0xFF, a probe or its answer after them (SDN-19-R1 #507), and as a data record otherwise.
#
# make_seeds.py runs make_seeds(h), h being make_seeds.py itself with write_seed and the packet helpers.

import struct


def probe(kind, sequence, time):
    return bytes([kind]) + struct.pack('>IQ', sequence, time)


def ipv6(src, dst, next_header, payload, label=0x12345):
    return struct.pack('>IHBB16s16s', (6 << 28) | label, len(payload), next_header, 64, bytes(src), bytes(dst)) + payload


def make_seeds(h):
    a, b = [10, 10, 0, 1], [192, 168, 1, 7]
    a6 = [0xfd, 0x10] + [0] * 13 + [1]
    b6 = [0xfd, 0x10] + [0] * 13 + [7]

    def record(name, data):
        h.write_seed('fuzz_gateway', name, b'\x00' + data)

    def packet(name, data):
        h.write_seed('fuzz_gateway', name, b'\x01' + data)

    def datagram(name, data):
        h.write_seed('fuzz_gateway', name, b'\x02' + data)

    # A probe and its answer; a record of another kind, one byte short and one byte long, and an empty one
    record('probe.bin', probe(1, 7, 123456789))
    record('answer.bin', probe(2, 7, 123456789))
    record('other_kind.bin', probe(3, 7, 123456789))
    record('short.bin', probe(1, 7, 123456789)[:12])
    record('long.bin', probe(2, 7, 123456789) + b'\x00')
    record('empty.bin', b'')

    # The datagram path: a probe and its answer behind the VRF tag of no VRF and the kind of a control record; a control record
    # that is no probe, and one without its probe; a record of the VRF tag of no VRF and another kind, a later frame version of
    # the data records; a data record of VRF 10; and a VRF tag alone
    control = struct.pack('>I', 0) + b'\xff'
    datagram('dgram_probe.bin', control + probe(1, 9, 123456789))
    datagram('dgram_answer.bin', control + probe(2, 9, 123456789))
    datagram('dgram_other_kind.bin', control + probe(3, 9, 123456789))
    datagram('dgram_bare.bin', control)
    datagram('dgram_version.bin', struct.pack('>I', 0) + b'\x01' + bytes(19))
    datagram('dgram_data.bin', struct.pack('>I', 10) + h.ipv4(a, b, 17, h.udp(a, b, 40006, 53, b'ranz-gateway')))
    datagram('dgram_tag.bin', struct.pack('>I', 0))

    # IPv4: UDP and TCP with their ports, a fragment without them, ICMP, a header length past the packet and one under 20
    payload = b'ranz-gateway'
    packet('udp4.bin', h.ipv4(a, b, 17, h.udp(a, b, 40000, 53, payload)))
    packet('tcp4.bin', h.ipv4(a, b, 6, h.tcp(a, b, 40001, 443, 1, 0, 0x02, b'')))
    fragment = bytearray(h.ipv4(a, b, 17, h.udp(a, b, 40002, 53, payload)))
    fragment[6] = 0x20
    packet('fragment4.bin', bytes(fragment))
    echo = struct.pack('>BBHHH', 8, 0, 0, 1, 1) + payload
    packet('icmp4.bin', h.ipv4(a, b, 1, echo))
    long_header = bytearray(h.ipv4(a, b, 17, h.udp(a, b, 40003, 53, payload)))
    long_header[0] = 0x4F
    packet('header_past.bin', bytes(long_header[:40]))
    short_header = bytearray(h.ipv4(a, b, 17, h.udp(a, b, 40004, 53, payload)))
    short_header[0] = 0x44
    packet('header_short.bin', bytes(short_header))

    # IPv6: UDP with its flow label, a hop-by-hop options header, which hashes without ports, and one byte short of a header
    udp6 = struct.pack('>HHHH', 40005, 53, 8 + len(payload), 0) + payload
    packet('udp6.bin', ipv6(a6, b6, 17, udp6))
    packet('hop_by_hop6.bin', ipv6(a6, b6, 0, bytes([17, 0, 1, 4, 0, 0, 0, 0]) + udp6))
    packet('short6.bin', ipv6(a6, b6, 17, udp6)[:39])

    # Neither IPv4 nor IPv6
    packet('version5.bin', bytes([0x50]) + bytes(39))
