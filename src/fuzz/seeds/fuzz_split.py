# fuzz_split.py
# Seeds of fuzz_split (src/fuzz/fuzz_split.c): TCP splitting of the Node module (src/Cedar/NodeSplit.c; CORE-P2-3 #94). The first
# byte of a seed, modulo 2, picks what follows: 0, a control record of a split flow, which NodeSplitParseRecord reads: the kind
# (0x20 OPEN, 0x21 ANSWER, 0x22 DATA, 0x23 WINDOW, 0x24 FIN, 0x25 RESET), the flags (0x01: the sender opened the flow), the id
# of the flow in 4 bytes and what the kind carries, big-endian; 1, an IP packet of the host, whose TCP SYN NodeSplitReset
# answers with a reset.
#
# make_seeds.py runs make_seeds(h), h being make_seeds.py itself with write_seed and the packet helpers.

import struct


def header(kind, from_opener, flow):
    return bytes([kind, 1 if from_opener else 0]) + struct.pack('>I', flow)


def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def tcp(src, dst, sport, dport, flags, seq=0x52414E5A, options=b''):
    offset = (20 + len(options)) // 4
    segment = struct.pack('>HHIIBBHHH', sport, dport, seq, 0, offset << 4, flags, 65535, 0, 0) + options
    pseudo = bytes(src) + bytes(dst) + struct.pack('>BBH', 0, 6, len(segment))
    c = checksum(pseudo + segment)
    segment = segment[:16] + struct.pack('>H', c) + segment[18:]
    total = 20 + len(segment)
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, total, 0, 0, 64, 6, 0, bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('>H', checksum(ip)) + ip[12:]
    return ip + segment


def make_seeds(h):
    a, b = [198, 19, 81, 2], [198, 19, 81, 1]

    def record(name, data):
        h.write_seed('fuzz_split', name, b'\x00' + data)

    def packet(name, data):
        h.write_seed('fuzz_split', name, b'\x01' + data)

    # Each kind, as a node writes it
    record('open.bin', header(0x20, True, 1) + struct.pack('>I4sH4sHI', 401, bytes(a), 50000, bytes(b), 7001, 262144))
    record('answer_ok.bin', header(0x21, False, 1) + struct.pack('>BI', 0, 262144))
    record('answer_refused.bin', header(0x21, False, 2) + struct.pack('>BI', 1, 0))
    record('data.bin', header(0x22, True, 1) + b'ranz split data')
    record('data_back.bin', header(0x22, False, 1) + bytes(range(256)) * 4)
    record('window.bin', header(0x23, False, 1) + struct.pack('>I', 65536))
    record('fin.bin', header(0x24, True, 1))
    record('reset.bin', header(0x25, False, 1))
    # Malformed: an OPEN of the other end, one byte short, an unknown status, empty data, an unknown flag and kind, a probe of
    # the gateway HA
    record('open_wrong_end.bin', header(0x20, False, 1) + struct.pack('>I4sH4sHI', 401, bytes(a), 50000, bytes(b), 7001, 262144))
    record('open_short.bin', header(0x20, True, 1) + struct.pack('>I4sH4sH', 401, bytes(a), 50000, bytes(b), 7001) + b'\x00\x00\x00')
    record('answer_status.bin', header(0x21, False, 1) + struct.pack('>BI', 9, 0))
    record('data_empty.bin', header(0x22, True, 1))
    record('flags.bin', bytes([0x24, 0x80]) + struct.pack('>I', 1))
    record('kind.bin', header(0x26, True, 1))
    record('probe.bin', bytes([1]) + struct.pack('>IQ', 7, 123456789))
    record('empty.bin', b'')

    # The SYN of the host, one with options, a segment that is no SYN, a UDP datagram and a fragment
    packet('syn.bin', tcp(a, b, 50000, 7001, 0x02))
    packet('syn_options.bin', tcp(a, b, 50001, 7001, 0x02, options=b'\x02\x04\x05\x50\x01\x03\x03\x08\x01\x01\x04\x02'))
    packet('ack.bin', tcp(a, b, 50000, 7001, 0x10))
    packet('udp.bin', struct.pack('>BBHHHBBH4s4s', 0x45, 0, 28, 0, 0, 64, 17, 0, bytes(a), bytes(b)) + struct.pack('>HHHH', 5000, 7009, 8, 0))
    packet('fragment.bin', tcp(a, b, 50000, 7001, 0x02)[:6] + b'\x20\x00' + tcp(a, b, 50000, 7001, 0x02)[8:])
    packet('short.bin', tcp(a, b, 50000, 7001, 0x02)[:30])
