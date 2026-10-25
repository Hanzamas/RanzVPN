# Seeds of fuzz_nodedns, run by make_seeds.py (h is that module).
#
# Stub resolver of overlay DNS (src/Cedar/NodeDns.c NodeDnsAnswer): the first byte picks the zone of fuzz_nodedns.c (bit 0:
# the VRF of 4via6, bit 1: the suffix corp in place of red.ranz.internal), then the query as the DNS client of Windows
# sends it to UDP port 53 of the node's address in the VRF: a name of the zone for A, AAAA and ANY, in mixed case, the
# name with the most addresses, a name under the suffix that the zone does not have, an empty non-terminal, the suffix
# itself for its SOA, a name outside the suffix, a query with the OPT record of EDNS, a response, an opcode other than
# QUERY, a compression pointer in the question, a cut question and a class other than IN.

import struct


def name(text):
    return b''.join(bytes([len(label)]) + label.encode() for label in text.split('.') if label) + b'\0'


def query(text, qtype=1, qid=0x5244, flags=0x0100, qclass=1, extra=b'', arcount=0):
    return struct.pack('>HHHHHH', qid, flags, 1, 0, 0, arcount) + name(text) + struct.pack('>HH', qtype, qclass) + extra


# The OPT record of EDNS0 (RFC 6891): the root, type 41, a UDP size of 1232, no flags and no data
OPT = b'\0' + struct.pack('>HHIH', 41, 1232, 0, 0)


def make_seeds(h):
    def seed(file_name, data):
        h.write_seed('fuzz_nodedns', file_name, data)

    seed('a.bin', b'\x00' + query('fileserver.red.ranz.internal'))
    seed('aaaa.bin', b'\x00' + query('fileserver.red.ranz.internal', 28))
    seed('any_mixed_case.bin', b'\x00' + query('FileServer.Red.RANZ.internal', 255))
    seed('many.bin', b'\x00' + query('many.red.ranz.internal', 255))
    seed('via6_aaaa.bin', b'\x01' + query('fileserver.red.ranz.internal', 28))
    seed('via6_a.bin', b'\x01' + query('node-s.red.ranz.internal'))
    seed('nxdomain.bin', b'\x00' + query('nothing.red.ranz.internal'))
    seed('empty_non_terminal.bin', b'\x00' + query('hq.red.ranz.internal'))
    seed('apex_soa.bin', b'\x00' + query('red.ranz.internal', 6))
    seed('outside.bin', b'\x00' + query('www.example.com'))
    seed('edns.bin', b'\x00' + query('files.hq.red.ranz.internal', arcount=1, extra=OPT))
    seed('one_label_suffix.bin', b'\x02' + query('fileserver.corp'))
    seed('response.bin', b'\x00' + query('fileserver.red.ranz.internal', flags=0x8180))
    seed('notify.bin', b'\x00' + query('red.ranz.internal', 6, flags=0x2000))
    pointer = struct.pack('>HHHHHH', 0x5244, 0x0100, 1, 0, 0, 0) + b'\x0afileserver\xc0\x0c' + struct.pack('>HH', 1, 1)
    seed('pointer.bin', b'\x00' + pointer)
    seed('cut.bin', b'\x00' + query('fileserver.red.ranz.internal')[:20])
    seed('class_chaos.bin', b'\x00' + query('fileserver.red.ranz.internal', 16, qclass=3))
