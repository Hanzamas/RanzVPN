# Seeds of fuzz_frontdoor, run by make_seeds.py (h is that module).
#
# Front door of the new core (src/Core/FrontDoorHello.c FrontDoorParseHello, FrontDoorRoute, FrontDoorHandoffDecode): the
# first bytes of a connection to TCP 443, a ClientHello in one record or in many, a signature, a plain HTTP request and
# the start of a TLS record; and the handoff message that an owner process reads, FRONT_DOOR_HANDOFF: the magic "RFD1",
# its size and a WSAPROTOCOL_INFOW of 628 bytes, whose address family, socket type and protocol are at 76, 88 and 92.
# fuzz_frontdoor.c routes by the owner table of coretest frontdoor.

import struct


def alpn_extension(protocols):
    names = b''.join(bytes([len(p)]) + p for p in protocols)
    data = struct.pack('>H', len(names)) + names
    return struct.pack('>HH', 16, len(data)) + data


def tls_records(hello, fragment):
    # A ClientHello made by client_hello, its handshake message cut into records of fragment bytes
    message = hello[5:]
    return b''.join(b'\x16\x03\x01' + struct.pack('>H', len(message[i:i + fragment])) + message[i:i + fragment]
                    for i in range(0, len(message), fragment))


def make_seeds(h):
    def seed(name, data):
        h.write_seed('fuzz_frontdoor', name, data)

    versions = struct.pack('>HHB', 43, 3, 2) + b'\x03\x04'
    controller = h.client_hello(versions + h.sni_extension(b'node.frontdoor.test') +
                                alpn_extension([b'h2', b'http/1.1']))
    seed('hello_alpn_h2.bin', controller)
    seed('hello_records_of_7.bin', tls_records(controller, 7))
    seed('hello_web_ui.bin', h.client_hello(versions + h.sni_extension(b'eu.admin.frontdoor.test')))
    seed('hello_node.bin', h.client_hello(versions))
    seed('hello_absent_owner.bin', h.client_hello(versions + alpn_extension([b'ranz-absent/1'])))
    seed('hello_cut.bin', controller[:40])
    seed('signature.txt', b'RANZ-FRONT-DOOR-TEST and then the owner\'s own protocol')
    seed('http.txt', b'GET / HTTP/1.1\r\nHost: admin.frontdoor.test\r\n\r\n')
    seed('record_start.bin', b'\x16\x03\x01')
    info = bytearray(628)
    info[76:80] = struct.pack('<i', 2)
    info[88:92] = struct.pack('<i', 1)
    info[92:96] = struct.pack('<i', 6)
    seed('handoff.bin', struct.pack('<II', 0x31444652, 8 + len(info)) + bytes(info))
