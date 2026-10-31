# make_seeds.py
# Writes the seed corpus of the libFuzzer targets into src/fuzz/corpus/<target>/.
# Python standard library only; deterministic (same bytes on every run).
#
# The seeds of the targets up to fuzz_switch are made by the make_<name>_seeds() functions below. A new target has its
# own file src/fuzz/seeds/<target>.py, which defines make_seeds(h) and is run after them, so that no function and no line
# of the main block here is added: h is this module, with write_seed(target, name, data) and the helpers (ipv4, udp,
# eth, der, ...). Files whose name starts with an underscore are not run.
#
# Usage: python -I src/fuzz/make_seeds.py

import base64
import hashlib
import importlib.util
import os
import random
import struct
import sys

CORPUS = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'corpus')

# Non-ASCII sample characters: LATIN SMALL LETTER E WITH ACUTE, CJK "sun"
E_ACUTE = chr(0xE9)
CJK_SUN = chr(0x65E5)


def write_seed(target, name, data):
    directory = os.path.join(CORPUS, target)
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(directory, name), 'wb') as f:
        f.write(data)


# ---------------------------------------------------------------------------
# PACK (Mayaqua/Pack.c WritePack): big-endian UINT counts and sizes
# ---------------------------------------------------------------------------
VALUE_INT, VALUE_DATA, VALUE_STR, VALUE_UNISTR, VALUE_INT64 = 0, 1, 2, 3, 4


def buf_str(s):
    # WriteBufStr: length + 1, then the bytes without terminator
    b = s.encode('ascii')
    return struct.pack('>I', len(b) + 1) + b


def pack_value(vtype, v):
    if vtype == VALUE_INT:
        return struct.pack('>I', v)
    if vtype == VALUE_INT64:
        return struct.pack('>Q', v)
    if vtype == VALUE_DATA:
        return struct.pack('>I', len(v)) + v
    if vtype == VALUE_STR:
        b = v.encode('ascii')
        return struct.pack('>I', len(b)) + b
    if vtype == VALUE_UNISTR:
        b = v.encode('utf-8') + b'\0'      # UTF-8 size includes the terminator
        return struct.pack('>I', len(b)) + b
    raise ValueError(vtype)


def pack(elements):
    out = struct.pack('>I', len(elements))
    for name, vtype, values in elements:
        out += buf_str(name) + struct.pack('>II', vtype, len(values))
        for v in values:
            out += pack_value(vtype, v)
    return out


def make_pack_seeds():
    write_seed('fuzz_pack', 'minimal.bin', pack([('hello', VALUE_INT, [1])]))
    # Shaped like the client's login PACK: every value type, one multi-value element
    write_seed('fuzz_pack', 'login.bin', pack([
        ('method', VALUE_STR, ['login']),
        ('hubname', VALUE_STR, ['DEFAULT']),
        ('username', VALUE_STR, ['fuzz']),
        ('authtype', VALUE_INT, [1]),
        ('secure_password', VALUE_DATA, [bytes(range(20))]),
        ('client_str', VALUE_STR, ['Ranz VPN Client']),
        ('client_ver', VALUE_INT, [502]),
        ('client_build', VALUE_INT, [5187]),
        ('unique_id', VALUE_DATA, [bytes(range(100, 120))]),
        ('max_connection', VALUE_INT, [1]),
        ('use_encrypt', VALUE_INT, [1]),
        ('use_compress', VALUE_INT, [0]),
        ('half_connection', VALUE_INT, [0]),
        ('qos', VALUE_INT, [0]),
        ('client_hostname', VALUE_UNISTR, ['fuzz-host ' + E_ACUTE + CJK_SUN]),
        ('timestamp', VALUE_INT64, [0x0000019A2B3C4D5E]),
        ('ports', VALUE_INT, [443, 992, 5555]),
    ]))


def pack_one_element(vtype, num_value, payload):
    # A PACK of one element "a" that claims num_value values; payload is the bytes that follow
    return struct.pack('>I', 1) + buf_str('a') + struct.pack('>II', vtype, num_value) + payload


def make_pack_bad_seeds():
    # Malformed PACKs the decoder rejects before it allocates (FND-42 #114, vpntest pack_decode_bounds)
    write_seed('fuzz_pack', 'bad_int_count_huge.bin', pack_one_element(VALUE_INT, 262144, b''))
    write_seed('fuzz_pack', 'bad_unknown_type.bin', pack_one_element(7, 1, struct.pack('>I', 0)))
    write_seed('fuzz_pack', 'bad_data_size_huge.bin',
               pack_one_element(VALUE_DATA, 1, struct.pack('>I', 0x10000000) + b'abcd'))
    write_seed('fuzz_pack', 'bad_str_truncated.bin',
               pack_one_element(VALUE_STR, 2, pack_value(VALUE_STR, 'abc') + struct.pack('>I', 10) + b'abc'))


def make_login_seeds():
    # Login PACKs for ParseLoginRequest (fuzz_login, FND-196 #164)
    write_seed('fuzz_login', 'udp_accel_v2.bin', pack([
        ('method', VALUE_STR, ['login']),
        ('hubname', VALUE_STR, ['DEFAULT']),
        ('username', VALUE_STR, ['fuzz']),
        ('authtype', VALUE_INT, [1]),
        ('max_connection', VALUE_INT, [8]),
        ('use_encrypt', VALUE_INT, [1]),
        ('use_compress', VALUE_INT, [1]),
        ('half_connection', VALUE_INT, [1]),
        ('qos', VALUE_INT, [1]),
        ('client_id', VALUE_INT, [123]),
        ('adjust_mss', VALUE_INT, [1300]),
        ('use_udp_acceleration', VALUE_INT, [1]),
        ('udp_acceleration_max_version', VALUE_INT, [2]),
        ('support_hmac_on_udp_acceleration', VALUE_INT, [1]),
        ('support_udp_accel_fast_disconnect_detect', VALUE_INT, [1]),
        ('udp_acceleration_client_key', VALUE_DATA, [bytes(range(20))]),
        ('udp_acceleration_client_key_v2', VALUE_DATA, [bytes(range(128))]),
        ('udp_acceleration_client_ip', VALUE_INT, [0x0100007F]),
        ('udp_acceleration_client_port', VALUE_INT, [40000]),
        ('require_bridge_routing_mode', VALUE_INT, [1]),
        ('unique_id', VALUE_DATA, [bytes(range(100, 120))]),
        ('ClientProductName', VALUE_STR, ['Ranz VPN Client']),
        ('ClientHostname', VALUE_STR, ['fuzz-host']),
        ('ClientIpAddress', VALUE_INT, [0x0100007F]),
    ]))
    write_seed('fuzz_login', 'monitor_ipv6.bin', pack([
        ('hubname', VALUE_STR, ['DEFAULT']),
        ('username', VALUE_STR, ['administrator']),
        ('authtype', VALUE_INT, [0]),
        ('qos', VALUE_INT, [1]),
        ('use_udp_acceleration', VALUE_INT, [1]),
        ('udp_acceleration_client_ip@ipv6_bool', VALUE_INT, [1]),
        ('udp_acceleration_client_ip@ipv6_array', VALUE_DATA, [bytes(16)]),
        ('udp_acceleration_client_ip@ipv6_scope_id', VALUE_INT, [0]),
        ('udp_acceleration_client_port', VALUE_INT, [0]),
        ('require_monitor_mode', VALUE_INT, [1]),
        ('unique_id', VALUE_DATA, [bytes(7)]),
    ]))
    write_seed('fuzz_login', 'no_hubname.bin', pack([
        ('username', VALUE_STR, ['fuzz']),
        ('authtype', VALUE_INT, [1]),
    ]))


# ---------------------------------------------------------------------------
# Configuration (Mayaqua/Cfg.c): text and binary
# ---------------------------------------------------------------------------
TAG_CPYRIGHT = (b'\xef\xbb\xbf# Software Configuration File\r\n# ---------------------------\r\n# \r\n'
                b'# You may edit this file when the VPN Server / Client / Bridge program is not running.\r\n# \r\n'
                b'# In prior to edit this file manually by your text editor,\r\n'
                b'# shutdown the VPN Server / Client / Bridge background service.\r\n'
                b'# Otherwise, all changes will be lost.\r\n# \r\n')

CFG_TEXT = '\r\n'.join([
    'declare root',
    '{',
    '\tuint ConfigRevision 3',
    '\tbool IPsecMessageDisplayed false',
    '\tstring Region $',
    '\tdeclare ServerConfiguration',
    '\t{',
    '\t\tuint64 AutoDeleteCheckDiskFreeSpaceMin 104857600',
    '\t\tbool DisableNatTraversal true',
    '\t\tbyte HashedPassword AAECAwQFBgcICQoLDA0ODxAREhM=',
    '\t\tstring ServerName Ranz$20VPN',
    '\t\tuint ServerType 0',
    '\t}',
    '\tdeclare VirtualHUB',
    '\t{',
    '\t\tdeclare DEFAULT',
    '\t\t{',
    '\t\t\tbool Online true',
    '\t\t\tstring HubType 0',
    '\t\t}',
    '\t}',
    '}',
    '',
]).encode('ascii')

ITEM_TYPE_INT, ITEM_TYPE_INT64, ITEM_TYPE_BYTE, ITEM_TYPE_STRING, ITEM_TYPE_BOOL = 1, 2, 3, 4, 5


def sha0(data):
    # SHA-0 (FIPS 180), as Mayaqua's Sha0(): SHA-1 without the rotation in the message schedule
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    msg = data + b'\x80' + b'\0' * ((55 - len(data)) % 64) + struct.pack('>Q', len(data) * 8)
    rol = lambda x, n: ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    for off in range(0, len(msg), 64):
        w = list(struct.unpack('>16I', msg[off:off + 64]))
        for t in range(16, 80):
            w.append(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16])
        a, b, c, d, e = h
        for t in range(80):
            if t < 20:
                f, k = (d ^ (b & (c ^ d))), 0x5A827999
            elif t < 40:
                f, k = (b ^ c ^ d), 0x6ED9EBA1
            elif t < 60:
                f, k = ((b & c) | (d & (b | c))), 0x8F1BBCDC
            else:
                f, k = (b ^ c ^ d), 0xCA62C1D6
            a, b, c, d, e = (rol(a, 5) + f + e + k + w[t]) & 0xFFFFFFFF, a, rol(b, 30), c, d
        h = [(x + y) & 0xFFFFFFFF for x, y in zip(h, [a, b, c, d, e])]
    return b''.join(struct.pack('>I', x) for x in h)


def cfg_bin_folder(name, folders, items):
    # As CfgReadNextFolderBin reads it: name, subfolder count, subfolders, item count, items
    out = buf_str(name) + struct.pack('>I', len(folders))
    for sub in folders:
        out += cfg_bin_folder(*sub)
    out += struct.pack('>I', len(items))
    for iname, itype, value in items:
        out += buf_str(iname) + struct.pack('>I', itype)
        if itype in (ITEM_TYPE_INT, ITEM_TYPE_BOOL):
            out += struct.pack('>I', value)
        elif itype == ITEM_TYPE_INT64:
            out += struct.pack('>Q', value)
        else:
            b = value if itype == ITEM_TYPE_BYTE else value.encode('utf-8')
            out += struct.pack('>I', len(b)) + b
    return out


def cfg_bin_file(body):
    # As CfgReadW reads it: "SEVPN_DB", SHA-0 of the body, body
    return b'SEVPN_DB' + sha0(body) + body


def cfg_bin_one_item(name, itype):
    # Folder "root" without subfolders and with one item of the given name and type; the caller adds the value
    return buf_str('root') + struct.pack('>II', 0, 1) + buf_str(name) + struct.pack('>I', itype)


def make_cfg_seeds():
    write_seed('fuzz_cfg', 'server_text.config', TAG_CPYRIGHT + b'\r\n' + CFG_TEXT)
    body = cfg_bin_folder('root', [
        ('ServerConfiguration', [], [
            ('AutoDeleteCheckDiskFreeSpaceMin', ITEM_TYPE_INT64, 104857600),
            ('HashedPassword', ITEM_TYPE_BYTE, bytes(range(20))),
            ('ServerName', ITEM_TYPE_STRING, 'Ranz VPN ' + E_ACUTE),
            ('DisableNatTraversal', ITEM_TYPE_BOOL, 1),
        ]),
    ], [
        ('ConfigRevision', ITEM_TYPE_INT, 3),
        ('IPsecMessageDisplayed', ITEM_TYPE_BOOL, 0),
    ])
    write_seed('fuzz_cfg', 'server_binary.config', cfg_bin_file(body))

    # Malformed binary configurations (SEC-3 #96), each with a valid hash: CfgBufBinToFolder()
    # must reject every one without a crash. Counts and sizes beyond the bytes left (the old
    # reader looped up to 2^32 times, or aborted in MallocEx), a string size of 0xFFFFFFFF (the
    # old reader wrapped size + 1 to 0 and copied past the block), an item name length of
    # 0xFFFFFFFF with more than 511 bytes after it (the old ReadBufStr() moved the cursor back),
    # an unknown item type and a body cut in the middle.
    write_seed('fuzz_cfg', 'bin_folder_count_huge.config',
               cfg_bin_file(buf_str('root') + struct.pack('>I', 0xFFFFFFFF)))
    write_seed('fuzz_cfg', 'bin_item_count_huge.config',
               cfg_bin_file(buf_str('root') + struct.pack('>II', 0, 0xFFFFFFFF)))
    write_seed('fuzz_cfg', 'bin_byte_size_huge.config',
               cfg_bin_file(cfg_bin_one_item('HashedPassword', ITEM_TYPE_BYTE) + struct.pack('>I', 0xFFFFFFF0) + bytes(range(4))))
    write_seed('fuzz_cfg', 'bin_string_size_wrap.config',
               cfg_bin_file(cfg_bin_one_item('ServerName', ITEM_TYPE_STRING) + struct.pack('>I', 0xFFFFFFFF) + b'Ranz'))
    write_seed('fuzz_cfg', 'bin_name_length_wrap.config',
               cfg_bin_file(buf_str('root') + struct.pack('>III', 0, 1, 0xFFFFFFFF) + b'n' * 600 +
                            struct.pack('>II', ITEM_TYPE_INT, 3)))
    write_seed('fuzz_cfg', 'bin_unknown_type.config',
               cfg_bin_file(cfg_bin_one_item('ConfigRevision', 9) + struct.pack('>I', 3)))
    write_seed('fuzz_cfg', 'bin_truncated.config', cfg_bin_file(body[:len(body) // 2]))

    # Malformed configurations of FND-56 (#118): "SEVPN_DB" too short for its SHA-0 (CfgReadW()
    # hashed b->Size - 28 bytes), and folders nested 200 deep in text and binary (the readers
    # recursed once per level; they stop at 64). 200 levels fit in the 4096-byte max_len.
    write_seed('fuzz_cfg', 'bin_short_header.config', b'SEVPN_DB' + bytes(12))
    write_seed('fuzz_cfg', 'text_nested_deep.config',
               b'declare root\r\n{\r\n' + b'declare x\r\n{\r\n' * 199 + b'}\r\n' * 200)
    nested = b''.join(buf_str('root' if i == 0 else 'x') + struct.pack('>I', 1 if i < 199 else 0)
                      for i in range(200))
    write_seed('fuzz_cfg', 'bin_nested_deep.config', cfg_bin_file(nested + struct.pack('>I', 0) * 200))


# ---------------------------------------------------------------------------
# Ethernet frames (Mayaqua/TcpIp.c ParsePacketEx4)
# ---------------------------------------------------------------------------
MAC_A = bytes.fromhex('5e0000000001')
MAC_B = bytes.fromhex('5e0000000002')
BROADCAST = b'\xff' * 6


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ipv4(src, dst, proto, payload, ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0,
                      bytes(src), bytes(dst))
    return hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:] + payload


def l4_csum(src, dst, proto, segment):
    pseudo = bytes(src) + bytes(dst) + struct.pack('>BBH', 0, proto, len(segment))
    return csum(pseudo + segment)


def udp(src, dst, sport, dport, payload):
    seg = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    return seg[:6] + struct.pack('>H', l4_csum(src, dst, 17, seg)) + seg[8:]


def tcp(src, dst, sport, dport, seq, ack, flags, payload):
    seg = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    return seg[:16] + struct.pack('>H', l4_csum(src, dst, 6, seg)) + seg[18:]


def tcp_syn(src, dst, sport, dport, seq, options):
    # SYN without data; the options are a multiple of 4 bytes
    seg = struct.pack('>HHIIBBHHH', sport, dport, seq, 0, (5 + len(options) // 4) << 4, 0x02, 64240, 0, 0) + options
    return seg[:16] + struct.pack('>H', l4_csum(src, dst, 6, seg)) + seg[18:]


def eth(dst, src, ethertype, payload):
    return dst + src + struct.pack('>H', ethertype) + payload


def make_tcpip_seeds():
    a, b = [10, 0, 0, 1], [10, 0, 0, 2]
    dns_query = (struct.pack('>HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0) +
                 b'\x07example\x03com\x00' + struct.pack('>HH', 1, 1))
    write_seed('fuzz_tcpip', 'ipv4_udp_dns.bin',
               eth(MAC_B, MAC_A, 0x0800, ipv4(a, b, 17, udp(a, b, 53000, 53, dns_query))))

    http_get = b'GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: fuzz\r\n\r\n'
    write_seed('fuzz_tcpip', 'ipv4_tcp_http.bin',
               eth(MAC_B, MAC_A, 0x0800, ipv4(a, b, 6, tcp(a, b, 49152, 80, 1000, 2000, 0x18, http_get), 2)))

    arp = struct.pack('>HHBBH', 1, 0x0800, 6, 4, 1) + MAC_A + bytes(a) + b'\0' * 6 + bytes(b)
    write_seed('fuzz_tcpip', 'arp_request.bin', eth(BROADCAST, MAC_A, 0x0806, arp))

    # DHCPDISCOVER from 0.0.0.0:68 to 255.255.255.255:67
    zero, bcast = [0, 0, 0, 0], [255, 255, 255, 255]
    bootp = (struct.pack('>BBBBIHH', 1, 1, 6, 0, 0x2A2B2C2D, 0, 0x8000) + b'\0' * 16 +
             MAC_A + b'\0' * 10 + b'\0' * 192 + b'\x63\x82\x53\x63' +
             b'\x35\x01\x01' + b'\x37\x03\x01\x03\x06' + b'\xff')
    write_seed('fuzz_tcpip', 'ipv4_udp_dhcp_discover.bin',
               eth(BROADCAST, MAC_A, 0x0800, ipv4(zero, bcast, 17, udp(zero, bcast, 68, 67, bootp), 3)))

    # The same DHCPDISCOVER tagged with 802.1ad (TPID 0x88A8), VLAN 10: the parser of a hub with
    # VlanTypeId 0x88A8 reads it through the VLAN tag (FND-39 #113)
    write_seed('fuzz_tcpip', 'vlan_8021ad_ipv4_udp_dhcp_discover.bin',
               eth(BROADCAST, MAC_A, 0x88A8, struct.pack('>HH', 10, 0x0800) +
                   ipv4(zero, bcast, 17, udp(zero, bcast, 68, 67, bootp), 3)))

    # SYN with No-Operation, No-Operation, timestamps and MSS 1460: the MSS clamp walks the options
    # to the MSS (SEC-1 #96, FND-40 #113)
    syn_options = b'\x01\x01' + b'\x08\x0a' + struct.pack('>II', 1, 0) + b'\x02\x04' + struct.pack('>H', 1460)
    write_seed('fuzz_tcpip', 'ipv4_tcp_syn_mss_after_ts.bin',
               eth(MAC_B, MAC_A, 0x0800, ipv4(a, b, 6, tcp_syn(a, b, 49152, 443, 1000, syn_options), 5)))

    # IPv6 ICMPv6 neighbor solicitation for fe80::2 from fe80::1
    src6 = bytes.fromhex('fe800000000000000000000000000001')
    dst6 = bytes.fromhex('ff0200000000000000000001ff000002')
    target6 = bytes.fromhex('fe800000000000000000000000000002')
    icmp6 = struct.pack('>BBHI', 135, 0, 0, 0) + target6 + b'\x01\x01' + MAC_A
    pseudo6 = src6 + dst6 + struct.pack('>I3xB', len(icmp6), 58)
    icmp6 = icmp6[:2] + struct.pack('>H', csum(pseudo6 + icmp6)) + icmp6[4:]
    ip6 = struct.pack('>IHBB', 0x60000000, len(icmp6), 58, 255) + src6 + dst6 + icmp6
    write_seed('fuzz_tcpip', 'ipv6_icmpv6_ns.bin', eth(bytes.fromhex('3333ff000002'), MAC_A, 0x86DD, ip6))

    # 802.1Q VLAN 10, IPv4 ICMP echo request
    echo = struct.pack('>BBHHH', 8, 0, 0, 0x4242, 1) + b'ranz-fuzz-ping'
    echo = echo[:2] + struct.pack('>H', csum(echo)) + echo[4:]
    vlan = struct.pack('>HH', 10, 0x0800) + ipv4(a, b, 1, echo, 4)
    write_seed('fuzz_tcpip', 'vlan_ipv4_icmp_echo.bin', eth(MAC_B, MAC_A, 0x8100, vlan))


# ---------------------------------------------------------------------------
# X.509: self-signed RSA-2048 / SHA-256 certificate built with the standard library.
# The key comes from a fixed-seed PRNG and is not stored: the certificate is test data only.
# ---------------------------------------------------------------------------
def der(tag, content):
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        lb = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        length = bytes([0x80 | len(lb)]) + lb
    return bytes([tag]) + length + content


def der_int(v):
    return der(0x02, v.to_bytes(v.bit_length() // 8 + 1, 'big'))


def der_oid(dotted):
    parts = [int(p) for p in dotted.split('.')]
    out = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.insert(0, 0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(chunk)
    return der(0x06, out)


def der_seq(*items):
    return der(0x30, b''.join(items))


def der_name(pairs):
    rdns = b''
    for oid, tag, value in pairs:
        rdns += der(0x31, der_seq(der_oid(oid), der(tag, value.encode('utf-8'))))
    return der(0x30, rdns)


def is_probable_prime(n, rng):
    if n < 2:
        return False
    for p in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(40):
        x = pow(rng.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits, e, rng):
    while True:
        p = rng.getrandbits(bits) | (3 << (bits - 2)) | 1
        if (p - 1) % e != 0 and is_probable_prime(p, rng):
            return p


def make_x509_seeds():
    rng = random.Random(20261012)
    e = 65537
    p, q = gen_prime(1024, e, rng), gen_prime(1024, e, rng)
    n = p * q
    d = pow(e, -1, (p - 1) * (q - 1))
    k = (n.bit_length() + 7) // 8

    sha256_rsa = der_seq(der_oid('1.2.840.113549.1.1.11'), der(0x05, b''))
    name = der_name([
        ('2.5.4.6', 0x13, 'JP'),
        ('2.5.4.10', 0x0C, 'Ranz VPN'),
        ('2.5.4.3', 0x0C, 'Ranz VPN fuzz seed'),
    ])
    rsa_pub = der_seq(der_int(n), der_int(e))
    spki = der_seq(der_seq(der_oid('1.2.840.113549.1.1.1'), der(0x05, b'')), der(0x03, b'\0' + rsa_pub))
    ski = hashlib.sha1(rsa_pub).digest()
    extensions = der_seq(
        der_seq(der_oid('2.5.29.19'), der(0x01, b'\xff'), der(0x04, der_seq(der(0x01, b'\xff')))),
        der_seq(der_oid('2.5.29.15'), der(0x01, b'\xff'), der(0x04, der(0x03, b'\x01\x86'))),
        der_seq(der_oid('2.5.29.14'), der(0x04, der(0x04, ski))),
        der_seq(der_oid('2.5.29.17'), der(0x04, der_seq(der(0x82, b'fuzz.ranz.invalid')))),
    )
    tbs = der_seq(
        der(0xA0, der_int(2)),                                   # v3
        der_int(0x0B0220261012),                                 # serial
        sha256_rsa,
        name,                                                    # issuer
        der_seq(der(0x17, b'260101000000Z'), der(0x17, b'360101000000Z')),
        name,                                                    # subject (self-signed)
        spki,
        der(0xA3, extensions),
    )

    # RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017 section 8.2)
    digest_info = bytes.fromhex('3031300d060960864801650304020105000420') + hashlib.sha256(tbs).digest()
    em = b'\x00\x01' + b'\xff' * (k - len(digest_info) - 3) + b'\x00' + digest_info
    sig = pow(int.from_bytes(em, 'big'), d, n)
    assert pow(sig, e, n) == int.from_bytes(em, 'big')
    cert = der_seq(tbs, sha256_rsa, der(0x03, b'\0' + sig.to_bytes(k, 'big')))

    b64 = base64.b64encode(cert).decode('ascii')
    pem = '-----BEGIN CERTIFICATE-----\n'
    pem += ''.join(b64[i:i + 64] + '\n' for i in range(0, len(b64), 64))
    pem += '-----END CERTIFICATE-----\n'
    write_seed('fuzz_x509', 'selfsigned_rsa2048.der', cert)
    write_seed('fuzz_x509', 'selfsigned_rsa2048.pem', pem.encode('ascii'))


# ---------------------------------------------------------------------------
# HTTP headers of the SE-VPN handshake (Cedar/Protocol.c, Mayaqua/HTTP.c HttpHeaderToStr)
# ---------------------------------------------------------------------------
def make_http_seeds():
    write_seed('fuzz_http', 'client_connect.txt', (
        b'POST /vpnsvc/connect.cgi HTTP/1.1\r\n'
        b'Host: 192.0.2.1\r\n'
        b'Content-Type: image/jpeg\r\n'
        b'Connection: Keep-Alive\r\n'
        b'Content-Length: 1411\r\n'
        b'\r\n'))
    write_seed('fuzz_http', 'server_response.txt', (
        b'HTTP/1.1 200 OK\r\n'
        b'Content-Type: application/octet-stream\r\n'
        b'Connection: Keep-Alive\r\n'
        b'Keep-Alive: timeout=15; max=19\r\n'
        b'Content-Length: 2048\r\n'
        b'\r\n'))
    write_seed('fuzz_http', 'browser_get.txt', (
        b'GET /vpnsvc/vpn.cgi HTTP/1.1\r\n'
        b'Host: vpn.example.invalid\r\n'
        b'User-Agent: Mozilla/5.0\r\n'
        b'Accept: */*\r\n'
        b'\r\n'))
    write_seed('fuzz_http', 'http09.txt', b'GET / HTTP/0.9\r\n')
    # The peer closes after one header line: no blank line, so no header
    write_seed('fuzz_http', 'truncated_header.txt', (
        b'POST /vpnsvc/connect.cgi HTTP/1.1\r\n'
        b'Host: 192.0.2.1\r\n'))
    # A header line longer than HTTP_HEADER_LINE_MAX_SIZE (4096) after Content-Length: no header
    write_seed('fuzz_http', 'oversized_line.txt', (
        b'POST /vpnsvc/vpn.cgi HTTP/1.1\r\n'
        b'Content-Type: application/octet-stream\r\n'
        b'Content-Length: 16\r\n'
        b'X-Pad: ' + b'A' * 4200 + b'\r\n'
        b'\r\n'))


# ---------------------------------------------------------------------------
# HTTP listener (Cedar/HttpListener.c, REL-6 #51): the requests of the vpntest test httplistener
# ---------------------------------------------------------------------------
HTTPLISTENER_TOKEN = b'fuzz-token_0123456789abcdef'     # The one token that fuzz_httplistener.c serves


def http_request(line, *headers):
    return line + b'\r\n' + b''.join(h + b'\r\n' for h in headers) + b'\r\n'


def make_httplistener_seeds():
    host = b'Host: example.test'
    challenge = b'/.well-known/acme-challenge/'
    seeds = {
        # Redirects to HTTPS
        'redirect_query.txt': http_request(b'GET /some/path?x=1&y=2 HTTP/1.1', host),
        'redirect_host_port.txt': http_request(b'GET /some/path?x=1&y=2 HTTP/1.1', b'Host: example.test:8080'),
        'redirect_head.txt': http_request(b'HEAD /some/path?x=1&y=2 HTTP/1.1', host),
        'redirect_http10.txt': http_request(b'GET /some/path?x=1&y=2 HTTP/1.0', host),
        'redirect_ipv6_host.txt': http_request(b'GET /some/path?x=1&y=2 HTTP/1.1', b'Host: [2001:db8::1]:8080'),
        'redirect_ipv4_host.txt': http_request(b'GET / HTTP/1.1', b'Host: 192.0.2.1'),
        # ACME HTTP-01 challenges
        'challenge_get.txt': http_request(b'GET ' + challenge + HTTPLISTENER_TOKEN + b' HTTP/1.1', host),
        'challenge_head_query.txt': http_request(b'HEAD ' + challenge + HTTPLISTENER_TOKEN + b'?x=1 HTTP/1.1', host),
        'challenge_unknown.txt': http_request(b'GET ' + challenge + b'0123456789abcdef0123 HTTP/1.1', host),
        'challenge_dotdot.txt': http_request(b'GET ' + challenge + b'.. HTTP/1.1', host),
        'challenge_percent.txt': http_request(b'GET ' + challenge + b'%2e%2e HTTP/1.1', host),
        'challenge_slash.txt': http_request(b'GET ' + challenge + HTTPLISTENER_TOKEN + b'/x HTTP/1.1', host),
        'challenge_backslash.txt': http_request(b'GET ' + challenge + HTTPLISTENER_TOKEN + b'\\x HTTP/1.1', host),
        'challenge_device.txt': http_request(b'GET ' + challenge + b'NUL HTTP/1.1', host),
        'challenge_long.txt': http_request(b'GET ' + challenge + b'a' * 256 + b' HTTP/1.1', host),
        # Errors
        'post.txt': http_request(b'POST / HTTP/1.1', host, b'Content-Length: 0'),
        'request_line_no_version.txt': http_request(b'GET /', host),
        'request_line_extra_word.txt': http_request(b'GET / HTTP/1.1 more', host),
        'request_line_other_version.txt': http_request(b'GET / FTP/1.1', host),
        'missing_host.txt': http_request(b'GET / HTTP/1.1', b'Accept: */*'),
        'repeated_host.txt': http_request(b'GET / HTTP/1.1', host, b'Host: other.test'),
        'host_at.txt': http_request(b'GET / HTTP/1.1', b'Host: user@example.test'),
        'host_slash.txt': http_request(b'GET / HTTP/1.1', b'Host: example.test/x'),
        'host_control.txt': http_request(b'GET / HTTP/1.1', b'Host: exa\x01mple.test'),
        'host_bad_port.txt': http_request(b'GET / HTTP/1.1', b'Host: example.test:8x'),
        'absolute_form.txt': http_request(b'GET http://example.test/ HTTP/1.1', host),
        # Bytes that never complete a request, or go over the limits of the reader
        'tls_client_hello.bin': client_hello(b''),
        'incomplete.txt': b'GET / HTTP/1.1\r\n' + host + b'\r\n',
        'over_long_line.txt': http_request(b'GET / HTTP/1.1', host, b'X-Pad: ' + b'A' * 4200),
    }
    for name, data in seeds.items():
        write_seed('fuzz_httplistener', name, data)


# ---------------------------------------------------------------------------
# DHCP replies (Mayaqua/TcpIp.c DhcpModifyIPv4, DhcpModify, ParseDhcpOptions)
# ---------------------------------------------------------------------------
DHCP_COOKIE = b'\x63\x82\x53\x63'

# Options of a DHCP ACK: the router, DNS, domain name and WINS options are the ones DhcpModify removes
DHCP_ACK_OPTIONS = (b'\x35\x01\x05' +                       # Message type: ACK
                    b'\x01\x04\xff\xff\xff\x00' +           # Subnet mask
                    b'\x03\x04\xc0\xa8\x1e\x01' +           # Router
                    b'\x06\x04\xc0\xa8\x1e\x01' +           # DNS server
                    b'\x0f\x03lan' +                        # Domain name
                    b'\x2c\x04\xc0\xa8\x1e\x02' +           # WINS server
                    b'\x33\x04\x00\x00\x0e\x10' +           # Lease time: 3600 s
                    b'\xff')                                # End


def bootp(op, chaddr, yiaddr, siaddr, options, sname=b''):
    # BOOTP fixed header (236 bytes, op to file), the magic cookie at offset 236, then the options,
    # padded to DHCP_MIN_SIZE (300) like the replies of a real server
    hdr = struct.pack('>BBBBIHH', op, 1, 6, 0, 0x2A2B2C2D, 0, 0x8000)
    hdr += b'\0' * 4 + bytes(yiaddr) + bytes(siaddr) + b'\0' * 4     # ciaddr, yiaddr, siaddr, giaddr
    hdr += chaddr + b'\0' * 10                                         # chaddr (16 bytes)
    hdr += sname.ljust(64, b'\0') + b'\0' * 128                        # sname, file
    assert len(hdr) == 236
    payload = hdr + DHCP_COOKIE + options
    return payload.ljust(300, b'\0')


def make_dhcp_seeds():
    server, client = [192, 168, 30, 1], [192, 168, 30, 10]
    ack = bootp(2, MAC_A, client, server, DHCP_ACK_OPTIONS)

    # The ACK in its frame, from the server port 67 to the client port 68: the path of StorePacket()
    write_seed('fuzz_dhcp', 'ack_frame.bin',
               eth(MAC_A, MAC_B, 0x0800, ipv4(server, client, 17, udp(server, client, 67, 68, ack), 6)))
    # The ACK as the DHCP payload of DhcpModify, and its options as the input of ParseDhcpOptions
    write_seed('fuzz_dhcp', 'ack_payload.bin', ack)
    write_seed('fuzz_dhcp', 'ack_options.bin', DHCP_ACK_OPTIONS)

    # An OFFER whose domain name is longer than 255 bytes: option 250 continues the option before it
    # (BuildDhcpOptionsBuf splits it that way), with Pad bytes between the options
    domain = b'd' * 300
    offer_options = (b'\x35\x01\x02' + b'\x00\x00' + b'\x03\x04\xc0\xa8\x1e\x01' +
                     b'\x0f\xff' + domain[:255] + b'\xfa' + bytes([len(domain) - 255]) + domain[255:] + b'\xff')
    write_seed('fuzz_dhcp', 'offer_option_continued.bin', bootp(2, MAC_A, client, server, offer_options))

    # The DHCP fixes of SEC-1 (#96) and FND-38 (#113): no cookie at offset 236 (the old code searched
    # the payload for one), cookie bytes with REQUEST options in sname in front of the real cookie, a
    # payload that ends inside the cookie, and an option whose body runs past the end of the payload
    no_cookie = bytearray(ack)
    no_cookie[236:240] = b'\0\0\0\0'
    write_seed('fuzz_dhcp', 'no_cookie.bin', bytes(no_cookie))
    write_seed('fuzz_dhcp', 'cookie_in_sname.bin',
               bootp(2, MAC_A, client, server, DHCP_ACK_OPTIONS, sname=DHCP_COOKIE + b'\x35\x01\x03\xff'))
    write_seed('fuzz_dhcp', 'short_in_cookie.bin', ack[:239])
    write_seed('fuzz_dhcp', 'option_past_end.bin',
               bootp(2, MAC_A, client, server, b'')[:240] + b'\x35\x01\x05' + b'\x06\x08\xc0\xa8')


# ---------------------------------------------------------------------------
# TLS ClientHello (Mayaqua/Network.c GetSniNameFromSslPacket) and address text (StrToIP,
# ParseIpAndMask46 and the parsers built on them)
# ---------------------------------------------------------------------------
def client_hello(extensions):
    # TLS 1.0 record, ClientHello with client version TLS 1.2, one cipher suite, null compression
    body = (b'\x03\x03' + bytes((i * 11 + 1) & 0xFF for i in range(32)) + b'\x00' +
            b'\x00\x02\x13\x01' + b'\x01\x00' + struct.pack('>H', len(extensions)) + extensions)
    handshake = b'\x01' + struct.pack('>I', len(body))[1:] + body
    return b'\x16\x03\x01' + struct.pack('>H', len(handshake)) + handshake


def sni_extension(name):
    entry = b'\x00' + struct.pack('>H', len(name)) + name
    data = struct.pack('>H', len(entry)) + entry
    return struct.pack('>HH', 0, len(data)) + data


def make_net_seeds():
    # supported_versions (43) with TLS 1.3, an extension the parser skips
    versions = struct.pack('>HHB', 43, 3, 2) + b'\x03\x04'
    write_seed('fuzz_net', 'client_hello_sni.bin', client_hello(sni_extension(b'vpn.example.invalid')))
    write_seed('fuzz_net', 'client_hello_sni_after_versions.bin',
               client_hello(versions + sni_extension(b'vpn.example.invalid')))
    # A name longer than the MAX_PATH (260) buffer of ParseHttpsAccessLog
    write_seed('fuzz_net', 'client_hello_sni_long.bin', client_hello(sni_extension(b'a' * 300 + b'.invalid')))
    write_seed('fuzz_net', 'client_hello_no_sni.bin', client_hello(versions))

    texts = {
        'ipv4.txt': b'192.0.2.1',
        'ipv4_trailing_text.txt': b'1.2.3.4abc',
        'ipv4_octet_256.txt': b'256.1.1.1',
        'ipv6.txt': b'2001:db8::1',
        'ipv6_full.txt': b'2001:0db8:0000:0000:0000:ff00:0042:8329',
        'ipv6_v4_mapped.txt': b'::ffff:1.2.3.4',
        'ipv6_scope_id.txt': b'fe80::1%12',
        'ipv6_bad.txt': b'2001:db8:::1',
        'ipv4_prefix.txt': b'192.168.0.0/24',
        'ipv4_prefix_33.txt': b'192.168.0.0/33',
        'ipv4_mask.txt': b'10.0.0.0/255.255.0.0',
        'ipv4_mask_not_contiguous.txt': b'10.0.0.0/255.0.255.0',
        'ipv6_prefix.txt': b'2001:db8::/32',
        'ipv6_mask.txt': b'fd00::/ffff:ffff:ffff:ffff::',
    }
    for name, text in texts.items():
        write_seed('fuzz_net', name, text)


# ---------------------------------------------------------------------------
# STUN (Mayaqua/Stun.c StunParseBindingResponse, StunParseServerStr; RFC 5389, RFC 5769)
# ---------------------------------------------------------------------------
STUN_COOKIE = 0x2112A442
STUN_TID = bytes.fromhex('b7e7a701bc34d686fa87dfae')       # Transaction ID of RFC 5769 section 2.2


def stun_attr(attr_type, value):
    # The value is padded to a multiple of 4 bytes; the length is the unpadded one
    return struct.pack('>HH', attr_type, len(value)) + value + b'\0' * (-len(value) % 4)


def stun_response(attrs):
    return struct.pack('>HHI', 0x0101, len(attrs), STUN_COOKIE) + STUN_TID + attrs


def stun_address(family, port, addr, xor):
    if xor:
        key = struct.pack('>I', STUN_COOKIE) + STUN_TID
        port ^= STUN_COOKIE >> 16
        addr = bytes(a ^ k for a, k in zip(addr, key))
    return struct.pack('>BBH', 0, family, port) + addr


def make_stun_seeds():
    ipv4 = bytes([192, 0, 2, 1])
    ipv6 = bytes.fromhex('20010db8123456780011223344556677')
    software = stun_attr(0x8022, b'STUN test client')     # Comprehension-optional, skipped
    write_seed('fuzz_stun', 'response_xor_ipv4.bin',
               stun_response(software + stun_attr(0x0020, stun_address(1, 32853, ipv4, True))))
    write_seed('fuzz_stun', 'response_xor_ipv6.bin',
               stun_response(software + stun_attr(0x0020, stun_address(2, 32853, ipv6, True))))
    # RFC 3489 server: MAPPED-ADDRESS only, behind an unknown attribute with padding
    write_seed('fuzz_stun', 'response_mapped_only.bin',
               stun_response(stun_attr(0x8023, b'ABCDE') +
                             stun_attr(0x0001, stun_address(1, 3478, bytes([203, 0, 113, 7]), False))))
    write_seed('fuzz_stun', 'response_mapped_and_xor.bin',
               stun_response(stun_attr(0x0001, stun_address(1, 3478, bytes([203, 0, 113, 7]), False)) +
                             stun_attr(0x0020, stun_address(1, 32853, ipv4, True))))
    # XOR-MAPPED-ADDRESS whose length (12) runs past the end of the message
    whole = stun_response(stun_attr(0x0020, stun_address(1, 32853, ipv4, True)))
    write_seed('fuzz_stun', 'response_attr_past_end.bin', whole[:22] + b'\x00\x0c' + whole[24:])

    texts = {
        'server_host.txt': b'stun.example.invalid',
        'server_host_port.txt': b'stun.example.invalid:19302',
        'server_ipv6_bracket_port.txt': b'[2001:db8::1]:3478',
        'server_ipv6_bare.txt': b'2001:db8::1',
        'server_port_too_large.txt': b'stun.example.invalid:99999',
    }
    for name, text in texts.items():
        write_seed('fuzz_stun', name, text)


# ---------------------------------------------------------------------------
# Peer layer of the new core (Core/Peer.c PeerInput, Core/PeerSignal.c PeerOpenSignal and PeerSignalDecode)
# ---------------------------------------------------------------------------
# The public keys of the fixed scalars of fuzz_peer.c and coretest: A (1, 2, ...), B (33, 34, ...), the relay
# (129, 130, ...). X25519 is not in the standard library, so they are written out (src/coretest/envelope.c).
PEER_A = bytes.fromhex('07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c')
PEER_B = bytes.fromhex('5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b')
PEER_RELAY = bytes.fromhex('883186b800b41d5cf0429695da9b3cc4f328ebcd184a6e482fa578c103f06c77')
# The known answers of coretest's envelope test: a signal payload, its envelope from A to B, a bind from A to the
# relay
PEER_SIGNAL = bytes.fromhex(
    '01010102030405060708883186b800b41d5cf0429695da9b3cc4f328ebcd184a6e482fa578c103f06c7700000000000000000000'
    'ffffc000020a1b58020100000000000000000000ffff0a00000213880200000000000000000000ffffc63364079c41')
PEER_SIGNAL_ENVELOPE = bytes.fromhex(
    '0407a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c244fe3b963e899dd295baffce248d3530f3a9a74'
    '79ba063002680ebfe7adad49529bf345ba812669a43343fe55f5bdebfa1fd20846a6b5d96b0efe2ebaabc1b2f8e61fd05853d2e30e'
    'daa0107cab08f15d22975a1970ba0956de502d94c629a92543f49c5206a51e61b47e1c6263a7345cae0aa14d13bfd2d6f1f2049ea5'
    'a1ef584e6d2014829b4ea20ba9afc1f865290e2a82')
PEER_BIND_ENVELOPE = bytes.fromhex(
    '0207a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c244fe3b963e899dd295baffce248d3530f3a9a74'
    '79ba063002680ebfe7adad498b4b5ccb906d23b5b95c9a9b3beeb6779a7126787517d53658')


def make_peer_seeds():
    write_seed('fuzz_peer', 'data_a_to_b.bin', b'\x01' + PEER_A + PEER_B + b'hello through the relay')
    write_seed('fuzz_peer', 'data_a_to_relay.bin', b'\x01' + PEER_A + PEER_RELAY + b'ping')
    write_seed('fuzz_peer', 'data_short.bin', b'\x01' + PEER_A[:20])
    write_seed('fuzz_peer', 'signal_payload.bin', PEER_SIGNAL)
    # No candidate, no relay: the smallest signal
    write_seed('fuzz_peer', 'signal_payload_empty.bin', b'\x01\x02' + struct.pack('>Q', 7) + b'\0' * 50 + b'\0')
    write_seed('fuzz_peer', 'signal_envelope.bin', PEER_SIGNAL_ENVELOPE)
    write_seed('fuzz_peer', 'bind_envelope.bin', PEER_BIND_ENVELOPE)
    # A bound with the header of an envelope and a ciphertext that opens for no one
    write_seed('fuzz_peer', 'bound_garbage.bin', b'\x03' + PEER_RELAY + PEER_A + b'\0' * 43)
    # The STUN messages of ICE at B, whose session with A has A's answer (CORE-S5-6-R1, #537): a check of A that names the
    # username fragment of that session as RanzUfrg, which fuzz_peer.c puts in its place, so the session takes it and
    # libjuice dispatches it (agent_dispatch_stun); the same with USE-CANDIDATE; the same with ICE-CONTROLLING in place of
    # ICE-CONTROLLED, a role conflict with B, whose session is controlling and keeps its role against the tiebreaker 1;
    # and an answer to no check of B. The MESSAGE-INTEGRITY of each is zeros, which fuzz_peer.c makes the HMAC of B's
    # session in the copy for B once the fragment is in its place (CORE-S5-6-R2, #557), so the checks pass the check of
    # their integrity and reach agent_process_stun_binding. None has a FINGERPRINT, which the fragment would break.
    check = (stun_attr(0x0006, b'RanzUfrg:RanzPeer') + stun_attr(0x0024, struct.pack('>I', 0x6E7F1EFF)) +
             stun_attr(0x8029, struct.pack('>Q', 0x0102030405060708)))
    integrity = stun_attr(0x0008, bytes(20))
    write_seed('fuzz_peer', 'stun_check.bin',
               struct.pack('>HHI', 0x0001, len(check + integrity), STUN_COOKIE) + STUN_TID + check + integrity)
    nominate = check + stun_attr(0x0025, b'') + integrity
    write_seed('fuzz_peer', 'stun_check_use_candidate.bin',
               struct.pack('>HHI', 0x0001, len(nominate), STUN_COOKIE) + STUN_TID + nominate)
    conflict = (stun_attr(0x0006, b'RanzUfrg:RanzPeer') + stun_attr(0x0024, struct.pack('>I', 0x6E7F1EFF)) +
                stun_attr(0x802A, struct.pack('>Q', 1)) + integrity)
    write_seed('fuzz_peer', 'stun_check_role_conflict.bin',
               struct.pack('>HHI', 0x0001, len(conflict), STUN_COOKIE) + STUN_TID + conflict)
    write_seed('fuzz_peer', 'stun_answer.bin',
               stun_response(stun_attr(0x0020, stun_address(1, 40000, bytes([203, 0, 113, 20]), True)) + integrity))


# ---------------------------------------------------------------------------
# Noise session (src/Core/NoiseSession.c): the records of the golden transcripts of coretest
# noisesession (src/coretest/session.c), made with the keys of the cacophony IK vector, which
# fuzz_noise.c uses too. Bound: the TLS exporter 00 .. 1f, records in clear; encrypted: no binding,
# records under the Noise keys, rekey after 4.
# ---------------------------------------------------------------------------
NOISE_GOLDEN = {
    'bound': {
        'hs1': '0001ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444e417bc55c7a8166c993356c1be41ef67818a292426f301556c7f26b21d25ddb50901f6c0fe1e7ad5e23084c93002377d265fcde584d2a7bee488866fe3d6a96',
        'hs2': '000195ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088435e02bac3ee97e3ac27fdd5f32aad4e05',
        'records': ['0201010348554205616c69636500067365637265740000',
                    '01000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b',
                    '03', '0172656b65792031', '0172656b65792032', '04'],
    },
    'encrypted': {
        'hs1': '0001ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444e417bc55c7a8166c993356c1be41ef67818a292426f301556c7f26b21d25ddbab78f691bedb2016cad0d55ed4bc463368c1ed3ba8c9906fedeb321c1431d854',
        'hs2': '000195ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843369f326da14e1d270d0629a34a4a68e5',
        'records': ['022183df9b987b30e1738c9674856828c0538701253acadf7ad43a1e13c85906b77531983c9a40',
                    '010df1c02f1c17afc87c5812abff8ebfa905eeb568befbed9f5459d37710a31dacd0ab6e18b17f6a80c0461d63b8f1bc4d306340776a6b80186c7d0decd694ee2765af5683a494d6387cdc6c84',
                    '037910fa9329022aa1d6d5c94aba0eadf8', '81862aea81d5cff4afc5fdc3684e80756a8700f0a2852641',
                    '01e9cb26864bae94ffc40a1aa46694bff1c6508fbdb27285', '04795896313c9804601a8fb9cf8654be0d'],
    },
}


def noise_login(method, hub, user, secret=b'', sign=b''):
    # NoiseLoginEncode: version, method, hub and user (1-byte sizes), secret and signature (2-byte sizes)
    return (bytes([1, method, len(hub)]) + hub + bytes([len(user)]) + user +
            struct.pack('>H', len(secret)) + secret + struct.pack('>H', len(sign)) + sign)


def make_noise_seeds():
    for mode, g in NOISE_GOLDEN.items():
        write_seed('fuzz_noise', 'handshake1_%s.bin' % mode, bytes.fromhex(g['hs1']))
        write_seed('fuzz_noise', 'handshake2_%s.bin' % mode, bytes.fromhex(g['hs2']))
        stream = b''.join(struct.pack('>H', len(bytes.fromhex(r))) + bytes.fromhex(r) for r in g['records'])
        write_seed('fuzz_noise', 'records_%s.bin' % mode, stream)
    # A first record of IKhfs (suite 2): the size of its message 1 with an empty payload, 1296 bytes
    rng = random.Random(62)
    write_seed('fuzz_noise', 'handshake1_ikhfs.bin', bytes([0, 2]) + bytes(rng.getrandbits(8) for _ in range(1296)))
    write_seed('fuzz_noise', 'login_password.bin', noise_login(1, b'HUB', b'alice', b'secret'))
    write_seed('fuzz_noise', 'login_cert.bin', noise_login(2, b'HUB', b'alice', bytes(range(200)), bytes(256)))
    write_seed('fuzz_noise', 'login_join.bin', noise_login(3, b'HUB', b'alice', bytes(16)))


# ---------------------------------------------------------------------------
# Transport module (src/Core/Transport.c TransportParseList, src/Core/TransportNoise.c): fallback lists, and the
# frames that a server node reads from a stream without a channel binding, each the size of its record in 4 bytes
# (big-endian) and the record: the encrypted golden handshake and records above, which the server node of
# fuzz_transport.c accepts and decrypts
# ---------------------------------------------------------------------------
def transport_frames(records):
    return b''.join(struct.pack('>I', len(r)) + r for r in records)


def make_transport_seeds():
    g = NOISE_GOLDEN['encrypted']
    hs1 = bytes.fromhex(g['hs1'])
    write_seed('fuzz_transport', 'handshake1.bin', transport_frames([hs1]))
    write_seed('fuzz_transport', 'records.bin', transport_frames([hs1] + [bytes.fromhex(r) for r in g['records']]))
    # A frame one byte above the largest record (2 + 65535) and an empty frame: the stream ends at either
    write_seed('fuzz_transport', 'frame_too_large.bin', struct.pack('>I', 2 + 65535 + 1) + hs1)
    write_seed('fuzz_transport', 'frame_empty.bin', struct.pack('>I', 0) + hs1)
    # The handshake frame cut inside its record
    write_seed('fuzz_transport', 'frame_cut.bin', transport_frames([hs1])[:40])
    # Fallback lists (ADR-0005: QUIC, then TLS-443, then the CDN path): two entries with spaces around them, the 8
    # entries a list holds at most, an empty entry after the last comma, a transport that is not known, an entry
    # without an address, and the longest address that fits (255 bytes) before one that does not
    write_seed('fuzz_transport', 'list.txt', b'quic:vpn.example:443, tls:vpn.example:443')
    write_seed('fuzz_transport', 'list_full.txt', b','.join(b'cdn:https://edge%d.example/ranz' % i for i in range(8)))
    write_seed('fuzz_transport', 'list_trailing_comma.txt', b'quic:vpn.example:443,')
    write_seed('fuzz_transport', 'list_unknown.txt', b'\tquic:vpn.example:443 ,\twss:vpn.example:443')
    write_seed('fuzz_transport', 'list_no_address.txt', b'tls:vpn.example:443, quic:')
    write_seed('fuzz_transport', 'list_long_address.txt', b'tls:' + b'a' * 255 + b',tls:' + b'b' * 256)
    make_proxy_seeds()


# What a proxy answers a client of the TLS transport (src/Core/TransportPath.c, SDN-61 #254): an HTTP proxy's 200 to
# CONNECT, a 407 with header lines, an answer with LF line ends and one cut short; the replies of a SOCKS5 proxy with an
# IPv4 address, a name and an IPv6 address; and a proxy list and a bypass list of WinHTTP
def make_proxy_seeds():
    write_seed('fuzz_transport', 'proxy_http_200.bin', b'HTTP/1.1 200 Connection established\r\n\r\n')
    write_seed('fuzz_transport', 'proxy_http_407.bin',
               b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="proxy"\r\n'
               b'Content-Length: 0\r\n\r\n')
    write_seed('fuzz_transport', 'proxy_http_lf.bin', b'HTTP/1.0 200 OK\nProxy-Agent: ranz-test\n\n')
    write_seed('fuzz_transport', 'proxy_http_cut.bin', b'HTTP/1.1 200 Connection est')
    write_seed('fuzz_transport', 'proxy_socks_ipv4.bin', bytes([5, 0, 0, 1, 127, 0, 0, 1]) + struct.pack('>H', 1080))
    write_seed('fuzz_transport', 'proxy_socks_name.bin', bytes([5, 0, 0, 3, 11]) + b'vpn.example' + struct.pack('>H', 443))
    write_seed('fuzz_transport', 'proxy_socks_ipv6.bin', bytes([5, 4, 0, 4]) + bytes(15) + b'\x01' + struct.pack('>H', 0))
    write_seed('fuzz_transport', 'proxy_list.txt', b'http=proxy.example:80;https=[2001:db8::1]:3128 socks=s.example:1080')
    write_seed('fuzz_transport', 'proxy_bypass.txt', b'<local>;*.example.com;10.*;<-loopback>')


# ---------------------------------------------------------------------------
# VXLAN module of the new core (src/Core/Vxlan.c VxlanInput, RFC 7348 section 5): the datagrams of VTEPs, the 8 bytes
# of the VXLAN header (the flags, 3 reserved bytes, the VNI in 3 bytes, 1 reserved byte) and an Ethernet frame.
# fuzz_vxlan.c carries VNI 5001 and VNI 16777215 (0xFFFFFF); VNI 7777 is none of its VNIs.
# ---------------------------------------------------------------------------
def vxlan(vni, frame, flags=0x08, reserved=b'\0\0\0', last=0):
    return bytes([flags]) + reserved + struct.pack('>I', vni)[1:] + bytes([last]) + frame


def make_vxlan_seeds():
    a, b = [10, 0, 0, 1], [10, 0, 0, 2]
    echo = struct.pack('>BBHHH', 8, 0, 0, 0x4242, 1) + b'ranz-vxlan-ping'
    echo = echo[:2] + struct.pack('>H', csum(echo)) + echo[4:]
    untagged = eth(MAC_B, MAC_A, 0x0800, ipv4(a, b, 1, echo, 7))
    tagged = eth(MAC_B, MAC_A, 0x8100, struct.pack('>HH', 10, 0x0800) + ipv4(a, b, 1, echo, 8))
    arp = struct.pack('>HHBBH', 1, 0x0800, 6, 4, 1) + MAC_A + bytes(a) + b'\0' * 6 + bytes(b)
    write_seed('fuzz_vxlan', 'untagged.bin', vxlan(5001, untagged))
    write_seed('fuzz_vxlan', 'vlan_tagged.bin', vxlan(5001, tagged))
    write_seed('fuzz_vxlan', 'vni_max_arp.bin', vxlan(0xFFFFFF, eth(BROADCAST, MAC_A, 0x0806, arp)))
    write_seed('fuzz_vxlan', 'unknown_vni.bin', vxlan(7777, untagged))
    # Every reserved bit set, which a receiver ignores; no I flag, which it drops; one byte short of the header and an
    # Ethernet header
    write_seed('fuzz_vxlan', 'reserved_bits.bin', vxlan(5001, untagged, flags=0xFF, reserved=b'\xff\xff\xff', last=0xFF))
    write_seed('fuzz_vxlan', 'no_vni_flag.bin', vxlan(5001, untagged, flags=0x00))
    write_seed('fuzz_vxlan', 'short.bin', vxlan(5001, untagged[:13]))


# ---------------------------------------------------------------------------
# 1:1 NAT and 4via6 of the Node module (src/Cedar/NodeNat.c, SDN-6 #182): the first byte picks the VRF (its two low
# bits) and the way (bit 2: into the overlay), the rest is an IP packet. fuzz_nat.c has no rule in VRF 0, the 4via6
# of fd00:1:0:ffff::/96 in VRF 1, 192.168.1.0/24 as 10.99.1.0/24 and fd00:7::/64 as fd00:2:0:99::/64 in VRF 2, and
# the 4via6 of fd00:3:0:ffff::/96 with 10.4.0.0/24 as 10.204.0.0/24 behind it in VRF 3.
# ---------------------------------------------------------------------------
def ipv6(src, dst, nh, payload, ext=b''):
    # With ext, a hop-by-hop options header, the IPv6 header names it as the next header
    return struct.pack('>IHBB', 6 << 28, len(ext) + len(payload), 0 if ext else nh, 64) + bytes(src) + bytes(dst) + ext + payload


def l6_csum(src, dst, nh, segment):
    pseudo = bytes(src) + bytes(dst) + struct.pack('>I3xB', len(segment), nh)
    return csum(pseudo + segment)


def icmp4(icmp_type, code, rest, data):
    msg = struct.pack('>BBHI', icmp_type, code, 0, rest) + data
    return msg[:2] + struct.pack('>H', csum(msg)) + msg[4:]


def icmp6(src, dst, icmp_type, code, rest, data):
    msg = struct.pack('>BBHI', icmp_type, code, 0, rest) + data
    return msg[:2] + struct.pack('>H', l6_csum(src, dst, 58, msg)) + msg[4:]


def udp6(src, dst, sport, dport, payload):
    seg = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    return seg[:6] + struct.pack('>H', l6_csum(src, dst, 17, seg)) + seg[8:]


def tcp6_syn(src, dst, sport, dport, seq):
    seg = struct.pack('>HHIIBBHHH', sport, dport, seq, 0, 5 << 4, 0x02, 65535, 0, 0)
    return seg[:16] + struct.pack('>H', l6_csum(src, dst, 6, seg)) + seg[18:]


def make_nat_seeds():
    out, vrf1, vrf2, vrf3 = 0x04, 1, 2, 3
    a, b, gw = [10, 0, 0, 1], [10, 0, 0, 5], [10, 0, 0, 9]
    a6, b6, gw6 = (bytes.fromhex('fd0000010000ffff00000000') + bytes(x) for x in (a, b, gw))
    data = b'ranz-nat-data'

    def seed(name, way, packet):
        write_seed('fuzz_nat', name, bytes([way]) + packet)

    # The 4via6 of VRF 1: Echo, UDP and TCP each way, a UDP datagram without a checksum, ICMP errors with the packet
    # that they quote, an extension header and a fragment, which it drops
    seed('4via6_echo_out.bin', vrf1 | out, ipv6(a6, b6, 58, icmp6(a6, b6, 128, 0, 0x4E410001, data)))
    seed('4via6_udp_in.bin', vrf1, ipv4(b, a, 17, udp(b, a, 53, 40000, data)))
    seed('4via6_udp0_in.bin', vrf1, ipv4(b, a, 17, struct.pack('>HHHH', 53, 40000, 8 + len(data), 0) + data))
    seed('4via6_tcp_out.bin', vrf1 | out, ipv6(a6, b6, 6, tcp6_syn(a6, b6, 40001, 80, 0x01020304)))
    seed('4via6_unreachable_in.bin', vrf1, ipv4(gw, a, 1, icmp4(3, 3, 0, ipv4(a, b, 17, udp(a, b, 40000, 53, data)))))
    seed('4via6_too_big_out.bin', vrf1 | out, ipv6(a6, b6, 58, icmp6(a6, b6, 2, 0, 1500, ipv6(b6, a6, 17, udp6(b6, a6, 53, 40000, data)))))
    seed('4via6_time_exceeded_in.bin', vrf1, ipv4(gw, a, 1, icmp4(11, 0, 0, ipv4(a, b, 1, icmp4(8, 0, 0x4E410001, data))[:28])))
    seed('4via6_hop_by_hop_out.bin', vrf1 | out, ipv6(a6, gw6, 17, udp6(a6, gw6, 40000, 53, data), ext=bytes([17, 0, 1, 4, 0, 0, 0, 0])))
    frag = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 28 + len(data), 1, 0x2000, 64, 17, 0, bytes(b), bytes(a))
    seed('4via6_fragment_in.bin', vrf1, frag[:10] + struct.pack('>H', csum(frag)) + frag[12:] + udp(b, a, 53, 40000, data))
    # 1:1 NAT of VRF 2, IPv4 and IPv6: the destination on the way in, the source on the way out, an ICMP error with
    # the packet that it quotes
    lan, lan_out, peer = [192, 168, 1, 7], [10, 99, 1, 7], [10, 3, 0, 1]
    lan6, peer6 = bytes.fromhex('fd000007000000000000000000000007'), bytes.fromhex('fd000002000000010000000000000001')
    seed('nat_tcp_in.bin', vrf2, ipv4(peer, lan_out, 6, tcp(peer, lan_out, 40001, 80, 0x01020304, 0, 0x02, b'')))
    seed('nat_unreachable_out.bin', vrf2 | out, ipv4(lan, peer, 1, icmp4(3, 3, 0, ipv4(peer, lan, 17, udp(peer, lan, 40000, 53, data)))))
    seed('nat_echo6_out.bin', vrf2 | out, ipv6(lan6, peer6, 58, icmp6(lan6, peer6, 128, 0, 0x4E410001, data)))
    # The 4via6 of VRF 3 with a 1:1 NAT rule behind it, a VRF without rules, and a packet cut short
    c7, c5 = (bytes.fromhex('fd0000030000ffff00000000') + bytes(x) for x in ([10, 4, 0, 7], b))
    seed('combo_echo_out.bin', vrf3 | out, ipv6(c7, c5, 58, icmp6(c7, c5, 128, 0, 0x4E410001, data)))
    seed('none_udp_in.bin', 0, ipv4(b, a, 17, udp(b, a, 53, 40000, data)))
    seed('short_out.bin', vrf1 | out, ipv6(a6, b6, 58, icmp6(a6, b6, 128, 0, 0x4E410001, data))[:30])


# ---------------------------------------------------------------------------
# Switch module of the new core (src/Core/Switch.c SwitchInput): the first byte chooses the port of fuzz_switch.c (0 the
# access port of VLAN 10, 1 the trunk port of VLANs 10, 20 and 30, 2 the trunk port of VLAN 20 with the native VLAN 10,
# 3 a port without a member), the second moves its clock on by tens of ms (0xFF ages the MAC table after the frame, 0xFE
# clears it), the rest is the frame
# ---------------------------------------------------------------------------
def switch_input(port, clock, frame):
    return bytes([port, clock]) + frame


def make_switch_seeds():
    a, b = [10, 0, 0, 1], [10, 0, 0, 2]
    arp = struct.pack('>HHBBH', 1, 0x0800, 6, 4, 1) + MAC_A + bytes(a) + b'\0' * 6 + bytes(b)
    dgram = ipv4(a, b, 17, udp(a, b, 40000, 40001, b'ranz-switch'), 9)
    mdns = bytes.fromhex('01005e0000fb')
    netbios = bytes.fromhex('030000000001')
    netbeui = (b'\xf0\xf0\x03' + bytes.fromhex('2c00ffef0a00000000000100') + b'RANZ-SERVER     ' + b'RANZ-CLIENT     ')
    profinet = bytes.fromhex('8000') + b'\x80' * 8 + bytes.fromhex('12343500')
    write_seed('fuzz_switch', 'access_broadcast_arp.bin', switch_input(0, 1, eth(BROADCAST, MAC_A, 0x0806, arp)))
    write_seed('fuzz_switch', 'access_unicast_then_age.bin', switch_input(0, 0xFF, eth(MAC_B, MAC_A, 0x88B5, b'SW\x00\x01')))
    write_seed('fuzz_switch', 'access_netbeui.bin', switch_input(0, 3, eth(netbios, MAC_A, len(netbeui), netbeui)))
    write_seed('fuzz_switch', 'trunk_vlan20_udp.bin',
               switch_input(1, 1, eth(MAC_B, MAC_A, 0x8100, struct.pack('>HH', 20, 0x0800) + dgram)))
    write_seed('fuzz_switch', 'trunk_vlan30_then_clear.bin',
               switch_input(1, 0xFE, eth(BROADCAST, MAC_B, 0x8100, struct.pack('>HH', 30, 0x88B5) + b'SW\x00\x02')))
    write_seed('fuzz_switch', 'trunk_vlan_4095.bin',
               switch_input(1, 0, eth(BROADCAST, MAC_B, 0x8100, struct.pack('>HH', 0x0FFF, 0x88B5) + b'SW\x00\x03')))
    write_seed('fuzz_switch', 'trunk_tag_cut_short.bin', switch_input(1, 0, MAC_B + MAC_A + bytes.fromhex('8100001408')))
    write_seed('fuzz_switch', 'native_multicast.bin', switch_input(2, 2, eth(mdns, MAC_B, 0x0800, dgram)))
    write_seed('fuzz_switch', 'native_priority_tag_profinet.bin',
               switch_input(2, 0, eth(MAC_A, MAC_B, 0x8100, struct.pack('>HH', 0xC000, 0x8892) + profinet)))
    write_seed('fuzz_switch', 'no_member.bin', switch_input(3, 0, eth(BROADCAST, MAC_A, 0x88B5, b'SW\x00\x04')))
    # The IP table (SDN-50-N #492): an IPv6 packet, whose source the table learns, and an IPv4 packet whose clock byte reads
    # and clears both tables after it
    a6, b6 = bytes.fromhex('fd000000000000000000000000000001'), bytes.fromhex('fd000000000000000000000000000002')
    write_seed('fuzz_switch', 'access_ipv6.bin', switch_input(0, 1, eth(MAC_B, MAC_A, 0x86DD, ipv6(a6, b6, 17, udp6(a6, b6, 40000, 40001, b'ranz-switch')))))
    write_seed('fuzz_switch', 'access_ipv4_then_clear.bin', switch_input(0, 0xFE, eth(MAC_B, MAC_A, 0x0800, dgram)))


def make_module_seeds():
    # src/fuzz/seeds/<target>.py, in the order of their names: each has make_seeds(h), h being this module. The directory
    # is not on the module path under python -I, so the files are loaded by their path.
    directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'seeds')
    if not os.path.isdir(directory):
        return
    for name in sorted(os.listdir(directory)):
        if not name.endswith('.py') or name.startswith('_'):
            continue
        spec = importlib.util.spec_from_file_location('seeds_' + name[:-3], os.path.join(directory, name))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.make_seeds(sys.modules[__name__])


if __name__ == '__main__':
    assert sha0(b'abc').hex() == '0164b8a914cd2a5e74c4f7ff082c4d97f1edf880'
    assert len(PEER_SIGNAL) == 99 and len(PEER_SIGNAL_ENVELOPE) == 180 and len(PEER_BIND_ENVELOPE) == 90
    make_pack_seeds()
    make_pack_bad_seeds()
    make_login_seeds()
    make_cfg_seeds()
    make_tcpip_seeds()
    make_x509_seeds()
    make_http_seeds()
    make_httplistener_seeds()
    make_dhcp_seeds()
    make_net_seeds()
    make_stun_seeds()
    make_peer_seeds()
    make_noise_seeds()
    make_transport_seeds()
    make_vxlan_seeds()
    make_nat_seeds()
    make_switch_seeds()
    make_module_seeds()
