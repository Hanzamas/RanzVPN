# fuzz_policy.py
# The seeds of fuzz_policy (src/fuzz/fuzz_policy.c, the policy engine of CORE-S4-2 #75), run by make_seeds.py with h, the
# make_seeds module. A seed that starts with '{' is a document of rules; any other seed is a frame: a byte that chooses
# the member that sends it (bits 0 to 2) and the member it goes to (bits 3 to 5, 7 for an end outside the Network), a
# byte that moves the clock on by tens of ms (0xFF ages the conntrack tables), a byte whose low bits choose the VLAN, then
# the frame. The members of fuzz_policy.c: 0 alice (lab, every check), 1 bob (lab), 2 the lan bridge (lab), 3 the
# server (lab), 4 carol (wan), 5 the gateway (wan), 6 a member of the group staff (wan). lab is an L2 Network, wan an L3
# Network.

import struct

TARGET = 'fuzz_policy'

# The document of the engine of the frames of fuzz_policy.c, and documents that use every key
DOC_FRAMES = (
    b'{"networks": ['
    b'{"name": "lab", "mode": "l2", "maxFlows": 64, "timeouts": {"tcpEstablished": 60, "tcpTransitory": 5, "udp": 3, "icmp": 2, "other": 4}},'
    b'{"name": "wan", "mode": "l3", "maxFlows": 64}],'
    b'"addressGroups": [{"name": "servers", "addresses": ["10.0.0.0/24", "fd00::/64"]}],'
    b'"rules": ['
    b'{"name": "block-telnet", "action": "deny", "priority": 5, "protocol": "tcp", "ports": [23]},'
    b'{"name": "staff-web", "action": "allow", "priority": 10, "from": {"groups": ["staff"]}, "to": {"addressGroups": ["servers"]}, "protocol": "tcp", "ports": [80, 443, "8000-8080"]},'
    b'{"name": "dns", "action": "allow", "priority": 20, "protocol": "udp", "ports": [53]},'
    b'{"name": "ping", "action": "allow", "priority": 30, "protocol": "icmp", "direction": "both"},'
    b'{"name": "vlan-10", "action": "allow", "priority": 40, "networks": ["lab"], "vlans": [10]},'
    b'{"name": "gateway", "action": "allow", "priority": 50, "networks": ["wan"], "from": {"tags": ["gateway"]}},'
    b'{"name": "gre", "action": "allow", "priority": 60, "protocol": 47},'
    b'{"name": "lan", "action": "allow", "priority": 70, "from": {"tags": ["lan"]}, "protocol": "any", "direction": "both"}]}')

DOC_IDENTITY = (
    b'{"networks": [{"name": "lab", "mode": "l2", "maxFlows": 8}, {"name": "wan"}],'
    b' "addressGroups": [{"name": "admins", "addresses": ["192.0.2.0/28", "2001:db8::/48"]}, {"name": "empty"}],'
    b' "rules": ['
    b'{"name": "alice-ssh", "action": "allow", "priority": 1, "from": {"users": ["Alice"]}, "to": {"tags": ["server"], "addresses": ["10.0.0.2"]}, "protocol": "tcp", "ports": ["22", "2200-2299"]},'
    b'{"name": "admins-any", "action": "allow", "priority": 2, "from": {"addressGroups": ["admins", "empty"]}, "protocol": "ip", "direction": "both"},'
    b'{"name": "staff-dns", "action": "allow", "from": {"groups": ["staff"]}, "protocol": 17, "ports": [53, 5353]},'
    b'{"name": "deny-wan", "action": "deny", "priority": 1000000, "networks": ["wan"]},'
    b'{"name": "starter", "action": "allow", "priority": 999999}]}')

DOC_MINIMAL = b'{"networks": [{"name": "lab", "mode": "l2"}, {"name": "wan", "mode": "l3"}], "rules": [{"name": "all", "action": "allow"}]}'

# Documents that the engine refuses, each for one reason
DOC_BAD = {
    'doc_duplicate_key.json': b'{"networks": [{"name": "lab", "name": "wan"}]}',
    'doc_unknown_key.json': b'{"networks": [{"name": "lab", "defaultAction": "allow"}]}',
    'doc_bad_prefix.json': b'{"networks": [{"name": "lab"}], "rules": [{"name": "r", "action": "allow", "from": {"addresses": ["10.0.0.0/33"]}}]}',
    'doc_ports_without_protocol.json': b'{"networks": [{"name": "lab"}], "rules": [{"name": "r", "action": "allow", "ports": [80]}]}',
    'doc_unknown_network.json': b'{"networks": [{"name": "lab"}], "rules": [{"name": "r", "action": "deny", "networks": ["nope"]}]}',
    'doc_bad_range.json': b'{"networks": [{"name": "lab"}], "rules": [{"name": "r", "action": "allow", "protocol": "udp", "ports": ["90-80"]}]}',
    'doc_vlan_4095.json': b'{"networks": [{"name": "lab"}], "rules": [{"name": "r", "action": "allow", "vlans": [4095]}]}',
    'doc_not_json.json': b'{"networks": [',
    'doc_max_flows.json': b'{"networks": [{"name": "lab", "maxFlows": 1048577}]}',
}

MAC = [bytes([0x02, 0, 0, 0, 0, i + 1]) for i in range(8)]


def frame(h, src, dst, vlan, clock, data):
    # The three bytes in front of a frame: the members, the clock and the VLAN
    return bytes([(src & 7) | ((dst & 7) << 3), clock, vlan]) + data


def ip4(n):
    return [10, 0, 0, n]


def ip6(n):
    return bytes.fromhex('fd00000000000000000000000000') + bytes([0, n])


def ipv6(src, dst, next_header, payload):
    return struct.pack('>IHBB', 0x60000000, len(payload), next_header, 64) + src + dst + payload


def make_seeds(h):
    h.write_seed(TARGET, 'doc_frames.json', DOC_FRAMES)
    h.write_seed(TARGET, 'doc_identity.json', DOC_IDENTITY)
    h.write_seed(TARGET, 'doc_minimal.json', DOC_MINIMAL)
    for name, data in DOC_BAD.items():
        h.write_seed(TARGET, name, data)

    a, s = ip4(1), ip4(3)
    syn = h.tcp(a, s, 40000, 80, 1, 0, 0x02, b'')
    synack = h.tcp(s, a, 80, 40000, 9, 2, 0x12, b'')
    fin = h.tcp(a, s, 40000, 80, 2, 10, 0x11, b'')
    rst = h.tcp(s, a, 80, 40000, 10, 3, 0x14, b'')
    telnet = h.tcp(a, s, 40001, 23, 1, 0, 0x02, b'')
    dns = h.udp(a, s, 40002, 53, struct.pack('>HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0))
    echo = struct.pack('>BBHHH', 8, 0, 0, 0x4242, 1) + b'ping'
    reply = struct.pack('>BBHHH', 0, 0, 0, 0x4242, 1) + b'ping'
    syn_packet = h.ipv4(a, s, 6, syn)
    unreachable = struct.pack('>BBHI', 3, 1, 0, 0) + syn_packet[:28]

    # TCP between alice (0) and the server (3) in lab: the SYN, the answer, the end, a reset, and a denied port
    h.write_seed(TARGET, 'l2_tcp_syn.bin', frame(h, 0, 3, 0, 1, h.eth(MAC[3], MAC[0], 0x0800, syn_packet)))
    h.write_seed(TARGET, 'l2_tcp_synack.bin', frame(h, 3, 0, 0, 1, h.eth(MAC[0], MAC[3], 0x0800, h.ipv4(s, a, 6, synack))))
    h.write_seed(TARGET, 'l2_tcp_fin.bin', frame(h, 0, 3, 0, 1, h.eth(MAC[3], MAC[0], 0x0800, h.ipv4(a, s, 6, fin))))
    h.write_seed(TARGET, 'l2_tcp_rst.bin', frame(h, 3, 0, 0, 0xFF, h.eth(MAC[0], MAC[3], 0x0800, h.ipv4(s, a, 6, rst))))
    h.write_seed(TARGET, 'l2_tcp_telnet.bin', frame(h, 0, 3, 0, 1, h.eth(MAC[3], MAC[0], 0x0800, h.ipv4(a, s, 6, telnet))))
    h.write_seed(TARGET, 'l2_udp_dns.bin', frame(h, 0, 3, 0, 1, h.eth(MAC[3], MAC[0], 0x0800, h.ipv4(a, s, 17, dns))))
    h.write_seed(TARGET, 'l2_icmp_echo.bin', frame(h, 0, 1, 0, 1, h.eth(MAC[1], MAC[0], 0x0800, h.ipv4(a, ip4(2), 1, echo))))
    h.write_seed(TARGET, 'l2_icmp_reply.bin', frame(h, 1, 0, 0, 1, h.eth(MAC[0], MAC[1], 0x0800, h.ipv4(ip4(2), a, 1, reply))))
    h.write_seed(TARGET, 'l2_icmp_unreachable.bin',
                 frame(h, 2, 0, 0, 1, h.eth(MAC[0], MAC[2], 0x0800, h.ipv4(ip4(9), a, 1, unreachable))))

    # A tagged frame of VLAN 10, a frame of another EtherType, and a later fragment
    h.write_seed(TARGET, 'l2_vlan10_udp.bin',
                 frame(h, 1, 3, 1, 1, h.eth(MAC[3], MAC[1], 0x8100, struct.pack('>HH', 10, 0x0800) + h.ipv4(ip4(2), s, 17, h.udp(ip4(2), s, 5000, 9999, b'x')))))
    h.write_seed(TARGET, 'l2_non_ip.bin', frame(h, 2, 1, 0, 1, h.eth(MAC[1], MAC[2], 0x88B5, b'RANZ policy')))
    later = bytearray(h.ipv4(a, s, 17, b'\0' * 16, 7))
    later[6:8] = struct.pack('>H', 0x0002)
    h.write_seed(TARGET, 'l2_later_fragment.bin', frame(h, 0, 3, 0, 1, h.eth(MAC[3], MAC[0], 0x0800, bytes(later))))
    h.write_seed(TARGET, 'l2_tcp_cut_short.bin', frame(h, 0, 3, 0, 1, h.eth(MAC[3], MAC[0], 0x0800, syn_packet)[:40]))

    # What the segment needs: ARP, DHCP of a client and of a server, neighbour discovery and a router advertisement
    arp = struct.pack('>HHBBH', 1, 0x0800, 6, 4, 1) + MAC[0] + bytes(a) + b'\0' * 6 + bytes(s)
    h.write_seed(TARGET, 'l2_arp_request.bin', frame(h, 0, 7, 0, 1, h.eth(h.BROADCAST, MAC[0], 0x0806, arp)))
    zero, bcast = [0, 0, 0, 0], [255, 255, 255, 255]
    bootp = struct.pack('>BBBBIHH', 1, 1, 6, 0, 0x2A2B2C2D, 0, 0x8000) + b'\0' * 16 + MAC[0] + b'\0' * 202 + b'\x63\x82\x53\x63\x35\x01\x01\xff'
    h.write_seed(TARGET, 'l2_dhcp_discover.bin',
                 frame(h, 0, 7, 0, 1, h.eth(h.BROADCAST, MAC[0], 0x0800, h.ipv4(zero, bcast, 17, h.udp(zero, bcast, 68, 67, bootp)))))
    h.write_seed(TARGET, 'l2_dhcp_offer.bin',
                 frame(h, 0, 7, 0, 1, h.eth(h.BROADCAST, MAC[0], 0x0800, h.ipv4(a, bcast, 17, h.udp(a, bcast, 67, 68, bootp)))))
    link = bytes.fromhex('fe800000000000000000000000000001')
    all_nodes = bytes.fromhex('ff020000000000000000000000000001')
    ra = struct.pack('>BBHBBHII', 134, 0, 0, 64, 0, 1800, 0, 0)
    ns = struct.pack('>BBHI', 135, 0, 0, 0) + link + b'\x01\x01' + MAC[0]
    h.write_seed(TARGET, 'l2_ipv6_ra.bin', frame(h, 0, 7, 0, 1, h.eth(bytes.fromhex('333300000001'), MAC[0], 0x86DD, ipv6(link, all_nodes, 58, ra))))
    h.write_seed(TARGET, 'l2_ipv6_ns.bin', frame(h, 0, 7, 0, 1, h.eth(bytes.fromhex('3333ff000002'), MAC[0], 0x86DD, ipv6(link, all_nodes, 58, ns))))

    # IPv6 TCP with a hop-by-hop header and a first fragment, from bob to the server
    hop = struct.pack('>BB', 44, 0) + b'\x01\x04\0\0\0\0'
    fragment = struct.pack('>BBHI', 6, 0, 0x0001, 0x12345678)
    tcp6 = struct.pack('>HHIIBBHHH', 40000, 443, 1, 0, 5 << 4, 0x02, 65535, 0, 0)
    h.write_seed(TARGET, 'l2_ipv6_tcp_ext.bin',
                 frame(h, 1, 3, 0, 1, h.eth(MAC[3], MAC[1], 0x86DD, ipv6(ip6(2), ip6(3), 0, hop + fragment + tcp6))))

    # wan, an L3 Network: GRE from carol to the gateway, an ICMPv6 echo of the gateway, and a packet of no IP version
    gre = struct.pack('>HH', 0, 0x0800)
    h.write_seed(TARGET, 'l3_gre.bin', frame(h, 4, 5, 0, 1, h.ipv4(ip4(4), ip4(5), 47, gre)))
    echo6 = struct.pack('>BBHHH', 128, 0, 0, 0x7777, 1) + b'ping'
    h.write_seed(TARGET, 'l3_icmpv6_echo.bin', frame(h, 5, 7, 0, 1, ipv6(ip6(5), ip6(9), 58, echo6)))
    h.write_seed(TARGET, 'l3_not_ip.bin', frame(h, 6, 4, 0, 1, b'\x50' + b'\0' * 30))
