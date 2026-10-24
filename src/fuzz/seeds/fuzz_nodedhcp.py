# Seeds of fuzz_nodedhcp, run by make_seeds.py (h is that module).
#
# DHCP responder of an L2 Network (src/Cedar/NodeDhcp.c NodeDhcpInput): the first byte picks the configuration of
# fuzz_nodedhcp.c (0: the /24 pool 10.20.0.0 with the responder at .2 and two reservations, 1: the same with the mode
# off, 2: the /30 pool 10.30.0.0 with the responder at .1); then each frame after a byte that moves the clock on, in
# seconds, and its size in 2 bytes. The frames are the ones of the members of the switch of the Network: the DHCP
# messages of clients (a lease from DISCOVER to RELEASE, a renewal by unicast, INIT-REBOOT, DECLINE, INFORM), the answer
# of a DHCP server of the LAN, and an ARP request for the responder's own address.

import struct

COOKIE = b'\x63\x82\x53\x63'
RESPONDER = bytes.fromhex('020000004301')    # fuzz_dhcp_mac of fuzz_nodedhcp.c
SERVER = [10, 20, 0, 2]
LEASED = [10, 20, 0, 8]
NOWHERE = [0, 0, 0, 0]
EVERYONE = [255, 255, 255, 255]


def message(op, msg_type, chaddr, xid, ciaddr=NOWHERE, options=b'', broadcast=True):
    # The fixed header (236 bytes), the magic cookie, the message type, the options and End, padded to 300 bytes
    hdr = struct.pack('>BBBBIHH', op, 1, 6, 0, xid, 0, 0x8000 if broadcast else 0)
    hdr += bytes(ciaddr) + b'\0' * 12                    # ciaddr; yiaddr, siaddr and giaddr
    hdr += chaddr + b'\0' * 10 + b'\0' * 192             # chaddr (16 bytes), sname and file
    assert len(hdr) == 236
    return (hdr + COOKIE + bytes([53, 1, msg_type]) + options + b'\xff').ljust(300, b'\0')


def address(code, a):
    return bytes([code, 4]) + bytes(a)


def host_name(name):
    return bytes([12, len(name)]) + name


def step(seconds, data):
    return bytes([seconds]) + struct.pack('>H', len(data)) + data


def make_seeds(h):
    def seed(name, data):
        h.write_seed('fuzz_nodedhcp', name, data)

    def client(mac, msg_type, xid, ciaddr=NOWHERE, options=b'', to=EVERYONE, to_mac=h.BROADCAST, broadcast=True):
        payload = message(1, msg_type, mac, xid, ciaddr, options, broadcast)
        return h.eth(to_mac, mac, 0x0800, h.ipv4(ciaddr, to, 17, h.udp(ciaddr, to, 68, 67, payload)))

    select = address(50, LEASED) + address(54, SERVER)
    discover = client(h.MAC_A, 1, 0x1001, options=host_name(b'client-a'))
    request = client(h.MAC_A, 3, 0x1001, options=select + host_name(b'client-a'))
    seed('lease.bin', b'\x00' + step(0, discover) + step(1, request))

    renew = client(h.MAC_A, 3, 0x1002, ciaddr=LEASED, to=SERVER, to_mac=RESPONDER, broadcast=False)
    release = client(h.MAC_A, 7, 0x1003, ciaddr=LEASED, options=address(54, SERVER), to=SERVER, to_mac=RESPONDER, broadcast=False)
    seed('renew_release.bin', b'\x00' + step(0, discover) + step(0, request) + step(255, renew) + step(1, release))

    decline = client(h.MAC_A, 4, 0x1004, options=select)
    seed('decline.bin', b'\x00' + step(0, discover) + step(0, request) + step(2, decline) + step(0, discover))

    init_reboot = client(h.MAC_B, 3, 0x2001, options=address(50, [10, 99, 0, 5]))
    other_server = client(h.MAC_B, 3, 0x2002, options=address(50, [10, 20, 0, 9]) + address(54, [10, 20, 0, 250]))
    seed('nak_other_server.bin', b'\x00' + step(0, init_reboot) + step(0, other_server))

    inform = client(h.MAC_B, 8, 0x2003, ciaddr=[10, 20, 0, 200], to=SERVER, to_mac=RESPONDER, broadcast=False)
    seed('inform.bin', b'\x00' + step(0, inform))

    # The answer of a DHCP server of the LAN to the probe, by broadcast, then a client that gets no answer
    lan = [192, 168, 1, 1]
    offer = message(2, 2, RESPONDER, 0x5A4E4152, options=address(54, lan) + address(51, [0, 0, 14, 16]))
    lan_offer = h.eth(h.BROADCAST, h.MAC_B, 0x0800, h.ipv4(lan, EVERYONE, 17, h.udp(lan, EVERYONE, 67, 68, offer)))
    seed('lan_server.bin', b'\x00' + step(0, lan_offer) + step(5, discover))

    arp = struct.pack('>HHBBH', 1, 0x0800, 6, 4, 1) + h.MAC_A + bytes(LEASED) + b'\0' * 6 + bytes(SERVER)
    seed('arp.bin', b'\x00' + step(0, h.eth(h.BROADCAST, h.MAC_A, 0x0806, arp)))

    seed('mode_off.bin', b'\x01' + step(0, discover) + step(0, request))

    # The /30 pool holds one client: the second gets no offer
    seed('tiny_pool.bin', b'\x02' + step(0, discover) + step(0, client(h.MAC_B, 1, 0x2004)))
