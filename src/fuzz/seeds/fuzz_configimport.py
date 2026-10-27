# fuzz_configimport.py
# Seeds of fuzz_configimport (src/fuzz/fuzz_configimport.c): the config importer of the configuration store
# (src/Cedar/ConfigStoreImport.c, CORE-F5 #65), which reads the file of a fork configuration. The seeds are the fork
# configuration of vpntest store (tests/golden/store/fork_server.config), which imports two hubs with their CAs and
# users, the listeners, the server certificate and its chain and the administrators, and leaves out the rows that the
# store refuses; the configuration without ServerConfiguration that the test refuses; a fork configuration in the binary
# format (SEVPN_DB and the SHA-0 of its body, as CfgReadW reads it); and the server configurations of fuzz_cfg.
#
# make_seeds.py runs make_seeds(h), h being make_seeds.py itself with write_seed and the Cfg helpers.

import os


def user(h, name, auth, items):
    # A user folder of a hub as the fork writes one: the importer reads these items, and the ones of its kind of login
    return (name, [], [('AuthType', h.ITEM_TYPE_INT, auth), ('RealName', h.ITEM_TYPE_STRING, 'User ' + name),
                       ('Note', h.ITEM_TYPE_STRING, 'note'), ('ExpireTime', h.ITEM_TYPE_INT64, 0)] + items)


def make_seeds(h):
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(h.__file__))))
    with open(os.path.join(root, 'tests', 'golden', 'store', 'fork_server.config'), 'rb') as f:
        h.write_seed('fuzz_configimport', 'fork_server.config', f.read())

    # What vpntest store writes for a file that is no fork configuration: a hub and no ServerConfiguration
    h.write_seed('fuzz_configimport', 'no_server.config',
                 b'declare root\r\n{\r\n\tdeclare VirtualHUB\r\n\t{\r\n\t\tdeclare LOST\r\n\t\t{\r\n\t\t}\r\n\t}\r\n}\r\n')

    # A fork configuration in the binary format: a hub with a user of each kind of login that the importer reads, two
    # listeners, one without a port, and ServerConfiguration with the hash of a password and a server key that the import
    # leaves out
    body = h.cfg_bin_folder('root', [
        ('ListenerList', [
            ('Listener0', [], [('Enabled', h.ITEM_TYPE_BOOL, 1), ('Port', h.ITEM_TYPE_INT, 443)]),
            ('Listener1', [], [('Enabled', h.ITEM_TYPE_BOOL, 0), ('Port', h.ITEM_TYPE_INT, 0)]),
        ], []),
        ('ServerConfiguration', [], [
            ('HashedPassword', h.ITEM_TYPE_BYTE, bytes(range(20))),
            ('ServerKey', h.ITEM_TYPE_BYTE, b'not a key'),
        ]),
        ('VirtualHUB', [
            ('BINHUB', [
                ('SecurityAccountDatabase', [
                    ('CertList', [], []),
                    ('UserList', [
                        user(h, 'anon', 0, []),
                        user(h, 'pass', 1, [('AuthPassword', h.ITEM_TYPE_BYTE, bytes(20))]),
                        user(h, 'nt', 5, [('AuthNtUserName', h.ITEM_TYPE_STRING, 'DOMAIN\\nt')]),
                        user(h, 'root', 3, [('AuthCommonName', h.ITEM_TYPE_STRING, 'root-cn'), ('AuthSerial', h.ITEM_TYPE_BYTE, bytes([1, 2, 3]))]),
                    ], []),
                ], []),
            ], [('Online', h.ITEM_TYPE_BOOL, 1), ('HashedPassword', h.ITEM_TYPE_BYTE, bytes(range(1, 21)))]),
        ], []),
    ], [('ConfigRevision', h.ITEM_TYPE_INT, 1)])
    h.write_seed('fuzz_configimport', 'fork_server_binary.config', h.cfg_bin_file(body))

    # The server configurations of fuzz_cfg, which have ServerConfiguration and no hub
    h.write_seed('fuzz_configimport', 'server_text.config', h.TAG_CPYRIGHT + b'\r\n' + h.CFG_TEXT)
    h.write_seed('fuzz_configimport', 'server_binary.config', h.cfg_bin_file(h.cfg_bin_folder('root', [
        ('ServerConfiguration', [], [
            ('HashedPassword', h.ITEM_TYPE_BYTE, bytes(range(20))),
            ('ServerName', h.ITEM_TYPE_STRING, 'Ranz VPN ' + h.E_ACUTE),
        ]),
    ], [('ConfigRevision', h.ITEM_TYPE_INT, 3)])))
