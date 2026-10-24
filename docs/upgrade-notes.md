# Upgrade notes

What an existing server shows after an upgrade. Newest first.

## SDN-54 (#247): old log files go at the first start

The log of the Controller service (`controller.log` in its data directory), the log of a Node (`node_log` in its data directory) and the log of the BGP sidecar of the Node (`ranz-bgp.log` in the same folder) now keep within an age limit of 30 days and a disk limit of 256 MB. At the first start after the upgrade, the files of these logs whose last record is older than 30 days are deleted, and so are the oldest files beyond 256 MB together, with the log file that is open counted at the size it may grow to (a quarter of the limit). A file that another program holds open stays and is tried again every hour.

To keep more, start the Controller with `-log-days` and `-log-mb`, or set the settings `LogDays` and `LogMB` in the Configuration store of the Node; 0 is no limit. The Controller logs to its standard error, and so keeps no file, when it runs in the foreground or on Linux.

## FIX-5 (#101): the virtual hub MAC address and address change once

The machine identity of a server now comes from the MachineGuid of Windows (`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`) and a random 32-byte salt that the config file keeps as the `byte MachineIdSalt` item of `ServerConfiguration`. It used to come from the host name, the host IP addresses and the OS version.

On the first start after the upgrade:

- The config file has no `MachineIdSalt` yet. The server draws one and saves it at start-up.
- Every virtual hub gets a new MAC address (`00:AE:xx:xx:xx:xx`), a new hub address (`172.31.x.x`) and, from the new MAC address, a new IPv6 link-local address. Hosts on the hub segment learn the new MAC address from the next ARP or neighbour exchange. Static ARP entries, MAC filters or access lists that name the old hub MAC address need the new one.
- The `unique_id` that a Cascade sends when it logs in to another server changes.

After that, the identity stays the same across restarts, host renames, IP address changes and OS updates.

Other cases:

- Two servers cloned from one image share the MachineGuid. They get separate identities only if each has its own config file: an image made before the server first started has none, so each clone draws its own salt. An image that already holds the config file gives every clone the same salt, and with it the same hub MAC address and address. On each such clone, stop the server, delete the `byte MachineIdSalt` line from the `ServerConfiguration` folder of the config file, and start it again; it draws and saves a new salt.
- A config file restored on the same machine keeps the identity. Restored on a different machine, it gives a new identity, because the MachineGuid differs. A new config file, or one without `MachineIdSalt`, gives a new identity.
- Two server instances on one machine no longer share the identity. A Cascade between them still counts as a local-host session, because the server also checks whether the peer address is one of its own.
