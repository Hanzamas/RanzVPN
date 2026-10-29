# Upgrade notes

What an existing server shows after an upgrade. Newest first.

## AUD1-DT-16 (#501): a cluster of Controllers seals the secrets of its targets with a Cluster key

A cluster of Controllers, whose members run with `-rqlite-join`, kept the secrets of its export and audit targets in clear, since its members have no key in common. It seals them now with a Cluster key: one key of the cluster, which each member holds in memory and the store holds only as a copy for each member, sealed to the key of that member's host. At the first start of a member of this release:

- **The cluster gets its Cluster key, and the secrets are sealed.** The first member of this release that starts makes the Cluster key, logs `this member holds the Cluster key: it made it`, seals the secrets that the store holds in clear, and logs `sealed the secrets of the targets that were in clear, with the Cluster key` with how many. Each member that starts after it publishes the public half of the key of its host in the store, gets a copy of the Cluster key from a member that holds it within seconds, and logs `this member holds the Cluster key: its copy opens`. The targets send as before, and the API still never shows a secret.
- **During the rolling upgrade** a member of the earlier release cannot open a sealed secret. While one leads, the targets are sent without their secrets (a webhook unsigned, which a receiver that checks the signature refuses and the Controller sends again later; an OTLP endpoint without its bearer token), and its log says `the secret of a target cannot be opened`. Upgrade the members one after the other, without a pause: once a member of this release leads, the targets are sent with their secrets again. A target that a member of the earlier release puts meanwhile is in clear until a member of this release seals it, within a minute.
- **A member that holds no Cluster key yet** refuses a target with a secret, says `this member does not hold the Cluster key yet` in its log, and sends to the targets without their secrets until it gets its copy, which a member that holds the key gives it within seconds.
- **A backup of a cluster holds the secrets sealed**, and the Cluster key only as copies that the key of each member opens. A restore keeps the Cluster key of the cluster that it restores into: a backup of the same cluster opens as it was, and a backup of another cluster, or one restored on a single Controller, brings its targets back with their names, URLs and types and with no secret, as a backup restored on another host does. Put each target again with its secret. A backup that the cluster made before the upgrade holds the secrets in clear: make a new one and delete the old one.
- **When every member loses the key of its host at once**, for instance when every member that ran in the foreground runs as the service, whose account has another key set, no member can open its copy. A minute later a member makes a new Cluster key and logs `the Cluster key was lost`, and the targets are sent without their secrets until each is put again. Change the members one after the other instead, and the members that still hold the key give the others a copy.
- **A rollback** to the earlier release: its members cannot open a sealed secret, and send to the targets without their secrets until each is put again.
- A single Controller that becomes a member of a cluster keeps the secrets that the key of its host sealed, which the other members cannot open: put each target again once the cluster has formed.

## AUD1-DT-10 (#458): the secrets of the targets are sealed, a backup is for the Administrators, the data directory has an owner

The Controller's files on its host changed in three ways. At the first start after the upgrade:

- **The secrets of the export and audit targets are sealed.** The HMAC key of a webhook and the bearer token of an OTLP endpoint were in the store in clear. The Controller now seals each one with a key of its host (an X25519 key of the Microsoft Software Key Storage Provider, named after the data directory, in the key set of the account of the service) and logs `sealed the secrets of the targets that an earlier release kept in clear` with how many. The targets send as before, and the API still never shows a secret. A Controller with `-rqlite-join`, a member of a cluster, keeps the secrets in clear, since the members have no key in common, and says so in its log at each start.
- **A backup holds them sealed, and has an access list of its own.** A backup that `ranz controller backup` writes is readable by SYSTEM and the Administrators only, whatever the access list of its folder says, and its text names everything that it holds (the Intent, the audit log, the hashes of the tokens and of the passwords, the licence key and the secrets of the targets). A backup made before the upgrade holds the secrets in clear and has the access list of its folder: make a new one and delete the old one, or keep the old one as safe as the data directory.
- **The service does not start in a data directory that another account owns.** The data directory must be owned by SYSTEM, the Administrators or `NT SERVICE\ranz-controller`. One that `ranz install` made, or that the service made, is. One that a user made and put in the place of the real one is not: the service does not start, writes a failure (event ID 3) to the Application log that names the owner, and `ranz controller reset-admin`, `backup` and `restore` refuse the directory too. Look at what it holds, then remove it, or, when it is yours, give it to the Administrators with `takeown /F "C:\ProgramData\Ranz\controller" /A /R /D Y`, and start the service again. A data directory that is a link (a junction or a symbolic link) is refused the same way: name the folder itself with `-data`. `ranz install --controller` takes over a data directory that another account made only when it is empty (it makes it again), and refuses one that holds files, with a message.

What a restore does with the secrets: they open only with the key of the host that sealed them. After `ranz controller restore` on **another host**, on a host whose key storage was rebuilt, or with the data directory at another path, the targets come back with their names, their URLs and their types and with no secret. The Controller sends to them with none (a webhook unsigned, an OTLP endpoint with no bearer token), logs at its start `the secret of a target cannot be opened with the sealing key of this host` for each one, and `GET /api/v1/targets` shows `hasSecret` false. Put each target again with its secret (`PUT /api/v1/targets/{name}`, and `/api/v1/audit/targets/{name}` for an audit target). A restore on the same host keeps them working.

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
