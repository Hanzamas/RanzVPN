# The clients guide: join a Network with a stock WireGuard client

A Device is a phone, a laptop or a router that joins exactly one Network of Ranz VPN over standard WireGuard, without `ranz.exe`. It runs the WireGuard client that its platform has already, and it reaches the overlay through a gateway Node that terminates WireGuard for it. This guide is for the person who sets such a client up. It says how an administrator makes a Device, and then, one section for each client, how the Device imports what the Controller made for it.

| Device | Client | What it imports |
|---|---|---|
| Windows | WireGuard for Windows | the `.conf` file |
| Android | WireGuard (Google Play, F-Droid) | the QR code, or the file |
| iOS | WireGuard (App Store) | the QR code, or the file |
| macOS | WireGuard (Mac App Store) | the file |
| Linux | `wireguard-tools`, `wg-quick` | the file |
| MikroTik RouterOS 7 | built in | the values of the configuration, typed as commands |
| OpenWrt | `wireguard-tools` and `luci-proto-wireguard` | the values of the configuration, in `/etc/config/network` |

Two things are the same everywhere. The Controller makes the keys of a Device, or takes the public key that you give it, and shows the finished configuration once. And what a Device may reach is not decided by the client: it is decided by the policy of the VRF, by the address and the tags of the Device, as it is for a Node.

## Before you make a Device

The Intent of your Controller needs three things.

- An L3 Network with an IPv4 pool, an IPv6 pool or both. A Device never joins an L2 Network, because WireGuard carries no L2. The examples here use the Network `lab-net` of the VRF `lab`, with the pools `10.70.0.0/24` and `fd07:7:7:1::/64`.
- A gateway Node in the VRF of that Network. It is a Windows Node on which WireGuardNT loads: `ranz install` puts `wireguard.dll` there, unless it ran with `-no-wireguard`. Its Node resource has the field `wireguard`, with `endpoint`, the DNS name that its Devices reach it at, and optionally `port`, UDP 51820 by default. When the driver loads, the Node reports the Capability `wireguard` and the key of its WireGuard interface, and `ranz get nodes` shows them. The Controller refuses a Device whose gateway does not report the Capability, and its answer names the Node and the Device.
- The UDP port of the gateway open to the internet, or forwarded to the gateway by the NAT in front of it. `docs/ports.md` lists it.

## Make a Device

You need the role operator. Each Device has a name, one Network and one gateway Node. The examples use the gateway `gw`, whose `endpoint` is `gw.example.net`.

The Devices page of the web UI (`/devices`) has the form Make a Device: choose the Network and the gateway, give an owner and tags if you want them, and press Make. The page shows the finished configuration and its QR code, and offers Save as a .conf file. The same from a terminal:

```
ranz device create -network lab-net -gateway gw -tags phones -o phone.conf -qr phone
```

That writes the configuration to `phone.conf`, a new file that only its owner can read (on Windows, also SYSTEM and the Administrators), and draws the QR code on the terminal. With `-qr-file phone.png` it writes the QR code as a PNG file, a new file of the same kind, and without `-o` it prints the configuration on standard output. `ranz` never writes the keys over a file that exists: it refuses such a file before it makes the Device, so name a new file.

On Windows, `ranz` turns on the colour codes of the console for the QR code, so that it shows black on white. If your phone does not read the code on the terminal, for example on an old Windows console, use `-qr-file` and scan the PNG file on the screen instead.

A Device can have an owner, a User (`-owner alice`, the field Owner of the form). It then carries the groups of the User as tags, besides its own, and it counts against the maximum devices of the User. The owner sees the Device on the page My devices of the portal (`/portal`), with the last handshake that its gateway reported, and can remove it there; making a Device is still the work of an administrator. A standalone Device, for example a router, has no owner and takes the tags that you set on it (`-tags`).

### A router, or your own key

A router, or anyone who wants the private key never to leave the Device, makes the key pair on the Device and gives the Controller the public key:

```
ranz device create -network lab-net -gateway gw -public-key JE/juWPomd0pW6/84kjTUw86mnR5ugYwAmgOv+etrUk= router
```

The form has the field Public key for it. The Controller makes the PresharedKey and shows it once. The configuration says where the private key of the Device goes: it has the line `# PrivateKey = the private key of this Device, which only the Device holds` in place of a key.

### The keys show once

The Controller makes the key pair of a Device that you gave no public key, and a PresharedKey for every Device. The private key is in the one answer that shows the configuration and in nothing that the Controller keeps: not the store, not the Intent or its revisions, not a log, not the audit log, not a diagnostics bundle. The PresharedKey is kept sealed, and goes in clear to the gateway alone. Neither is shown again. `ranz get device-config phone` prints the configuration later, with a comment in place of each key. If a configuration is lost before a Device imported it, make a new Device and delete the old one: a key is never changed in place.

The configuration and the QR code hold the keys, so treat them as secrets. Delete the file once the Device has imported it.

## The configuration

This is the finished configuration of the Device `phone` that the Controller made the key pair for. The keys here are placeholders, and the addresses are the ones of the example Network. Every example below uses these values, so replace each of them with the one in your own configuration.

```ini
# Ranz VPN: the WireGuard configuration of Device phone, of Network lab-net in VRF lab
[Interface]
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
Address = 10.70.0.3/32, fd07:7:7:1::3/128
MTU = 1280

[Peer]
# The gateway, Node gw
PublicKey = ERERERERERERERERERERERERERERERERERERERERERE=
PresharedKey = AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=
Endpoint = gw.example.net:51820
AllowedIPs = 10.70.0.0/24, fd07:7:7:1::/64
PersistentKeepalive = 25
```

And this is the one of the Device `router`, whose public key was given, so that its private key stays on the router:

```ini
# Ranz VPN: the WireGuard configuration of Device router, of Network lab-net in VRF lab
[Interface]
# PrivateKey = the private key of this Device, which only the Device holds
Address = 10.70.0.4/32, fd07:7:7:1::4/128
MTU = 1280

[Peer]
# The gateway, Node gw
PublicKey = ERERERERERERERERERERERERERERERERERERERERERE=
PresharedKey = BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=
Endpoint = gw.example.net:51820
AllowedIPs = 10.70.0.0/24, fd07:7:7:1::/64
PersistentKeepalive = 25
```

What its lines say:

- `Address` is the address of the Device in each pool of its Network, one IPv4 and one IPv6 address. The Controller gives it the lowest free one and keeps it for as long as the Device is in that Network.
- `MTU` is the MTU of the VRF, 1280 unless the VRF sets another.
- `[Peer]` is the gateway, the one end of the tunnel. This is how WireGuard names it in a configuration. In Ranz, a Device is never called a peer. `PublicKey` is the key of the WireGuard interface of the gateway.
- `PresharedKey` is the secret that only this Device and its gateway share (see The PresharedKey and quantum computers).
- `Endpoint` is the DNS name and the UDP port of the gateway. It is a name so that the gateway can move without a change on any Device (see Failover of a gateway).
- `AllowedIPs` are the pools of every Network of the VRF: a split tunnel, in which only traffic for the overlay goes into the tunnel. What the Device reaches in those prefixes is up to policy.
- `PersistentKeepalive = 25` keeps the NAT mapping of the Device open on a mobile network. The battery saver (`-battery-saver`, or the box Battery saver in the form) leaves the line out, for a Device that only starts connections and should not wake its radio for a keepalive.
- The configuration has no `DNS` line. Reach hosts by their overlay addresses.

## Windows

1. Install WireGuard for Windows from wireguard.com.
2. Save the configuration as a `.conf` file: `ranz device create -o phone.conf ...`, or Save as a .conf file on the Devices page. The Windows app does not scan QR codes.
3. In the app, open Add Tunnel, then Import tunnel(s) from file, and choose the file. The name of the file is the name of the tunnel.
4. Press Activate.
5. Delete the `.conf` file. The app keeps its own copy, encrypted.

## Android

1. Install WireGuard from Google Play or F-Droid.
2. Open the app and press the plus button, then Scan from QR code. Allow the camera, and scan the QR code on the Devices page or on the terminal. Give the tunnel a name.
3. Or press the plus button, then Import from file or archive, and choose the `.conf` file.
4. Switch the tunnel on. Android asks once to allow the VPN connection.

A phone on a mobile network keeps its tunnel open with the keepalive of 25 seconds. If a Device only starts connections and the battery matters more, make it with the battery saver.

## iOS

1. Install WireGuard from the App Store.
2. Open the app and press Add a tunnel, then Create from QR code. Allow the camera, scan the QR code, and give the tunnel a name.
3. Or press Add a tunnel, then Create from file or archive, and open the `.conf` file from the Files app or AirDrop.
4. Allow iOS to add the VPN configuration, and switch the tunnel on.

## macOS

1. Install WireGuard from the Mac App Store.
2. Save the configuration as a `.conf` file. The macOS app does not scan QR codes.
3. In the app, press the plus button at the bottom left, then Import tunnel(s) from file, and choose the file.
4. Press Activate.

A Mac can use `wireguard-tools` from a package manager instead, as in the next section.

## Linux (wg-quick)

Install `wireguard-tools` with the package manager of your distribution (`sudo apt install wireguard-tools`, `sudo dnf install wireguard-tools`, `sudo pacman -S wireguard-tools`). The kernel has WireGuard since Linux 5.6.

```
sudo install -m 600 phone.conf /etc/wireguard/ranz.conf
sudo wg-quick up ranz
sudo wg show ranz
```

The name of the file is the name of the interface, `ranz` here, at most 15 characters. `wg show` prints the `latest handshake` once the tunnel has carried traffic. To bring the tunnel up at every start and to take it down:

```
sudo systemctl enable --now wg-quick@ranz
sudo wg-quick down ranz
```

`wg-quick` sets the two addresses and the MTU, and routes the `AllowedIPs` into the tunnel.

## MikroTik RouterOS 7

RouterOS 7 has WireGuard built in. A router keeps its private key, so give the Controller the public key of the router when you make the Device. On the router, make the interface, and read its public key:

```
/interface wireguard add name=ranz mtu=1280
/interface wireguard print
```

Make the Device `router` with that `public-key`, as in the section on a router above, and take the values of its configuration (the second one in this guide). Then set the gateway as the one peer of the interface, give the interface its addresses, and route the pools into it:

```
/interface wireguard peers add interface=ranz name=gw public-key="ERERERERERERERERERERERERERERERERERERERERERE=" preshared-key="BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=" endpoint-address=gw.example.net endpoint-port=51820 allowed-address=10.70.0.0/24,fd07:7:7:1::/64 persistent-keepalive=25s
/ip address add address=10.70.0.4/32 interface=ranz
/ipv6 address add address=fd07:7:7:1::4/128 interface=ranz advertise=no
/ip route add dst-address=10.70.0.0/24 gateway=ranz
/ipv6 route add dst-address=fd07:7:7:1::/64 gateway=ranz
```

RouterOS does not make routes from `allowed-address`, so the two routes are needed. The router itself is the Device and has the one address of the configuration. For the hosts of its LAN to reach the overlay, give them the address of the router by source NAT:

```
/ip firewall nat add chain=srcnat out-interface=ranz action=masquerade comment="Ranz"
```

`/interface wireguard peers print` shows the `last-handshake` once the tunnel is up. If you would rather import a private key that the Controller made, make the Device without `-public-key` and type that key as `private-key=` of the interface.

## OpenWrt

Install `wireguard-tools` and `luci-proto-wireguard` with the package manager of your release (`opkg`, or `apk` on a newer one), and restart the network. A router keeps its private key, so make it on the router, and give the Controller the public key when you make the Device:

```
umask 077
wg genkey > /etc/ranz.key
wg pubkey < /etc/ranz.key
```

Make the Device `router` with that public key, and take the values of its configuration (the second one in this guide). In `/etc/config/network`, with the private key from `/etc/ranz.key`:

```
config interface 'ranz'
	option proto 'wireguard'
	option private_key 'THE PRIVATE KEY OF THE ROUTER'
	list addresses '10.70.0.4/32'
	list addresses 'fd07:7:7:1::4/128'
	option mtu '1280'

config wireguard_ranz
	option description 'gw'
	option public_key 'ERERERERERERERERERERERERERERERERERERERERERE='
	option preshared_key 'BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ='
	option endpoint_host 'gw.example.net'
	option endpoint_port '51820'
	option persistent_keepalive '25'
	option route_allowed_ips '1'
	list allowed_ips '10.70.0.0/24'
	list allowed_ips 'fd07:7:7:1::/64'
```

Then `/etc/init.d/network restart`, and `wg show ranz` for the handshake. For the LAN to reach the overlay, put the interface in a firewall zone with masquerading, and let the LAN forward to it:

```
config zone
	option name 'ranz'
	list network 'ranz'
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option masq '1'
	option mtu_fix '1'

config forwarding
	option src 'lan'
	option dest 'ranz'
```

The zone goes into `/etc/config/firewall`, followed by `/etc/init.d/firewall restart`.

## Check that it works

Ping an overlay host that the policy lets the Device reach. The gateway reports the last handshake and the traffic of each Device: `ranz get devices` prints them, and so does the Devices page of the web UI. A Device whose gateway has seen no handshake shows none.

```
ranz get devices
```

## Revoke a Device

A lost phone or a retired router is cut off with the next generation of its gateway. Press Revoke on the Devices page, or delete the Device:

```
ranz delete Device phone
```

The Controller removes the Device and its PresharedKey, and the gateway stops terminating the Device. To replace the keys of a Device, make a new Device with a new name and delete the old one, which is the one way to rotate: no key is changed in place.

## Windows Server RRAS (IKEv2)

Some devices cannot run WireGuard: a phone or a router whose firmware has only the IKEv2 client of its vendor, or a PC on which no app may be installed. Windows Server can terminate IKEv2 for them with Routing and Remote Access (RRAS, the Remote Access role).

This is a note, not a feature of Ranz. Ranz does not install, configure or watch RRAS, and it has no IKEv2 server of its own. An IKEv2 client is not a Device: it gets no key, no QR code and no row on the Devices page. If the host that runs RRAS is also a Node that forwards, you can let the overlay reach those clients as it reaches any LAN behind a gateway Node: give RRAS a static address pool, declare that prefix in `lanSubnets` of the Node resource for the VRF, and write the policy for it. How to install and set up RRAS is in the documentation of Microsoft.

## Failover of a gateway

A Device uses one gateway, and until gateway failover exists its Devices are down while that gateway is down. What you do then is manual, and it depends on what has happened.

The gateway is the same Node, now at another address: repoint the DNS name. The `Endpoint` of every Device is the name in `wireguard.endpoint` of the gateway Node, so change the record of that name to the new address, and no Device changes. Give the record a short time to live before you need to move it. A client looks the name up when its tunnel starts and does not look it up again by itself, so turn the tunnel of each Device off and on after the change. A Linux interface can be told to look it up again with the script `reresolve-dns.sh` that comes with `wireguard-tools`.

The gateway is lost, and another Node takes over. The new Node has its own key, so repointing the name is not enough. Set the `gateway` of each Device to the new Node and apply it, and give each Device the two lines of its `[Peer]` section that change. `ranz export -o yaml` prints the Intent: save it as `intent.yaml`, change the `gateway` of each Device in it, and apply it.

```
ranz export -o yaml
ranz apply -f intent.yaml
ranz get device-config phone
```

The new gateway must be a Node of the VRF of the Network, with a `wireguard` end, on which WireGuardNT loads. The Controller gives the PresharedKey of each Device to its new gateway, and each Device keeps its addresses, its private key and its PresharedKey. On each Device, replace `PublicKey` and `Endpoint` under `[Peer]` with the ones that `ranz get device-config` prints.

## The PresharedKey and quantum computers

WireGuard has no post-quantum key exchange of its own: its handshake uses Curve25519. Someone who records the traffic of a Device today, and one day has a quantum computer that breaks Curve25519, could read the recording then. A PresharedKey is the one protection against that. It is a secret of 256 bits that the Device and its gateway both mix into the handshake, and a recorded session stays unreadable without it, even when Curve25519 is broken.

So the Controller makes a PresharedKey for every Device, by default, and carries it in the configuration. What follows from that for you:

- The PresharedKey is in the configuration file and in the QR code, with the private key. Treat both as secrets, and delete the file once the Device has imported it. Whoever has the PresharedKey and later breaks Curve25519 can read the traffic that they recorded.
- The Controller keeps the PresharedKey sealed, as it keeps the secrets of its export and audit targets: to the sealing key of the Controller, a key of the Microsoft Software Key Storage Provider that never leaves it. A cluster of Controllers seals it with its Cluster key, which each member holds through a copy that the sealing key of its own host opens (ADR-0026). A backup of the store holds the PresharedKey sealed, and shows it to nobody. The Controller shows it once, and gives it in clear to the gateway alone, which hands it to WireGuardNT.
- A backup that is restored on another host, or into another cluster, brings the Devices back with a PresharedKey that does not open there. The gateway then terminates those Devices without it, so no client that has it completes a handshake. The Controller says so: its log names each of those Devices once, when it starts, and the Devices page, `ranz get devices` (`presharedKeyDoesNotOpen`) and `ranz get device-config` say that the PresharedKey does not open. Make each of those Devices again.
- A PresharedKey that the Controller could not open for a while, because its key storage provider did not answer, or because a member of a cluster did not hold the Cluster key yet, reaches the gateway by itself once it opens: the gateway does not have to start again, and the Device does not change.
- When a PresharedKey may have leaked, make a new Device, with new keys, and delete the old one.
- `-no-preshared-key`, or the box No PresharedKey in the form, leaves it out. Use it only for a client that cannot take one (every client in this guide can).
- A PresharedKey does not rotate by itself. Automatic rotation, with Rosenpass, is not part of this version.

## What is tested

A test keeps this guide in step with the product. It builds the example Network, has the Controller render the two configurations above and compares them with the ones in this file, checks that the examples for the routers carry the values of the configuration, that each client and each note has its section, and that every `ranz` command in this guide is a command of `ranz`. In CI, on a Windows runner, a stock WireGuard client (`wireguard-go`) takes the configuration that `ranz device create` made, completes the handshake with a gateway Node, and reaches an overlay host. The apps and the routers themselves are not run in CI: their steps are the manual setups that this guide documents, and a step that no longer matches an app is a defect to report.
