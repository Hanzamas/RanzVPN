# First test of the product on two PCs

This is the runbook for the first test of Ranz VPN on two real Windows PCs. You run it by hand. The steps are in the order you do them. The same steps run in CI, in the same order, from this file (see "How CI proves it" at the end), so a command that stops working breaks the build and not your afternoon.

## What this test shows today

Read this first. The Node service of a PC joins its Controller (step 20), but two Node services cannot form a Noise session with each other yet (see Gaps at the end). So the test has three kinds of steps:

- **Real.** The product does it: install, the Controller and its certificate, the web UI, the default Intent, PC B reaching the Controller, the link between the PCs, the Node resources and their addresses, the Node service of PC A joining the Controller with its own key, the replacement of the certificate of the Controller by one that `ranz cert` made, `ranz doctor`, the logs and the diagnostics bundles, uninstall. Most steps are real.
- **Stand-in.** `vpntest firsttest`, a test program that is built in CI, plays the Nodes that need a session with each other. It enrols two Nodes at the Controller of PC A over the real network, gives one of them a real Wintun adapter and answers a ping for the other. Steps 17, 19 and 24. From step 20 on, the Node service of PC A plays `pc-a` and the stand-in plays `pc-b` only.
- **Gap.** The thing the test is really for, two Node services that ping each other, does not work yet. The Gaps at the end say what is missing.

## The two PCs and the values you copy

| Name | What it is |
|---|---|
| PC A | Runs the Controller (the Intent, the web UI, the API) and a Node service, which joins the Controller as `pc-a` in step 20. |
| PC B | Runs a Node service, which has nothing to do in this test, and from step 17 on the stand-in. |

Use test PCs or virtual machines that you can reinstall. `ranz install` puts drivers on the PC (Wintun on both architectures, SeLow and the XDP runtime on x64), and `ranz uninstall` takes them out again.

A few commands need a value from an earlier step. They show it in angle brackets. Copy the value from the output where the step says so.

| Value | What it is | Where you get it |
|---|---|---|
| `<PC-A>` | The address of PC A that PC B can reach, for example `192.168.1.10` | `ipconfig` on PC A |
| `<PORT>` | The TCP port of the Controller: `443`, or `5555` when 443 was taken | step 7, `tlsPort` |
| `<CONTROLLER>` | `<PC-A>:<PORT>` | |
| `<FINGERPRINT>` | The TLS fingerprint of the Controller | step 7, `tlsFingerprint`. Step 21 gives the Controller another certificate, and `<FINGERPRINT>` becomes the new `fingerprint` of step 21 from there on. |
| `<CONTROLLER-KEY>` | The static key of the Controller | step 7, `publicKey` |
| `<VIEWER-TOKEN>` | An API token that can only read | step 12 |
| `<PC-A-OVERLAY>` | The overlay address of the Node `pc-a` | step 16 |
| `<NODE-KEY>` | The static key of the Node service of PC A | step 20, `publicKey` |

All commands are PowerShell commands, run in a window that was opened as Administrator. Each PC has its own window. A command that starts with `ranz` runs `ranz.exe` of step 1.

## The steps

| Step | Id | PC | Kind |
|---|---|---|---|
| 1 | download | both | real |
| 2 | prerequisites | both | real |
| 3 | trust | both | real |
| 4 | firewall | A | real |
| 5 | install-a | A | real |
| 6 | controller-up | A | real |
| 7 | certificate | A | real |
| 8 | web-ui | A | real |
| 9 | default-intent | A | real |
| 10 | install-b | B | real |
| 11 | node-up | B | real |
| 12 | viewer-token | A | real |
| 13 | reach-controller | B | real |
| 14 | link-check | A and B | real |
| 15 | declare-nodes | A | real, with test keys |
| 16 | addresses | A | real |
| 17 | stand-in | B | stand-in |
| 18 | enrol | A | real, for the stand-in |
| 19 | ping | B | stand-in |
| 20 | node-service | A | real |
| 21 | replace-certificate | A and B | real |
| 22 | doctor | both | real |
| 23 | logs | A | real |
| 24 | stop-stand-in | B | stand-in |
| 25 | stand-in-gone | B | real |
| 26 | uninstall | both | real |
| 27 | clean-up | both | real |
| 28 | gaps | | gap |

The step numbers in the headings below are the ones of this table. The text of each heading has the id after it. CI uses the id, not the number.

## Part 0. Get ready

### 1. Get the files (download)

<!-- step: download pc=both -->

Both PCs need the same build. Open the Actions tab of `Hanzamas/RanzVPN` and take the newest successful run that is named `Full CI: push on integration`. The signed `ranz.exe` and the certificate stay for 14 days after a run. In the list of artifacts of the run, download:

| Artifact | What it holds | Where it goes |
|---|---|---|
| `ranz-x64` (`ranz-arm64` on an Arm PC) | `ranz.exe`, signed once. The Node, the drivers and the Controller's rqlite member are inside it. | `C:\ranz-test\ranz`, on both PCs |
| `ci-signing-certificate` | `ranz-ci-signing.cer`, the self-signed certificate that signed `ranz.exe` in CI | `C:\ranz-test\cert`, on both PCs |
| `Binaries-x64` (`Binaries-arm64`) | `vpntest.exe` and the other test programs | `C:\ranz-test\bin`, on PC B only |

Each artifact is a zip file. Unzip each one into its folder. With the GitHub CLI you can do the same:

```powershell
gh run list -R Hanzamas/RanzVPN -w windows.yml -b integration -L 5
gh run download <run id> -R Hanzamas/RanzVPN -n ranz-x64 -D C:\ranz-test\ranz
gh run download <run id> -R Hanzamas/RanzVPN -n ci-signing-certificate -D C:\ranz-test\cert
gh run download <run id> -R Hanzamas/RanzVPN -n Binaries-x64 -D C:\ranz-test\bin
```

Open PowerShell as Administrator and put the folder of `ranz.exe` on the path of that window:

```powershell run
$env:Path = "C:\ranz-test\ranz;$env:Path"
ranz version
```

You see one line, `ranz 0.1.` and the build number.

### 2. Check the PC (prerequisites)

<!-- step: prerequisites pc=both -->

You need Windows 10 or Windows Server 2016 or newer, on x64 or arm64. The artifact must be the one of your architecture. Both PCs must be on a network where PC B can open a TCP connection to PC A.

```powershell run
([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture
Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue
```

The first command must print `True`. The second names your Windows. The third prints nothing on PC A when TCP 443 is free. If another program holds 443, the Controller uses 5555 (the fallback of ADR-0020) and you use `5555` as `<PORT>` below.

### 3. Trust the CI certificate (trust)

<!-- step: trust pc=both -->

`ranz install` writes `ranz-node.exe`, the drivers and a copy of `ranz.exe`. It refuses every file whose signature does not chain to a trusted root. The CI build is signed with a self-signed certificate, so each PC must trust that certificate as a root first. (A release build will carry a purchased certificate and needs no such step.) Step 27 removes it again.

```powershell run
Import-Certificate -FilePath C:\ranz-test\cert\ranz-ci-signing.cer -CertStoreLocation Cert:\LocalMachine\Root
(Get-AuthenticodeSignature C:\ranz-test\ranz\ranz.exe).Status
```

The last line must be `Valid`. The signer is `CN=Ranz VPN CI signing (self-signed), O=Hanzcodes`.

### 4. The firewall (firewall)

<!-- step: firewall pc=a -->

Windows Firewall blocks incoming connections, and you open nothing by hand. `ranz install` opens the ports of what it installs, as rules of the group `Ranz VPN`: TCP 443 and UDP 443 for the Node (`ranz-node.exe`), and with `--controller` TCP 443 and 5555 for the Controller (`ranz.exe`): the web UI, the API and the control streams of the Nodes, on 5555 when 443 was taken. `ranz uninstall` removes every rule of the group (step 26). The link check of step 14 lets its own port in while it runs. `docs/ports.md` lists every port of the product. Before the install the group is empty:

```powershell run
Get-NetFirewallRule -Group "Ranz VPN" -ErrorAction SilentlyContinue | Format-Table DisplayName, Direction, Action, Enabled
```

The command prints nothing.

## Part 1. PC A: the Controller

### 5. Install the Node and the Controller (install-a)

<!-- step: install-a pc=a -->

```powershell run
ranz install --controller
Get-NetFirewallRule -Group "Ranz VPN" | Format-Table DisplayName, Direction, Action, Enabled
```

This does the following, and checks the hash and the signature of every file before it writes the file. A file that fails is never written.

- It makes the folder `C:\Program Files\Ranz VPN` for SYSTEM and the Administrators. It writes `ranz-node.exe`, `wintun.dll`, `NOTICE.txt` and a copy of `ranz.exe` into it.
- On x64 it installs the SeLow driver and the XDP runtime. On arm64 there are none: Wintun is the only driver.
- It registers and starts the Node service `ranzvpnserver`.
- Because of `--controller` it also registers and starts the Controller service `ranz-controller`. The Controller brings its own rqlite member inside `ranz.exe`.
- It opens the ports of the Node and the Controller in Windows Firewall: the group `Ranz VPN` holds three inbound rules that allow, `Ranz VPN Node (TCP 443)`, `Ranz VPN Node (UDP 443)` and `Ranz VPN Controller (TCP 443, 5555)`, and nothing else.

- It narrows who may reach the API and the web UI of the Controller, because TCP 443 and 5555 are open on every profile. The admin source allowlist is loopback and the subnets of the private interfaces of the PC (RFC 1918 and unique local addresses), unless you name the sources yourself with `--admin-from`, for example `ranz install --controller --admin-from 203.0.113.0/24,198.51.100.7`, or open the API to every address with `--admin-from any`. From an address outside the list, every call gets `403` before its token is looked at, and the refusals are events (`admin-access-refused`, one a minute for one address). The control stream of the Nodes is not behind the list: a Node enrols from any address, and a Network limits where its Nodes enrol from. The Controller applies the list at its first start only; change it afterwards with `ranz admin-sources set PREFIX...` or lift it with `ranz admin-sources clear`. A Controller whose store is there already, because the service is registered or because `ranz uninstall` left the data directory, keeps the list of that store whatever `--admin-from` says, and `ranz install` says so in place of the line below.

The default list is wrong in two cases, and each needs a list of your own:

- **A global IPv6 subnet is not in the default.** The default holds private subnets only, so it holds no global IPv6 subnet of the PC. A dual-stack client on the same LAN that reaches the PC by an IPv6 name (an AAAA record), from an address in the same global `/64`, is answered `403`. To allow it, name the subnet with `--admin-from`, for example `ranz install --controller --admin-from 192.168.1.0/24,2001:db8:1:2::/64`. The `/64` is the first 64 bits of the global address of the PC: `Get-NetIPAddress -AddressFamily IPv6 | Format-Table InterfaceAlias, IPAddress, PrefixLength` lists the addresses, and a global one starts with `2` or `3`. `--admin-from` replaces the default list, so name the private subnets that you still want, as the example does. On a PC that is installed already, run `ranz admin-sources set 192.168.1.0/24 2001:db8:1:2::/64` on PC A.
- **A proxy, a load balancer or a masquerading router inside a private subnet makes the default too wide.** The Controller sees the address of the last device that connected to it, not the address of the caller behind that device. When a reverse proxy, a load balancer or a router that rewrites the source address of what it passes on (source NAT, or SNAT, which masquerading is) sits inside a private subnet of the PC and passes callers from the internet on to TCP 443 or 5555, every one of those callers reaches the Controller from a private address, and the default list lets them in. Name the sources that may reach the Controller with `--admin-from`, and leave out the subnet of that device, or do not pass the ports of the Controller on from the internet. A router that only forwards the port (a port forward, also called destination NAT or DNAT) is not a problem here: it keeps the address of the caller, which is public, so the default list answers that caller `403`. A proxy on the PC itself is worse: a loopback address always passes, so it lets in every caller that it passes on.

The last lines are a line `install: the Controller starts with the admin source allowlist ...`, `install: the ranz-controller service is running`, a line `install: Windows Firewall lets in ...` for each rule, and `ranz install: done`. It is safe to run the command again: a rule that is there as it should be stays, so a second install and an upgrade leave the same rules.

### 6. The Controller starts (controller-up)

<!-- step: controller-up pc=a -->

```powershell run
Get-Service ranzvpnserver, ranz-controller
Get-ChildItem C:\ProgramData\Ranz\controller
Get-Content C:\ProgramData\Ranz\controller\controller.log -Tail 12
(Get-Acl C:\ProgramData\Ranz\controller).Owner
(Get-Acl C:\ProgramData\Ranz\controller).AreAccessRulesProtected
```

Both services are `Running`. The folder `C:\ProgramData\Ranz\controller` is the data directory of the Controller. At its first start the Controller made:

- `admin.token`: the secret of the admin API token. Only SYSTEM, the Administrators and the service account can read it.
- `controller.log`: its log. It says `first start: the intent of a first install` and `TLS port`, and at its first start which sources may reach the API and how to change that (`first start: the admin source allowlist is set`) and that the starter rule allows all traffic inside VRF `default` and how to narrow it (`first start: the starter rule default-allow-all`). Every later start says which list it keeps (`the admin source allowlist is set`), and warns when there is none.
- `tls.fingerprint`: the TLS fingerprint of the certificate that the Controller serves, 64 hex digits and no secret. The Controller writes it at every start and every time the certificate changes (step 21). `ranz` on this PC checks the certificate of the Controller by it (step 7).
- `payload\rqlited.exe` and `rqlite\`: its store.

The last two commands print `BUILTIN\Administrators` and `True`: the Administrators own the data directory, and its access list is protected, so that it takes no rule from `C:\ProgramData`, which lets every user make a folder. Only SYSTEM, the Administrators and the service account have a right in it. `ranz install` made it that way. A folder of that name that another account made before the install is not kept: the install makes an empty one again, and refuses one that holds files, with a message that says what to do, since the files could be a store with a token that its maker knows or an `rqlited.exe` of its own, which the service would run. The service itself does not start in a data directory that an account other than SYSTEM, the Administrators and the service owns.

### 7. The certificate (certificate)

<!-- step: certificate pc=a -->

The Controller made two keys at its first start and keeps them in Windows key storage: a Noise static key and a TLS key. Its certificate is self-signed, made from the TLS key, and made again at every start. The fingerprint is the SHA-256 of the public key of the certificate, so it stays the same while the key does.

If the log of step 6 says that the TLS port is `[::]:5555`, the Controller fell back from 443. Then set `$env:RANZ_SERVER = "https://127.0.0.1:5555"` in this window before the next command.

```powershell run
$env:RANZ_TOKEN_FILE = "C:\ProgramData\Ranz\controller\admin.token"
ranz status
```

You see this, with your own values:

```
{
  "publicKey": "...44 characters...=",
  "controlAddress": "[::]:443",
  "tlsFingerprint": "...64 hex digits...",
  "capabilities": { "tlsPort": 443, "tlsPortFallback": false },
  "adminAccess": { "sources": ["10.1.2.0/24", "127.0.0.0/8", "::1/128"], "open": false, "note": "only these sources, and loopback, reach the API ..." },
  "starterRule": { "name": "default-allow-all", "note": "the starter rule default-allow-all allows all traffic inside VRF default: narrow it ..." },
  ...
}
```

`adminAccess` is the admin source allowlist of step 5: the sources that may reach the API and the web UI, and `open` is `true` when there is none. The list is an admin's to read, so `sources` is in the answer for the admin token only: a viewer reads `open` and the note. `starterRule` is there while the Intent holds the starter rule of step 9 as the first start made it.

Write down `publicKey` as `<CONTROLLER-KEY>`, `tlsFingerprint` as `<FINGERPRINT>` and `tlsPort` as `<PORT>`. If `tlsPort` is `5555`, the Controller fell back and `tlsPortFallback` is `true`.

`ranz` on PC A checks the certificate by the fingerprint that the Controller writes to `tls.fingerprint` in its data directory (`C:\ProgramData\Ranz\controller`), because another program of the host can listen on a port that the Controller is not on. Where it cannot read that file it sends no token and asks for `-tls-fingerprint`. On any other PC, `ranz` accepts the certificate only with the fingerprint (step 13). A browser cannot check the fingerprint, so it warns. Step 21 replaces the certificate by one that a browser trusts.

### 8. The web UI (web-ui)

<!-- step: web-ui pc=a -->

Open `https://localhost/` in a browser on PC A. Use `https://localhost:5555/` after a fallback. The browser warns that the certificate is not trusted: the Controller's certificate is self-signed and its name is `ranz-controller`. Go on anyway.

The page sends you to `/sign-in`. Paste the content of `admin.token` into the field. Get it with `Get-Content C:\ProgramData\Ranz\controller\admin.token`. The token stays in that browser tab until you sign out or close it.

The pages are Overview, VRFs, Networks, Nodes, Intent, Revisions, Events, Licence, Diagnostics and API tokens. Open Overview: the Controller card shows the control address, the TLS fingerprint and the public key of step 7, and the Licence card shows the Personal tier. This is the same check by command:

```powershell run
curl.exe -k -s -o NUL -w "%{http_code}\n" https://localhost/
ranz whoami
```

The first command prints `200`. The second prints the token: the name `admin` and the role `admin`. The web UI only calls the same API as `ranz` does, with the same token.

### 9. VRF default, Network default and the starter rule (default-intent)

<!-- step: default-intent pc=a -->

The first start of the Controller made revision 1 of the Intent (ADR-0034). You do not create anything.

```powershell run
ranz get resources
ranz get revisions
ranz get ipam
```

You see three resources:

- `VRF` `default`: the routing domain of the overlay. The Controller gave it an id and a random IPv6 ULA /48. DNS is on and the MTU is 1280.
- `Network` `default`: in VRF `default`, mode `L3`, with the automatic IPv4 pool `100.64.0.0/10`.
- `Policy` `default-allow-all`: the starter rule. It allows all traffic inside VRF `default`.

There is one revision, `first-start`. `ranz get ipam` shows the pool of Network `default`: its size, and `allocated` is 0. The pages VRFs, Networks, Intent and Revisions of the web UI show the same.

A Node that names no VRF joins VRF `default` and gets an address from that pool.

The starter rule lets every Node of VRF `default` talk to every other. The first start says so in `controller.log`, and `ranz status` says so in `starterRule` for as long as the Intent holds the rule as the first start made it: a rule of that name that you narrowed in place, with a protocol or ports, no longer allows all, and `starterRule` is gone. To narrow it, first apply the Policies that you want, each with the action `allow` or `deny`, while the starter rule still lets everything through, and then delete the starter rule. VRF `default` is then at default deny for every flow that your Policies do not allow, and the flows that they allow never stop in between. For example, to let the Nodes of VRF `default` ping each other and reach TCP 443 of the Nodes that carry the tag `web` (`tags` of their Node resource), and nothing else:

```powershell
Set-Content -Path C:\ranz-test\policies.json -Value '{"resources":[{"kind":"Policy","name":"allow-ping","spec":{"vrf":"default","action":"allow","protocol":"icmp"}},{"kind":"Policy","name":"allow-web","spec":{"vrf":"default","action":"allow","to":{"tags":["web"]},"protocol":"tcp","ports":["443"]}}]}'
ranz apply -f C:\ranz-test\policies.json
ranz delete Policy default-allow-all
```

This test keeps the starter rule, so these commands are no step of it. `ranz apply -f` takes an intent document, as in step 15; an end of a Policy (`from`, `to`) may also name addresses, and a `priority` orders the rules. `ranz diff` shows what a change did, and `ranz rollback REVISION` takes it back.

## Part 2. PC B: a Node

### 10. Install the Node (install-b)

<!-- step: install-b pc=b -->

On PC B run steps 1, 2 and 3 first. Then:

```powershell run
ranz install
```

This is the same install without `--controller`: no Controller service is made, and the group `Ranz VPN` of Windows Firewall holds the two rules of the Node only, TCP 443 and UDP 443. Nothing of PC B listens on the network today.

### 11. The Node runs (node-up)

<!-- step: node-up pc=b -->

```powershell run
Get-Service ranzvpnserver
Get-ChildItem "$env:ProgramData\Hanzcodes\Ranz VPN"
Get-ChildItem "$env:ProgramData\Hanzcodes\Ranz VPN\node_log" -Recurse -File | Select-String "Node started|Capabilities:|Controller: none"
ranz node state -o table
```

The service is `Running`. The data directory of the Node, `C:\ProgramData\Hanzcodes\Ranz VPN`, holds its Configuration store `ranz_node.db`, a text copy of its settings `node_config.txt` (the Node writes it at its start, and it holds no password hash), and the folder `node_log`. The log says `Node started` and, a moment later, the Capabilities of the PC, for example `Capabilities: architecture x64, SeLow yes, XDP yes`. On arm64 it says `SeLow no, XDP no`. It also says once at each start `Controller: none`: the Node has no Controller settings yet (step 20 gives them to the Node of PC A), so it opens no control stream and dials no Controller.

`ranz node state` shows what the Node service does now. It asks the running service on its admin pipe, which only SYSTEM and the Administrators may open, and prints its Roles, its control stream, its adapters with their VRFs and addresses, the Noise sessions of its peers with their transport and age, and its listeners. Here the control stream is `none: the node has no Controller settings`, and there is no adapter and no session yet. Without `-o table` it prints JSON. For a stopped service it says `is stopped`, with the exit code 3.

### 12. A token for PC B (viewer-token)

<!-- step: viewer-token pc=a -->

PC B will read the Controller of PC A. It needs a token. Make one that can only read. This is on PC A:

```powershell run
ranz token create -role viewer pc-b
```

The answer holds the secret of the token once. Write it down as `<VIEWER-TOKEN>`. It starts with `ranz_`. The Controller keeps only its hash.

### 13. PC B reaches the Controller (reach-controller)

<!-- step: reach-controller pc=b -->

This checks the network, the firewall and the certificate between the two PCs. On PC B:

```powershell run
Test-NetConnection <PC-A> -Port <PORT>
Set-Content -Path C:\ranz-test\viewer.token -Value "<VIEWER-TOKEN>"
$env:RANZ_SERVER = "https://<CONTROLLER>"
$env:RANZ_TLS_FINGERPRINT = "<FINGERPRINT>"
$env:RANZ_TOKEN_FILE = "C:\ranz-test\viewer.token"
ranz whoami
ranz get resources
```

`TcpTestSucceeded` must be `True`. If not, the firewall rules of step 5 or the network is the problem. `ranz whoami` prints the name `pc-b` and the role `viewer`. `ranz get resources` prints the three resources of step 9. The `RANZ_TLS_FINGERPRINT` makes `ranz` accept the certificate of the Controller only when its fingerprint is the one you copied. A wrong value fails. The viewer token cannot change anything: `ranz apply` from PC B is answered with 403.

PC B is let in by the admin source allowlist of step 5 when it is on a private subnet of PC A. When it is not, `ranz` on PC B is answered with 403 `is not allowed to reach the API and the web UI` before the token is looked at: add its address on PC A with `ranz admin-sources set` (it replaces the list, so name the entries of `ranz admin-sources list` too), or install with `--admin-from`. A global IPv6 address is not on a private subnet either: name its `/64`, as step 5 shows.

### 14. The link between the two PCs (link-check)

<!-- step: link-check pc=both -->

Before the overlay, check that the PCs reach each other and how fast. `ranz test throughput` is the successor of the traffic test of vpncmd. On PC A start the server, and leave it running:

```powershell background
ranz test throughput -listen <PC-A>:9821
```

On PC B run the client:

```powershell run
ranz test throughput -span 3s <PC-A>:9821
```

The server lets its port in while it serves: it prints `Windows Firewall lets in TCP 9821 ... while the test runs`, with a rule of the group `Ranz VPN`, and removes the rule when it stops (a server that was killed leaves it to `ranz uninstall`). A server on a loopback address makes no rule. The client prints one line for the connection, then a table with a row Download, Upload and Total and the rate of each. Stop the server on PC A with Ctrl+C. Once the overlay carries traffic, the same test between the two overlay addresses measures the overlay.

## Part 3. The Nodes join and get addresses

### 15. Declare the two Nodes (declare-nodes)

<!-- step: declare-nodes pc=a -->

A Node is part of the network only when the Intent holds a Node resource with the static key of that Node. You apply two. They name no VRF, so both join VRF `default`.

The Node resource of `pc-a` also says where the other PC reaches it. `endpoints` is a list in which each entry names a transport (`quic`, `tls` or `mimic`) and an address, a host and a port, under which the other Nodes reach the Node. `pc-a` has one endpoint: TLS at `<PC-A>:<PORT>`, the address of PC A that PC B reaches in step 13. The Controller puts the endpoints of a Node into the Peer object of every Node that shares a VRF with it, so the desired state of `pc-b` names them as the place of its peer `pc-a`. `pc-b` has no endpoints, so it is the Node that dials: no other Node can dial it, and a peer without endpoints is not dialled. `ranz apply` refuses a malformed endpoint with a message that says which: a transport that is not `quic`, `tls` or `mimic`, an address without a port, or a name that is no DNS name. An endpoint over `mimic` is dialled through the mimicry sidecar, whose server is a Node with a `mimic` section in its Listener resource (Gap 3); this Intent has none.

The keys below are the two public test keys of the stand-in, which plays both Nodes until step 20 puts the key of the Node service of PC A into `pc-a`. Their private halves are in the source of `vpntest`, so anyone who reaches your Controller could act as these two Nodes. Use them on a test Controller only.

```powershell run
Set-Content -Path C:\ranz-test\nodes.json -Value '{"resources":[{"kind":"Node","name":"pc-a","spec":{"publicKey":"B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=","endpoints":[{"transport":"tls","address":"<PC-A>:<PORT>"}]}},{"kind":"Node","name":"pc-b","spec":{"publicKey":"WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns="}}]}'
ranz apply -f C:\ranz-test\nodes.json
```

`ranz apply` prints the revision it made, 2, and the Generation of the state of each Node. Every apply is a revision: `ranz diff` shows what it changed and `ranz rollback 1` undoes it. Nothing of a Node listens at that endpoint yet: this Intent names no Listener, so the endpoint is what the Controller tells the Nodes, and not yet an address that answers one (Gap 3).

### 16. How each Node gets its address (addresses)

<!-- step: addresses pc=a -->

Only the Controller gives out addresses. There is no DHCP in the overlay. The address of a Node is the lowest free host address of the pool, and the Nodes come in the order of their names. It stays the address of that Node while the Node is in the Network. The Controller does this when you apply, before any Node connects:

```powershell run
ranz get resources
ranz get ipam
```

In the Node resources, `spec.addresses.default` is the address in Network `default`. `pc-a` has `100.64.0.1` and `pc-b` has `100.64.0.2`. Write down `100.64.0.1` as `<PC-A-OVERLAY>`. `spec.endpoints` of `pc-a` holds the endpoint of step 15, as the Controller keeps it, and `pc-b` has none. `ranz get ipam` shows `allocated` 2 for the pool. The Nodes page of the web UI lists both Nodes. They are not connected yet.

A Node learns its address in its desired state, which the Controller sends it on its control stream. The address is set on the Wintun adapter of the Node as a host address. The adapter also gets a route to the pool.

### 17. Start the stand-in Nodes (stand-in)

<!-- step: stand-in pc=b -->

This is the stand-in for two Node services that form a session with each other (Gap 3). `vpntest firsttest` runs two Nodes in one process on PC B. Each opens its control stream to the Controller of PC A, with the static key of its Node resource, as a Node service does:

- `pc-b` is a real Node with a real Wintun adapter named `Ranz default`. The adapter gets the address of `pc-b`, as the client role of the Node brings it up. The packets of PC B on this adapter go into the overlay.
- `pc-a` is a Node with a fake host that answers an ICMP echo request to its address. The two Nodes run their Noise session in memory, and find each other by their node names, so they do not use the endpoint of `pc-a` (Gap 3).

Why `pc-a` has no adapter: Windows delivers a packet for an address of the PC itself on the PC. Two adapters of one PC could not ping each other through the overlay. Only the fake host can answer the ping that you send from PC B.

`vpntest` loads `wintun.dll` from its own folder. Copy the one that `ranz install` wrote, then start the stand-in. It runs until it sees the stop file or Ctrl+C. Leave it running:

```powershell run
Copy-Item "$env:ProgramFiles\Ranz VPN\wintun.dll" C:\ranz-test\bin\
```

```powershell background
C:\ranz-test\bin\vpntest.exe firsttest <CONTROLLER> <CONTROLLER-KEY> C:\ranz-test\ready C:\ranz-test\stop
```

Wait until it prints `FIRSTTEST READY`, and the file `C:\ranz-test\ready` is there. The lines before it say that both Nodes applied their state, their session is up and the adapter holds its address, for example `FIRSTTEST NODE pc-b ADDRESS 100.64.0.2 ADAPTER "Ranz default"`.

### 18. The Nodes enrol (enrol)

<!-- step: enrol pc=a -->

The first stream of a static key is the enrolment of that Node. The Controller checks the key against the Node resources, takes the Capabilities of the Hello, sends the desired state, and waits for the acknowledgement of the Generation. On PC A:

```powershell run
ranz get nodes
ranz get audit -kind enrolment -o table
Get-Content C:\ProgramData\Ranz\controller\controller.log -Tail 20
```

- `ranz get nodes` shows `pc-a` and `pc-b` with `connected` true. `generation` and `ackedGeneration` are equal: the Node applied the last state. The `capabilities` are the ones the Node put in its Hello: the architecture of PC B, and whether SeLow and the XDP runtime are there.
- The audit log has one record of the kind `enrolment` for each Node: `the first control stream of the static key of this node`, with the address that the stream came from. `ranz get audit` reads it through the API with the token of the window, with the filters of the API (`-kind`, `-actor`, `-since`, `-until`, `-after`, `-limit`); without `-o table` it prints the JSON of the API. A token of any API role reads it, and a call without a valid token is refused with 401. (The Events of the web UI are another list: they hold the events of the Controller, such as an automatic rollback.)
- `controller.log` says `node connected` for each Node, with the address it came from and the Generation it had applied: `0` at the first start.

The Nodes page and the Overview of the web UI show the same: two Nodes in the Intent, two connected.

### 19. Ping over the overlay (ping)

<!-- step: ping pc=b -->

On PC B, look at the adapter and ping `pc-a` through it:

```powershell run
Get-NetIPAddress -InterfaceAlias "Ranz default" -AddressFamily IPv4
Get-NetRoute -InterfaceAlias "Ranz default" -AddressFamily IPv4
ping -n 4 <PC-A-OVERLAY>
```

- The adapter `Ranz default` has the address `100.64.0.2` with the prefix length 32.
- The routes of the adapter hold `100.64.0.0/10`, the pool, on link.
- The ping gets four replies from `100.64.0.1`. The packet leaves PC B through the adapter, goes through the overlay to `pc-a`, is answered by its fake host, and comes back. The Controller is not on the path of the packets, and by design a Node keeps forwarding with the last state it applied when the Controller is gone (ADR-0026, decision 5).

If another VPN on PC B owns `100.64.0.0/10` (Tailscale does), the routes clash: see Troubleshooting.

### 20. The Node service of PC A joins (node-service)

<!-- step: node-service pc=a -->

This is the step the test is for. Until now the stand-in played both Nodes. Here the Node service of PC A, which `ranz install --controller` started in step 5, takes the place of `pc-a`: it gets its Controller settings, and its own static key goes into the Node resource `pc-a` in place of the test key of the stand-in. The stand-in keeps playing `pc-b`. Two Node services cannot form a Noise session with each other yet (Gap 3), so the ping between two PCs stays the one of the stand-in in step 19.

Read the static key of the Node. `ranz node key` asks the Node service on its admin pipe, which only SYSTEM and the Administrators may open. The service makes the key when no role has needed it yet, and keeps it in Windows key storage: the private half is in no output and no log.

```powershell run
ranz node key
```

Write down `publicKey` as `<NODE-KEY>`. It is in the form of the `publicKey` of a Node resource. Then give the Node its Controller: the address, the static key and the TLS fingerprint of step 7.

```powershell run
ranz node controller set <CONTROLLER> <CONTROLLER-KEY> <FINGERPRINT>
ranz node controller show
```

`ranz node controller set` checks the three values, and refuses an address without a port, a key of the wrong length or a fingerprint that is not 64 hex digits with a message that says which. The Node service keeps the settings in its Configuration store, of which it is the one writer, and takes them at start, so the verb restarts it and says so. `ranz node controller clear` takes them out again. The service then opens its control stream: TLS 1.3 to `<CONTROLLER>`, whose certificate must have `<FINGERPRINT>`, and the Noise handshake with `<CONTROLLER-KEY>`. A wrong fingerprint or a wrong key fails closed: the Node takes no state, and its node log says which check failed.

No Node resource holds the key of the Node yet, so the Controller refuses it. The audit log records each refusal as a failed authentication of the actor `key:<NODE-KEY>`, and the Node dials again after a delay that doubles from 1 second up to 1 minute:

```powershell run
ranz get audit -kind auth-failed -o table
```

Put the key into the Node resource `pc-a`, in place of the test key of the stand-in. An apply replaces the whole resource, so the endpoint of step 15 is in it again:

```powershell run
Set-Content -Path C:\ranz-test\pc-a.json -Value '{"resources":[{"kind":"Node","name":"pc-a","spec":{"publicKey":"<NODE-KEY>","endpoints":[{"transport":"tls","address":"<PC-A>:<PORT>"}]}}]}'
ranz apply -f C:\ranz-test\pc-a.json
```

The Controller refuses the stream of the stand-in for `pc-a` at once: its key is no longer the one of the Node resource. The Node service joins on its next attempt, within a minute, without a restart. Wait a minute, then look at the Nodes:

```powershell run
ranz get nodes
ranz node state -o table
```

`pc-a` is connected, at the Generation it acknowledged, with the Capabilities of PC A. It holds the address `100.64.0.1` of the Node resource and its node log says `Overlay: generation`, but it has no adapter: the Roles of a default install do not bring one up, and no other Node can reach it: nothing of the Node service listens at its endpoint (Gap 3). `ranz node state` shows the same from the side of the Node: `Node pc-a`, its Roles, the control stream `connected to <CONTROLLER>` for some seconds at the Generation that `ranz get nodes` shows acknowledged, no adapter, the peer `pc-b` with its session down, and its listeners. While the Node is not connected, its control stream says why, as the node log does, and when it tries again.

Restart the Controller. The Node dials again by itself, after a delay that starts at 1 second again since its stream was open:

```powershell run
Restart-Service ranz-controller
```

A few seconds after the Controller is back, `ranz get nodes` shows `pc-a` connected again, and the node log says `the control stream ended after it was open` with the attempts after it. A network that drops without closing the connection ends the stream the same way: the Node probes a quiet stream with TCP keepalive after 10 seconds, and 3 probes 2 seconds apart that get no answer end it, so it dials again about 16 seconds after the last segment.

## Part 4. The certificate of the Controller

### 21. Replace the certificate of the Controller (replace-certificate)

<!-- step: replace-certificate pc=both -->

Until now the Controller served the self-signed certificate of step 7. `ranz controller-cert` replaces it (SDN-92). The certificate comes from one of three sources: a PEM file with its key, which this step uses; a certificate of the Windows key storage that `-ksp` names by its thumbprint, whose key stays in the key storage; or an ACME service (`-acme`), which the Controller renews by itself. The web UI, the API and the control streams of the Nodes all use the one certificate. `ranz controller-cert show` prints it: its source, subject, names, thumbprint, TLS fingerprint and end. It never prints a key. `ranz controller-cert clear` takes the setting away, and the Controller serves its own certificate again, with the fingerprint of step 7.

The Controller checks a certificate before it serves it. It refuses one whose key is not the key of the file, one that has ended or is not valid yet, one that is a CA certificate or is not for a server, one with a key that the Nodes do not take, and one that does not name every host that the Nodes use (`-host`). The reason is in the answer, and the certificate in use stays. A certificate that passes is served to the connections that come after it, and the connections that are up stay up.

A certificate with another key has another TLS fingerprint, and a Node pins the fingerprint (step 20). So the Controller first sends each Node the fingerprint of the new certificate with the one in use, over its control stream, waits until the Nodes that are connected have acknowledged it, and only then serves the new certificate. The Node takes the fingerprints in place of the one it was given, and keeps them in its settings, so it reaches the Controller after the change and after a restart. A Node that is not connected could not be told: the command names it and changes nothing, unless `-force` goes on, and that Node needs `ranz node controller set` with the new fingerprint. A certificate for the key that the Controller has already, as the ACME certificate of the Controller always is, has the same fingerprint, and nothing has to be sent.

The test makes the certificate with `ranz cert`: a CA of its own, and a certificate for `<PC-A>` that the CA signs. The Controller service runs as `NT SERVICE\ranz-controller`, so the key file gets an access rule for that account. On PC A:

```powershell run
New-Item -ItemType Directory -Force C:\ranz-test\controller-cert | Out-Null
ranz cert -cn "Ranz first test CA" -ca -savecert C:\ranz-test\controller-cert\ca.pem -savekey C:\ranz-test\controller-cert\ca.key
ranz cert -cn <PC-A> -hosts <PC-A> -signcert C:\ranz-test\controller-cert\ca.pem -signkey C:\ranz-test\controller-cert\ca.key -savecert C:\ranz-test\controller-cert\controller.pem -savekey C:\ranz-test\controller-cert\controller.key
icacls C:\ranz-test\controller-cert\controller.key /grant "NT SERVICE\ranz-controller:R"
```

Nothing is set yet, so the Controller still serves its own certificate:

```powershell run
ranz controller-cert show
```

`source` is `self-signed`, the subject is `CN=ranz-controller`, `fingerprint` is the `<FINGERPRINT>` of step 7, and there is no `setting`. Now set the certificate. `-host` names the host that the Nodes and PC B use to reach the Controller, which the certificate must name:

```powershell run
ranz controller-cert set -host <PC-A> -cert C:\ranz-test\controller-cert\controller.pem -key C:\ranz-test\controller-cert\controller.key
```

The answer has the certificate that is served now, with `source` `file`, and `pinned`, the Nodes that took the new fingerprint before the certificate was served: `pc-a`, the Node service, and `pc-b`, the stand-in. The `fingerprint` is another one than the one of step 7. Write it down as `<FINGERPRINT>` in place of the old one. The Controller keeps the setting in its store, writes the change in its log (`certificate of the controller changed`), in its events (`controller-certificate-changed`) and in its audit log, as an operation of the token that made it. From here `show` and `ranz status` print the new fingerprint:

```powershell run
ranz controller-cert show
```

A certificate that the Controller does not take changes nothing. This one is refused with 400: the certificate does not name the host `other.example.com`, and the answer says which host it names, `<PC-A>`. `show` still prints the certificate above.

```powershell
ranz controller-cert set -host other.example.com -cert C:\ranz-test\controller-cert\controller.pem -key C:\ranz-test\controller-cert\controller.key
```

The key of another certificate, a certificate that has ended and a certificate file that is gone are refused the same way, each with its reason.

The Node service pinned the fingerprint of step 7 in step 20. The Controller sent it the new fingerprint with the old one before it served the new certificate, and then the new one alone. `ranz node controller show` prints what the Node accepts: `tlsFingerprint` is the new fingerprint, and `tlsFingerprints` lists the fingerprints that the Controller sent, the new one only now. While the certificate changed the list had two, the old fingerprint first:

```powershell run
ranz node controller show
```

Now give each end a connection of its own. The Controller reads its setting from its store when it starts, and serves the new certificate again. The Nodes dial it again: the Node service with the new fingerprint that it kept, the stand-in with no fingerprint to check:

```powershell run
Restart-Service ranz-controller
```

Restart the Node service too. It reads the fingerprints that the Controller sent from its Configuration store, and dials with them:

```powershell run
Restart-Service ranzvpnserver
```

A few seconds later both Nodes are connected again, at the Generation that they acknowledged:

```powershell run
ranz get nodes
```

On PC B, `ranz` checks the certificate of the Controller by its fingerprint, as in step 13, or, with no fingerprint, by its chain: the certificate must name the host of `RANZ_SERVER`, and its chain must end in a root that Windows trusts, as for a browser. Copy `ca.pem` of PC A, the certificate of the CA and never `ca.key`, to the same folder on PC B, and trust it:

```powershell run
Import-Certificate -FilePath C:\ranz-test\controller-cert\ca.pem -CertStoreLocation Cert:\LocalMachine\Root | Select-Object Subject
```

Take the fingerprint away. `ranz whoami` works anyway, because the certificate names `<PC-A>` and its chain ends in the CA that PC B trusts:

```powershell run
Remove-Item Env:RANZ_TLS_FINGERPRINT -ErrorAction SilentlyContinue
ranz whoami
```

With the new fingerprint it works as in step 13. The old fingerprint is refused now:

```powershell run
$env:RANZ_TLS_FINGERPRINT = "<FINGERPRINT>"
ranz whoami
```

A browser on PC B takes the web UI as well, with no warning. The certificate names `<PC-A>`, so the address is `https://<PC-A>/`:

```powershell run
(Invoke-WebRequest -UseBasicParsing https://<CONTROLLER>/).StatusCode
```

A certificate that chains to no root that PC B trusts is refused without the fingerprint. Take the CA out of the store of PC B:

```powershell run
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "CN=Ranz first test CA*" } | Remove-Item
```

Without the fingerprint `ranz whoami` fails now, with `certificate signed by unknown authority`:

```powershell
Remove-Item Env:RANZ_TLS_FINGERPRINT -ErrorAction SilentlyContinue
ranz whoami
```

With the fingerprint it works, whatever PC B trusts. Pin it again, which the later steps of PC B expect:

```powershell run
$env:RANZ_TLS_FINGERPRINT = "<FINGERPRINT>"
```

The later steps run on the new certificate. Step 27 removes the files with `C:\ranz-test`, and the data directory of the Controller, which holds the setting.

## Part 5. Check

### 22. `ranz doctor` (doctor)

<!-- step: doctor pc=both -->

`ranz doctor` is the successor of the Check command of vpncmd. It checks the PC that it runs on, not the overlay: the clock, memory, text, the file system, threads and TLS over the network. With `-bundle` it also writes the diagnostics bundle of the PC (SDN-54): one ZIP file with the logs of the Node, its settings, the state of the services and the report of the checks, and, on PC A, the log of the Controller. It holds no secret: the values of tokens, passwords and keys are replaced, and `manifest.json` in the file lists every part with the number of secrets replaced in it. `-o` names the file, which must not exist yet. Run it on each PC:

```powershell run
ranz doctor -bundle -o C:\ranz-test\bundle-host.zip
```

Every line says `Pass` and the verdict is `All checks passed`. The exit code is 0. A check that fails prints its reason under it, and the exit code is 1. The last line says where the bundle is. Keep the file: it is what you send with the report of a test that failed.

### 23. What the web UI and the logs show (logs)

<!-- step: logs pc=a -->

On PC A look at the Controller. The Application log has one entry per start and stop of the service (ID 1 and 2), a warning when the TLS port fell back (ID 4) and one when `reset-admin` ran (ID 5):

```powershell run
Get-WinEvent -LogName Application -FilterXPath "*[System[Provider[@Name='ranz-controller']]]" -MaxEvents 3 | Format-List TimeCreated, Id, Message
ranz get events
ranz get revisions
```

- The Application log says `ranz-controller started`.
- `ranz get events` holds two events: `admin-sources-changed`, the admin source allowlist that the first start set (step 5), and `controller-certificate-changed`, the change of step 21. The Controller also raises an event for an automatic rollback of an apply with `--confirm`, a pool near exhaustion, a refused enrolment and a call from a source outside the allowlist (`admin-access-refused`), and none of that happened. The refusals of step 20 are failed authentications in the audit log.
- `ranz get revisions` shows the first start, the apply of step 15 and the apply of step 20. The certificate of step 21 is no part of the Intent, so it made no revision.
- In the web UI, Nodes shows both Nodes connected with the Generation they applied, `pc-a` the Node service and `pc-b` the stand-in, Revisions shows the three revisions, and Events shows the allowlist of the first start and the change of the certificate.

The Diagnostics page of the web UI has a button that downloads the diagnostics bundle of the Controller: its log, its Intent, revisions, events, licence, Nodes and address pools, and the state of its PC, with no secret in it. An operator or an admin may pull it, and every pull is in the audit log. This is the same by command, with the same token (the button calls this URL):

```powershell run
curl.exe -k -s --fail -X POST -H "Authorization: Bearer $((Get-Content $env:RANZ_TOKEN_FILE).Trim())" -o C:\ranz-test\bundle-controller.zip https://localhost/api/v1/diagnostics/bundle
```

The command prints nothing and writes the ZIP file. The log of the Controller is the part `controller/logs/controller.log` in it, and `manifest.json` lists all the parts.

On PC B the stand-in window shows the same story from the Node side: its `[INFO]` lines name each Node, its control stream, its Generation, its address, its sessions and how many packets it forwarded and delivered. The node log of the Node service of PC A tells it of `pc-a` since step 20: the refusals and the delay before each next attempt, the Generations it applied, and the end of its stream when the Controller restarted, with the attempts after it. The node log of the Node service on PC B (step 11) is unchanged: that service took no part.

### 24. Stop the stand-in (stop-stand-in)

<!-- step: stop-stand-in pc=b -->

Stop it by creating the stop file, or press Ctrl+C in its window. Do not kill the process. It cleans up first.

```powershell run
New-Item C:\ranz-test\stop -ItemType File
```

The stand-in checks that the echo requests of PC B reached `pc-a` and that the replies came back into the adapter. It then removes the adapter and prints `FIRSTTEST TEST OK` and `NO MEMORY LEAKS`. Wait for that, and for the end of its process.

### 25. The stand-in is gone (stand-in-gone)

<!-- step: stand-in-gone pc=b -->

On PC B, check that the adapter is gone, and that the Controller sees the stand-in as not connected:

```powershell run
Get-NetAdapter -Name "Ranz default" -ErrorAction SilentlyContinue
ranz get nodes
```

The first command prints nothing. In the answer of the second, `connected` is false for `pc-b`, and true for `pc-a`: that is the Node service of PC A since step 20, which stays connected until the uninstall stops it. (The window of PC B reads the Controller with the viewer token of step 13 and the fingerprint of step 21.)

## Part 6. Clean up

### 26. Uninstall (uninstall)

<!-- step: uninstall pc=both -->

Run on each PC:

```powershell run
ranz uninstall
```

It stops and removes the services, takes out the drivers that `ranz install` put there (and leaves a driver that was there before), removes every rule of the group `Ranz VPN` from Windows Firewall, and removes `C:\Program Files\Ranz VPN`. `Get-NetFirewallRule -Group "Ranz VPN"` then finds no rule, and `ranz node state` says that the Node service is stopped. It keeps the data directories on purpose (ADR-0020): a later `ranz install` resumes with the same Configuration store and the same Controller store, and the Controller keeps the admin source allowlist of that store (`ranz install` says so).

### 27. Remove what uninstall keeps (clean-up)

<!-- step: clean-up pc=both -->

Remove the data directories and the certificate. The data directory `C:\ProgramData\Ranz` is on PC A only: on PC B the command for it prints an error that you can ignore. There is no firewall rule to remove: `ranz uninstall` removed them.

```powershell run
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "CN=Ranz VPN CI signing*" } | Remove-Item
Remove-Item -Recurse -Force C:\ProgramData\Ranz
Remove-Item -Recurse -Force "C:\ProgramData\Hanzcodes\Ranz VPN"
```

Then delete `C:\ranz-test`. Windows keeps the two keys of the Controller (`Ranz controller Noise ...` and `Ranz controller TLS ...`) in its key storage. They are small and a new install at the same path reuses them, so `ranz status` shows the same key and fingerprint again. The static key of the Node service (`Ranz Node`, step 20) stays in the key set of the service account the same way, so `ranz node key` prints the same key after a new install.

## Gaps

<!-- gap: gaps -->

A Gap is something that the runbook needs and the code does not have. Nothing here was built for this runbook. Where a safe workaround exists the steps above use it. Gaps 1 and 2, the Node service that joins its Controller and the static key of a Node that a verb prints, are closed: they are step 20 (SDN-90, #395). Gaps 4, 5 and 6 are closed by SDN-91 (#396): `ranz install` opens the ports of what it installs and `ranz uninstall` closes them (steps 4, 5 and 26), `ranz get audit` reads the audit log (steps 18 and 20), and `ranz node state` shows the state of a Node on its PC (steps 11 and 20). Gap 7, the certificate of the Controller, is closed by SDN-92 (#397): it is step 21. The numbers of the others stay.

3. **The Node service listens only where its Listener says, and it dials nowhere.** A Listener resource (SDN-45, #238) names a Node, the TCP port of its front door and the UDP port of QUIC, 443 each, and the source of their certificate: a PKCS #12 file on the Node, a certificate of the LocalMachine\My store by its thumbprint, or ACME. A Listener may also have a `mimic` section (SDN-94, #423), the settings of the server role of the mimicry sidecar of its Node: the address that the sidecar listens on, the server names (the names of the decoy site, at least one), the decoy (an own site with a certificate source, or a borrowed site with its destination) and the clock tolerance. The sidecar and the front door use different addresses: the sidecar listens on an address of its own, the front door of the Node is another listener, and the `listen` of the section may not take the TCP port of the front door of its Listener. `ranz apply` refuses a section that does, or that is wrong in another way, with a message that says which setting is wrong (an address without a port, a name that is no DNS name, no server name, a borrowed decoy without a destination, an own decoy without a certificate source or with two, a key or a short id). The section holds no key and no short id. The Node makes the key of its mimic server and reports the public key on its control stream; the Controller makes the short id and, once the key is reported, gives each Node that has the server as a peer with a mimic endpoint a link to it (the address of the endpoint, the first server name, the public key and the short id), so no operator copies a key from one Node to another. `ranz explain -listener NAME` shows the section, whether the Node reported its key and the Nodes that have a link. The half that runs on the Node, which applies the settings and the links, makes the key and starts the sidecar from them, is CORE-P2-7 (#424). The Node that applies a Listener starts the front door (`FrontDoorStart`, SDN-29, #205), which hands each TLS connection to the TLS of the new protocol (TLS 1.3 only), and QUIC where `msquic.dll` is present, and its overlay takes the sessions of its peers on them (`src/Cedar/NodeListener.c`; `vpntest listener` proves it). The Intent of this runbook names no Listener, so the Node service of step 20 listens on no port. The address of a peer is closed since SDN-93 (#410): the Node resource names the endpoints under which the other Nodes reach it (step 15), the Controller puts them into the Peer object of every Node that shares a VRF with it, and a Node dials a peer through them with the race of the fallback list, as the data transport of the client role does with the name of a peer (`NodeEndpointsTargets` in `src/Cedar/NodeEndpoints.c`; `vpntest endpoints` proves it against a hub whose Listener takes the dial). Two parts are still missing. The desired state carries no pin of the certificate that a peer presents: a dialling Node pins the thumbprint that its Client setting holds for the server of that name, which CORE-H3 (#400) replaces with a SHA-256 pin bound to the Node identity. And the data transport of the Node service dials nowhere (`NodeControllerNoDial` in `src/Cedar/NodeController.c`): only the client role dials, so a PC that is to dial another needs the client role and its Client setting, which this runbook does not set up. So two Node services cannot form a Noise session, though each joins its Controller (step 20). **No open ticket carries the dial of the Node service.** The relay role binds a UDP socket only when its Roles setting asks for it. Workaround: the two stand-in Nodes run their session in memory.

## Troubleshooting

These are the ways this test fails, with what the code says. Whatever fails, take the diagnostics bundle of each PC (`ranz doctor -bundle`, step 22) and the one of the Controller (step 23) before you uninstall: they hold the logs of the test and no secret.

- **`ranz install` says `the certificate does not chain to a trusted root`.** The PC does not trust the CI certificate. Do step 3. The message names the file that failed.
- **`ranz install` says `does ranz install run as an Administrator?`.** The window is not elevated.
- **`ranz install` prints `install: warning: ... was not installed`.** A driver (SeLow or the XDP runtime) failed and was taken out again. The Node is installed and runs without it. The Capabilities of the Node then say `SeLow no` or `XDP no`.
- **A service is not `Running`.** `install` says `it stopped with exit code N`. Read `C:\ProgramData\Hanzcodes\Ranz VPN\node_log` for the Node and `C:\ProgramData\Ranz\controller\controller.log` for the Controller, and the System log (Service Control Manager).
- **The Controller stops at start and its log names rqlite.** Its store listens on `127.0.0.1:4001` and `127.0.0.1:4002`. Another program holds one of them.
- **The Controller is on 5555 and you did not expect it.** Something held 443 at its first start. The log says `the TLS port fell back`, the Application log has a warning (ID 4) and `ranz status` says `"tlsPortFallback": true`. The fallback stays until you start with an explicit `-listen`, or delete the file `listen-fallback` in the data directory. Use `<PORT>` 5555 in every step.
- **`ranz` says 401.** The token is wrong or deleted: `the bearer token is not a token of this controller, or it was deleted`. On PC A, `ranz controller reset-admin` makes a new admin token, prints it once and writes it to `admin.token`.
- **`ranz` says 403 with `is not allowed to reach the API and the web UI`.** The admin source allowlist does not hold the address of the caller. `ranz admin-sources list` on PC A shows it. A loopback address always passes. `ranz install --controller` sets the list to loopback and the private subnets of PC A, so an address outside them, a public one for example, needs `ranz install --controller --admin-from PREFIX,...` at the install, or `ranz admin-sources set` on PC A afterwards. A global IPv6 address of the same LAN is outside them too: name its `/64`, as step 5 shows. The other way round, a proxy, a load balancer or a masquerading router inside a private subnet of PC A makes every caller behind it look private, and the list lets those callers in (step 5).
- **`ranz` on PC B says `the controller's certificate has the TLS fingerprint ..., not ...`.** `<FINGERPRINT>` is not the one of this Controller, or PC B reaches another machine than PC A.
- **`ranz` on PC A says `ranz sends no token to https://127.0.0.1 without checking who answers there`.** `ranz` checks the certificate of a Controller on its own PC by the file `tls.fingerprint` in the data directory of the Controller (step 7), and it cannot use that file. The message says why, in one of two ways. Either it says that the file cannot be read. The usual cause is that the window is not elevated: the data directory belongs to the Administrators, and a window that is not elevated cannot read it. The other is a Controller that is older than this `ranz`: it writes no such file, and the message says that the file is not there. Or it says `does not trust that file`, and names the folder or the file and who owns it or may write it: `ranz` takes the file only when no account but SYSTEM, the Administrators and the account of the Controller service owns or may write it and its folder, so a folder that a local user made first, one that the Users group may add files to, and a file of another owner are refused. The data directory that `ranz install` made (step 6) is none of them. `ranz` has sent nothing and has not even connected. Open an elevated window, or give the fingerprint that `ranz status` printed in step 7 with `-tls-fingerprint <FINGERPRINT>` or `$env:RANZ_TLS_FINGERPRINT`, which takes the call through without reading the file. `-controller-dir` (or `$env:RANZ_CONTROLLER_DIR`) names the data directory when the Controller uses another one. `ranz login` and `ranz node login` say the same, and open no browser.
- **`ranz` on PC A says `ranz sent no token to https://127.0.0.1: what answers there has a certificate with the TLS fingerprint ..., and ... names ... for the Controller of this host`.** The two fingerprints differ, so something else answers on that port. The usual cause is that the Controller fell back to 5555 (see above) and another program of PC A holds 443, which is the port that `ranz` calls when `RANZ_SERVER` is not set. The other is that the Controller serves another certificate than the file says. `ranz` has sent no token. `ranz login` and `ranz node login` have sent no password either, and opened no browser. Set `$env:RANZ_SERVER = "https://127.0.0.1:5555"` (the `tlsPort` of step 7) and call again, or stop the other program.
- **A connection from PC B times out.** The firewall rules of step 5 (`Get-NetFirewallRule -Group "Ranz VPN"`; `ranz install` says `install: warning: Windows Firewall was not set` when another firewall owns the policy), or PC B does not reach `<PC-A>`. `Test-NetConnection` of step 13 tells.
- **`ranz node` says `needs administrator rights`.** The window is not elevated: the admin pipe of the Node service lets only SYSTEM and the Administrators in. `is stopped` (`does not run here`) means that the Node service is stopped: `Start-Service ranzvpnserver`.
- **`pc-a` does not connect in step 20.** Its node log (step 11) says why, once for each attempt, with the delay before the next one: `the TLS fingerprint check failed` means that `<FINGERPRINT>` is not the one of this Controller; `the Noise handshake failed` means that `<CONTROLLER-KEY>` is not its static key; `the Controller refused the node (reason 1)` means that no Node resource holds `<NODE-KEY>` yet, so do the apply of step 20; `no Controller answered there` means that `<CONTROLLER>` is wrong or the firewall blocks it. Correct the value with `ranz node controller set`, which restarts the Node service.
- **The stand-in says `wintun.dll next to vpntest?`.** Do the `Copy-Item` of step 17. The DLL must be in the folder of `vpntest.exe`. The stand-in needs an elevated window.
- **The stand-in says `not within 90000 ms`.** The Controller did not take the two Nodes. The stand-in does not print the reason of a refusal, so read `controller.log` on PC A: `node refused: unknown static key` means that no Node resource has the key (step 15), and `source address outside the source prefixes of its Network` means that a Network limits the addresses that Nodes may enrol from. No line at all means that the stream did not arrive: look at the firewall and at `<CONTROLLER>`.
- **`FIRSTTEST TEST FAILED` after the stop.** The line that failed says what: no echo request reached `pc-a` (you did not ping in time, or the ping went another way), or the replies did not come back.
- **The ping gets no reply.** `Get-NetRoute -InterfaceAlias "Ranz default"` must show `100.64.0.0/10`. Another VPN may own that range. Tailscale uses `100.64.0.0/10`; stop it for this test.
- **The stand-in prints `Wintun adapter Ranz default not created: error N`.** The adapter could not come up. Look for an older adapter of that name with `Get-NetAdapter -Name "Ranz default"`, for example one that a stand-in left when it was killed instead of stopped. The stand-in waits 5 seconds for an old adapter of the same name to go before it gives up.
- **`ranz controller-cert set` says `the private key file cannot be read`.** The Controller service runs as `NT SERVICE\ranz-controller` and may not read the file: give it read access to the key file, as step 21 does with `icacls`. The paths are on the PC of the Controller.
- **`ranz controller-cert set` says 409 and names a Node.** That Node is not connected, so the Controller could not tell it the fingerprint of the new certificate, and a Node that pinned the old one would not reach the Controller again. Connect it and run the command again. With `-force` the certificate is replaced anyway, and that Node needs `ranz node controller set <CONTROLLER> <CONTROLLER-KEY> <FINGERPRINT>` with the new fingerprint.
- **A Node does not connect after the certificate changed.** Its node log says `the TLS fingerprint check failed` and names the fingerprint that it saw: the Controller serves a certificate that the Node was not told of, as a Node that was not connected during a change with `-force`. Give it the new fingerprint with `ranz node controller set`. If the Controller fell back to its own certificate because its setting could not be read (its log says `the certificate setting cannot be used`), fix the cause, for example the access to the files, and the Controller serves the certificate again within seconds.

## How CI proves it

The job `first_test` of `.github/workflows/windows.yml` runs on `windows-latest` (x64) and `windows-11-arm` (arm64), in the full set of the workflow (it needs `plan`, `build_and_test` and `sign_and_integrity`, and runs when the plan says `full`). It copies the three artifacts of step 1 to the folders of that step, and then `.github/scripts/first-test.ps1` runs the steps of this file one after the other.

- **The script reads this file.** The markers `<!-- step: ... -->` and `<!-- gap: ... -->` give the ids in order. A step of the script that is not the next one in the file fails, and so does a step of the file that the script never ran. So the order and the set of steps cannot drift.
- **The commands are the commands of this file.** A block `powershell run` is run by the script, line by line, in the folder and the PowerShell of the runner, after it fills in the values in angle brackets from what it measured. A block `powershell background` is started and left running, and the script stops it at the end of its step. A command that exits with an error fails the step. The script then checks what the step says you see: the services, the files, the JSON of the API, the pages of the web UI, the audit records, the ping.
- **One machine plays both PCs.** The runner is PC A and PC B. It switches the `RANZ_*` variables of the window when the PC changes, so that PC B reads the Controller through the address of the runner and the fingerprint, as a second PC would. `<PC-A>` is the address of the runner that is not loopback. Step 10 finds the install of step 5 there already, which is safe.
- **The Node service of the runner joins.** Step 20 runs on the one Node service of the runner, as `pc-a`, in place of the stand-in for that Node; the stand-in keeps playing `pc-b`. Before the settings of the runbook, the script sets a wrong TLS fingerprint and then a wrong static key with `ranz node controller set`, and waits for the node log to say which check failed. After the right settings it waits for the refusal of the key in the audit log, then for `pc-a` connected at its acknowledged Generation, and after the restart of the Controller for `pc-a` connected again.
- **The certificate is replaced for real.** Step 21 makes the CA and the certificate with `ranz cert` for the address of the runner, gives the service account of the Controller the key file, and sets the certificate. The script reads the answer (the two Nodes pinned, the new fingerprint), the log, the events and the audit log, and checks that the Nodes that were connected stayed connected: the Controller log has no new `node connected` line. A certificate for another host is refused with its reason, and the certificate in use stays. The Node service must hold the new fingerprint and keep it in its settings. After the restart of the Controller and then of the Node service, both Nodes are connected again at their acknowledged Generation, and the node log has no new failure of the fingerprint check. PC B reaches the Controller with no fingerprint once it trusts the CA, with the new fingerprint, and the web UI answers 200 to a client that checks the chain. With the CA out of the store, `ranz` without the fingerprint is refused with `unknown authority`.
- **The admin source allowlist is read back.** The script checks the line of `ranz install` about the list (step 5), the lines of the first start in `controller.log` about the list and the starter rule (step 6), and `adminAccess` and `starterRule` of `ranz status` (step 7). PC B then reaches the Controller from the address of the runner, which is not loopback, so the list must hold it: on a private subnet it is in the default list, and when the address is not private the script adds it with `ranz admin-sources set` first, as the troubleshooting says, and counts that change among the events of steps 21 and 23. A runner is on a private subnet, so the script also takes that branch for an address of the documentation range, `203.0.113.77`: it checks that `ranz admin-sources list` then holds the address and every entry that it held, puts the list back, and counts the two changes among the events as well.
- **The firewall, the audit log and the state of the Node are read back.** After each install the script reads the rules of the group `Ranz VPN` from Windows Firewall, with their protocols, ports and programs: the three of the Node and the Controller, the same rules (by their ids) after the second install of step 10, none after the uninstall. It reads the enrolments and the refusal of the key of step 20 with `ranz get audit`, checks that a call without a valid token is refused, and reads `ranz node state` of the Node service before and after it joins, and once it is uninstalled.
- **A Gap is read from the sources.** At the Gap step, which the script runs last, it looks in the sources for what the document says is missing: a data transport of the Node service that dials a peer (Gap 3). When it is there, the job fails, until this file has real steps for it. It also checks that the closed Gaps stay closed: the Node service sets the control stream of its overlay, the CLI has the verbs of steps 20 and 21, `ranz install` knows the firewall, and the CLI has the verbs for the audit log and the state of a Node. So does the part of Gap 3 that SDN-93 closed: a Node dials a peer through its endpoints.
- **What CI cannot do.** It cannot try two PCs, a browser, or the Gaps. The web UI is checked by its pages and by the API calls that the pages make. The overlay between two Nodes is the stand-in, with one real Wintun adapter and a fake host.
