# First test of the product on two PCs

This is the runbook for the first test of Ranz VPN on two real Windows PCs. You run it by hand. The steps are in the order you do them. The same steps run in CI, in the same order, from this file (see "How CI proves it" at the end), so a command that stops working breaks the build and not your afternoon.

## What this test shows today

Read this first. The Node service of a PC joins its Controller (step 20), but two Node services cannot form a Noise session with each other yet (see Gaps at the end). So the test has three kinds of steps:

- **Real.** The product does it: install, the Controller and its certificate, the web UI, the default Intent, PC B reaching the Controller, the link between the PCs, the Node resources and their addresses, the Node service of PC A joining the Controller with its own key, `ranz doctor`, the logs and the diagnostics bundles, uninstall. Most steps are real.
- **Stand-in.** `vpntest firsttest`, a test program that is built in CI, plays the Nodes that need a session with each other. It enrols two Nodes at the Controller of PC A over the real network, gives one of them a real Wintun adapter and answers a ping for the other. Steps 17, 19 and 23. From step 20 on, the Node service of PC A plays `pc-a` and the stand-in plays `pc-b` only.
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
| `<FINGERPRINT>` | The TLS fingerprint of the Controller | step 7, `tlsFingerprint` |
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
| 21 | doctor | both | real |
| 22 | logs | A | real |
| 23 | stop-stand-in | B | stand-in |
| 24 | stand-in-gone | B | real |
| 25 | uninstall | both | real |
| 26 | clean-up | both | real |
| 27 | gaps | | gap |

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

`ranz install` writes `ranz-node.exe`, the drivers and a copy of `ranz.exe`. It refuses every file whose signature does not chain to a trusted root. The CI build is signed with a self-signed certificate, so each PC must trust that certificate as a root first. (A release build will carry a purchased certificate and needs no such step.) Step 26 removes it again.

```powershell run
Import-Certificate -FilePath C:\ranz-test\cert\ranz-ci-signing.cer -CertStoreLocation Cert:\LocalMachine\Root
(Get-AuthenticodeSignature C:\ranz-test\ranz\ranz.exe).Status
```

The last line must be `Valid`. The signer is `CN=Ranz VPN CI signing (self-signed), O=Hanzcodes`.

### 4. Open the firewall on PC A (firewall)

<!-- step: firewall pc=a -->

Windows Firewall blocks incoming connections, and `ranz install` adds no rule. PC A needs TCP 443 for the Controller: the web UI, the API and the control streams of the Nodes all use it. TCP 5555 is its fallback port. TCP 9821 is for the link check of step 14. `docs/ports.md` lists every port of the product. PC B needs no rule: nothing of it listens.

```powershell run
New-NetFirewallRule -DisplayName "Ranz first test" -Direction Inbound -Protocol TCP -LocalPort 443,5555,9821 -Action Allow | Select-Object DisplayName, Enabled, Direction, Action
```

Step 26 removes the rule.

## Part 1. PC A: the Controller

### 5. Install the Node and the Controller (install-a)

<!-- step: install-a pc=a -->

```powershell run
ranz install --controller
```

This does the following, and checks the hash and the signature of every file before it writes the file. A file that fails is never written.

- It makes the folder `C:\Program Files\Ranz VPN` for SYSTEM and the Administrators. It writes `ranz-node.exe`, `wintun.dll`, `NOTICE.txt` and a copy of `ranz.exe` into it.
- On x64 it installs the SeLow driver and the XDP runtime. On arm64 there are none: Wintun is the only driver.
- It registers and starts the Node service `ranzvpnserver`.
- Because of `--controller` it also registers and starts the Controller service `ranz-controller`. The Controller brings its own rqlite member inside `ranz.exe`.

The last lines are `install: the ranz-controller service is running` and `ranz install: done`. It is safe to run the command again.

### 6. The Controller starts (controller-up)

<!-- step: controller-up pc=a -->

```powershell run
Get-Service ranzvpnserver, ranz-controller
Get-ChildItem C:\ProgramData\Ranz\controller
Get-Content C:\ProgramData\Ranz\controller\controller.log -Tail 12
```

Both services are `Running`. The folder `C:\ProgramData\Ranz\controller` is the data directory of the Controller. At its first start the Controller made:

- `admin.token`: the secret of the admin API token. Only SYSTEM, the Administrators, the owner of the folder and the service account can read it.
- `controller.log`: its log. It says `first start: the intent of a first install` and `TLS port`.
- `payload\rqlited.exe` and `rqlite\`: its store.

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
  ...
}
```

Write down `publicKey` as `<CONTROLLER-KEY>`, `tlsFingerprint` as `<FINGERPRINT>` and `tlsPort` as `<PORT>`. If `tlsPort` is `5555`, the Controller fell back and `tlsPortFallback` is `true`.

`ranz` on PC A does not check the certificate: loopback is the host itself. On any other PC, `ranz` accepts the certificate only with the fingerprint (step 13). A browser cannot check the fingerprint, so it warns. The certificate cannot be replaced by one that a browser trusts yet (Gap 7).

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

## Part 2. PC B: a Node

### 10. Install the Node (install-b)

<!-- step: install-b pc=b -->

On PC B run steps 1, 2 and 3 first. PC B needs no firewall rule (step 4). Then:

```powershell run
ranz install
```

This is the same install without `--controller`: no Controller service is made. Nothing of PC B listens on the network today.

### 11. The Node runs (node-up)

<!-- step: node-up pc=b -->

```powershell run
Get-Service ranzvpnserver
Get-ChildItem "$env:ProgramData\Hanzcodes\Ranz VPN"
Get-ChildItem "$env:ProgramData\Hanzcodes\Ranz VPN\node_log" -Recurse -File | Select-String "Node started|Capabilities:|Controller: none"
```

The service is `Running`. The data directory of the Node, `C:\ProgramData\Hanzcodes\Ranz VPN`, holds its Configuration store `ranz_node.db`, a text copy of its settings `node_config.txt` (the Node writes it at its start, and it holds no password hash), and the folder `node_log`. The log says `Node started` and, a moment later, the Capabilities of the PC, for example `Capabilities: architecture x64, SeLow yes, XDP yes`. On arm64 it says `SeLow no, XDP no`. It also says once at each start `Controller: none`: the Node has no Controller settings yet (step 20 gives them to the Node of PC A), so it opens no control stream and dials no Controller.

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

`TcpTestSucceeded` must be `True`. If not, the firewall of step 4 or the network is the problem. `ranz whoami` prints the name `pc-b` and the role `viewer`. `ranz get resources` prints the three resources of step 9. The `RANZ_TLS_FINGERPRINT` makes `ranz` accept the certificate of the Controller only when its fingerprint is the one you copied. A wrong value fails. The viewer token cannot change anything: `ranz apply` from PC B is answered with 403.

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

The client prints one line for the connection, then a table with a row Download, Upload and Total and the rate of each. Stop the server on PC A with Ctrl+C. Once the overlay carries traffic, the same test between the two overlay addresses measures the overlay.

## Part 3. The Nodes join and get addresses

### 15. Declare the two Nodes (declare-nodes)

<!-- step: declare-nodes pc=a -->

A Node is part of the network only when the Intent holds a Node resource with the static key of that Node. You apply two. They name no VRF, so both join VRF `default`.

The keys below are the two public test keys of the stand-in, which plays both Nodes until step 20 puts the key of the Node service of PC A into `pc-a`. Their private halves are in the source of `vpntest`, so anyone who reaches your Controller could act as these two Nodes. Use them on a test Controller only.

```powershell run
Set-Content -Path C:\ranz-test\nodes.json -Value '{"resources":[{"kind":"Node","name":"pc-a","spec":{"publicKey":"B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw="}},{"kind":"Node","name":"pc-b","spec":{"publicKey":"WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns="}}]}'
ranz apply -f C:\ranz-test\nodes.json
```

`ranz apply` prints the revision it made, 2, and the Generation of the state of each Node. Every apply is a revision: `ranz diff` shows what it changed and `ranz rollback 1` undoes it.

### 16. How each Node gets its address (addresses)

<!-- step: addresses pc=a -->

Only the Controller gives out addresses. There is no DHCP in the overlay. The address of a Node is the lowest free host address of the pool, and the Nodes come in the order of their names. It stays the address of that Node while the Node is in the Network. The Controller does this when you apply, before any Node connects:

```powershell run
ranz get resources
ranz get ipam
```

In the Node resources, `spec.addresses.default` is the address in Network `default`. `pc-a` has `100.64.0.1` and `pc-b` has `100.64.0.2`. Write down `100.64.0.1` as `<PC-A-OVERLAY>`. `ranz get ipam` shows `allocated` 2 for the pool. The Nodes page of the web UI lists both Nodes. They are not connected yet.

A Node learns its address in its desired state, which the Controller sends it on its control stream. The address is set on the Wintun adapter of the Node as a host address. The adapter also gets a route to the pool.

### 17. Start the stand-in Nodes (stand-in)

<!-- step: stand-in pc=b -->

This is the stand-in for two Node services that form a session with each other (Gap 3). `vpntest firsttest` runs two Nodes in one process on PC B. Each opens its control stream to the Controller of PC A, with the static key of its Node resource, as a Node service does:

- `pc-b` is a real Node with a real Wintun adapter named `Ranz default`. The adapter gets the address of `pc-b`, as the client role of the Node brings it up. The packets of PC B on this adapter go into the overlay.
- `pc-a` is a Node with a fake host that answers an ICMP echo request to its address. The two Nodes run their Noise session in memory.

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
curl.exe -k -s -H "Authorization: Bearer $((Get-Content $env:RANZ_TOKEN_FILE).Trim())" "https://localhost/api/v1/audit?kind=enrolment"
Get-Content C:\ProgramData\Ranz\controller\controller.log -Tail 20
```

- `ranz get nodes` shows `pc-a` and `pc-b` with `connected` true. `generation` and `ackedGeneration` are equal: the Node applied the last state. The `capabilities` are the ones the Node put in its Hello: the architecture of PC B, and whether SeLow and the XDP runtime are there.
- The audit log has one record of the kind `enrolment` for each Node: `the first control stream of the static key of this node`, with the address that the stream came from. (There is no `ranz` verb for the audit log yet, so the command calls the API. The Events of the web UI are another list: they hold the events of the Controller, such as an automatic rollback.)
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
curl.exe -k -s -H "Authorization: Bearer $((Get-Content $env:RANZ_TOKEN_FILE).Trim())" "https://localhost/api/v1/audit?kind=auth-failed"
```

Put the key into the Node resource `pc-a`, in place of the test key of the stand-in:

```powershell run
Set-Content -Path C:\ranz-test\pc-a.json -Value '{"resources":[{"kind":"Node","name":"pc-a","spec":{"publicKey":"<NODE-KEY>"}}]}'
ranz apply -f C:\ranz-test\pc-a.json
```

The Controller refuses the stream of the stand-in for `pc-a` at once: its key is no longer the one of the Node resource. The Node service joins on its next attempt, within a minute, without a restart. Wait a minute, then look at the Nodes:

```powershell run
ranz get nodes
```

`pc-a` is connected, at the Generation it acknowledged, with the Capabilities of PC A. It holds the address `100.64.0.1` of the Node resource and its node log says `Overlay: generation`, but it has no adapter: the Roles of a default install do not bring one up, and no other Node can reach it (Gap 3).

Restart the Controller. The Node dials again by itself, after a delay that starts at 1 second again since its stream was open:

```powershell run
Restart-Service ranz-controller
```

A few seconds after the Controller is back, `ranz get nodes` shows `pc-a` connected again, and the node log says `the control stream ended after it was open` with the attempts after it.

## Part 4. Check

### 21. `ranz doctor` (doctor)

<!-- step: doctor pc=both -->

`ranz doctor` is the successor of the Check command of vpncmd. It checks the PC that it runs on, not the overlay: the clock, memory, text, the file system, threads and TLS over the network. With `-bundle` it also writes the diagnostics bundle of the PC (SDN-54): one ZIP file with the logs of the Node, its settings, the state of the services and the report of the checks, and, on PC A, the log of the Controller. It holds no secret: the values of tokens, passwords and keys are replaced, and `manifest.json` in the file lists every part with the number of secrets replaced in it. `-o` names the file, which must not exist yet. Run it on each PC:

```powershell run
ranz doctor -bundle -o C:\ranz-test\bundle-host.zip
```

Every line says `Pass` and the verdict is `All checks passed`. The exit code is 0. A check that fails prints its reason under it, and the exit code is 1. The last line says where the bundle is. Keep the file: it is what you send with the report of a test that failed.

### 22. What the web UI and the logs show (logs)

<!-- step: logs pc=a -->

On PC A look at the Controller. The Application log has one entry per start and stop of the service (ID 1 and 2), a warning when the TLS port fell back (ID 4) and one when `reset-admin` ran (ID 5):

```powershell run
Get-WinEvent -LogName Application -FilterXPath "*[System[Provider[@Name='ranz-controller']]]" -MaxEvents 3 | Format-List TimeCreated, Id, Message
ranz get events
ranz get revisions
```

- The Application log says `ranz-controller started`.
- `ranz get events` is empty: the Controller raises an event for an automatic rollback of an apply with `--confirm`, a pool near exhaustion and a refused enrolment, and none of that happened. The refusals of step 20 are failed authentications in the audit log.
- `ranz get revisions` shows the first start, the apply of step 15 and the apply of step 20.
- In the web UI, Nodes shows both Nodes connected with the Generation they applied, `pc-a` the Node service and `pc-b` the stand-in, Revisions shows the three revisions, and Events is empty.

The Diagnostics page of the web UI has a button that downloads the diagnostics bundle of the Controller: its log, its Intent, revisions, events, licence, Nodes and address pools, and the state of its PC, with no secret in it. An operator or an admin may pull it, and every pull is in the audit log. This is the same by command, with the same token (the button calls this URL):

```powershell run
curl.exe -k -s --fail -X POST -H "Authorization: Bearer $((Get-Content $env:RANZ_TOKEN_FILE).Trim())" -o C:\ranz-test\bundle-controller.zip https://localhost/api/v1/diagnostics/bundle
```

The command prints nothing and writes the ZIP file. The log of the Controller is the part `controller/logs/controller.log` in it, and `manifest.json` lists all the parts.

On PC B the stand-in window shows the same story from the Node side: its `[INFO]` lines name each Node, its control stream, its Generation, its address, its sessions and how many packets it forwarded and delivered. The node log of the Node service of PC A tells it of `pc-a` since step 20: the refusals and the delay before each next attempt, the Generations it applied, and the end of its stream when the Controller restarted, with the attempts after it. The node log of the Node service on PC B (step 11) is unchanged: that service took no part.

### 23. Stop the stand-in (stop-stand-in)

<!-- step: stop-stand-in pc=b -->

Stop it by creating the stop file, or press Ctrl+C in its window. Do not kill the process. It cleans up first.

```powershell run
New-Item C:\ranz-test\stop -ItemType File
```

The stand-in checks that the echo requests of PC B reached `pc-a` and that the replies came back into the adapter. It then removes the adapter and prints `FIRSTTEST TEST OK` and `NO MEMORY LEAKS`. Wait for that, and for the end of its process.

### 24. The stand-in is gone (stand-in-gone)

<!-- step: stand-in-gone pc=b -->

On PC B, check that the adapter is gone, and that the Controller sees the stand-in as not connected:

```powershell run
Get-NetAdapter -Name "Ranz default" -ErrorAction SilentlyContinue
ranz get nodes
```

The first command prints nothing. In the answer of the second, `connected` is false for `pc-b`, and true for `pc-a`: that is the Node service of PC A since step 20, which stays connected until the uninstall stops it. (The window of PC B reads the Controller with the viewer token of step 13.)

## Part 5. Clean up

### 25. Uninstall (uninstall)

<!-- step: uninstall pc=both -->

Run on each PC:

```powershell run
ranz uninstall
```

It stops and removes the services, takes out the drivers that `ranz install` put there (and leaves a driver that was there before), and removes `C:\Program Files\Ranz VPN`. It keeps the data directories on purpose (ADR-0020): a later `ranz install` resumes with the same Configuration store and the same Controller store.

### 26. Remove what uninstall keeps (clean-up)

<!-- step: clean-up pc=both -->

Remove the data directories, the certificate and the firewall rule. The firewall rule is on PC A only, and the data directory `C:\ProgramData\Ranz` too: on PC B the commands for them print an error that you can ignore.

```powershell run
Remove-NetFirewallRule -DisplayName "Ranz first test"
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "CN=Ranz VPN CI signing*" } | Remove-Item
Remove-Item -Recurse -Force C:\ProgramData\Ranz
Remove-Item -Recurse -Force "C:\ProgramData\Hanzcodes\Ranz VPN"
```

Then delete `C:\ranz-test`. Windows keeps the two keys of the Controller (`Ranz controller Noise ...` and `Ranz controller TLS ...`) in its key storage. They are small and a new install at the same path reuses them, so `ranz status` shows the same key and fingerprint again. The static key of the Node service (`Ranz Node`, step 20) stays in the key set of the service account the same way, so `ranz node key` prints the same key after a new install.

## Gaps

<!-- gap: gaps -->

A Gap is something that the runbook needs and the code does not have. Nothing here was built for this runbook. Where a safe workaround exists the steps above use it. Gaps 1 and 2, the Node service that joins its Controller and the static key of a Node that a verb prints, are closed: they are step 20 (SDN-90, #395). The numbers of the others stay.

3. **The Node service listens on no port.** `TransportQuicServerNew`, `TransportTlsServerNew` and the front door (`FrontDoorStart`, SDN-29, #205) are called by tests only, and the relay role binds a UDP socket only when its Roles setting asks for it. With the default settings two Node services cannot form a Noise session, though each joins its Controller (step 20). **No open ticket carries it:** CORE-S1-1 (#67), CORE-S2-1 (#69) and SDN-29 (#205) delivered the modules and not their wiring into the service. Workaround: the two stand-in Nodes run their session in memory.
4. **`ranz install` opens no firewall port.** The runbook adds and removes one rule by hand (steps 4 and 26). **No ticket carries it.** (REL-2, #47, did this for the slim fork.)
5. **No `ranz` verb for the audit log.** The API has it (SDN-49, #242, `GET /api/v1/audit`), the CLI does not. Step 18 uses `curl.exe`. **No ticket carries it.**
6. **No verb shows a Node's own state on its PC.** Its adapters, its sessions and its control stream show only in `ranz get nodes` on the Controller side and in the node log. `ranz doctor` checks the PC, not the Node, and `ranz doctor -bundle` (SDN-54, #247) collects the node log and the settings of the Node, not its live state. The nearest is SDN-55 (#248), the tray, which talks to the Node over a pipe. No verb is promised there.
7. **The certificate of the Controller cannot be replaced.** It is always its own self-signed one (step 7), so a browser warns and `ranz` on another PC needs the fingerprint. `ranz cert` makes certificates, but the Controller has no setting to use one. SDN-45 (#238) gives a Node a certificate source (file, key storage or ACME); **no ticket names the Controller's certificate.**

## Troubleshooting

These are the ways this test fails, with what the code says. Whatever fails, take the diagnostics bundle of each PC (`ranz doctor -bundle`, step 21) and the one of the Controller (step 22) before you uninstall: they hold the logs of the test and no secret.

- **`ranz install` says `the certificate does not chain to a trusted root`.** The PC does not trust the CI certificate. Do step 3. The message names the file that failed.
- **`ranz install` says `does ranz install run as an Administrator?`.** The window is not elevated.
- **`ranz install` prints `install: warning: ... was not installed`.** A driver (SeLow or the XDP runtime) failed and was taken out again. The Node is installed and runs without it. The Capabilities of the Node then say `SeLow no` or `XDP no`.
- **A service is not `Running`.** `install` says `it stopped with exit code N`. Read `C:\ProgramData\Hanzcodes\Ranz VPN\node_log` for the Node and `C:\ProgramData\Ranz\controller\controller.log` for the Controller, and the System log (Service Control Manager).
- **The Controller stops at start and its log names rqlite.** Its store listens on `127.0.0.1:4001` and `127.0.0.1:4002`. Another program holds one of them.
- **The Controller is on 5555 and you did not expect it.** Something held 443 at its first start. The log says `the TLS port fell back`, the Application log has a warning (ID 4) and `ranz status` says `"tlsPortFallback": true`. The fallback stays until you start with an explicit `-listen`, or delete the file `listen-fallback` in the data directory. Use `<PORT>` 5555 in every step.
- **`ranz` says 401.** The token is wrong or deleted: `the bearer token is not a token of this controller, or it was deleted`. On PC A, `ranz controller reset-admin` makes a new admin token, prints it once and writes it to `admin.token`.
- **`ranz` says 403 with `is not allowed to reach the API and the web UI`.** The admin source allowlist does not hold the address of the caller. `ranz admin-sources list` on PC A shows it. A loopback address always passes.
- **`ranz` on PC B says `the controller's certificate has the TLS fingerprint ..., not ...`.** `<FINGERPRINT>` is not the one of this Controller, or PC B reaches another machine than PC A.
- **A connection from PC B times out.** The firewall (step 4), or PC B does not reach `<PC-A>`. `Test-NetConnection` of step 13 tells.
- **`ranz node` says `needs administrator rights`.** The window is not elevated: the admin pipe of the Node service lets only SYSTEM and the Administrators in. `does not run here` means that the Node service is stopped: `Start-Service ranzvpnserver`.
- **`pc-a` does not connect in step 20.** Its node log (step 11) says why, once for each attempt, with the delay before the next one: `the TLS fingerprint check failed` means that `<FINGERPRINT>` is not the one of this Controller; `the Noise handshake failed` means that `<CONTROLLER-KEY>` is not its static key; `the Controller refused the node (reason 1)` means that no Node resource holds `<NODE-KEY>` yet, so do the apply of step 20; `no Controller answered there` means that `<CONTROLLER>` is wrong or the firewall blocks it. Correct the value with `ranz node controller set`, which restarts the Node service.
- **The stand-in says `wintun.dll next to vpntest?`.** Do the `Copy-Item` of step 17. The DLL must be in the folder of `vpntest.exe`. The stand-in needs an elevated window.
- **The stand-in says `not within 90000 ms`.** The Controller did not take the two Nodes. The stand-in does not print the reason of a refusal, so read `controller.log` on PC A: `node refused: unknown static key` means that no Node resource has the key (step 15), and `source address outside the source prefixes of its Network` means that a Network limits the addresses that Nodes may enrol from. No line at all means that the stream did not arrive: look at the firewall and at `<CONTROLLER>`.
- **`FIRSTTEST TEST FAILED` after the stop.** The line that failed says what: no echo request reached `pc-a` (you did not ping in time, or the ping went another way), or the replies did not come back.
- **The ping gets no reply.** `Get-NetRoute -InterfaceAlias "Ranz default"` must show `100.64.0.0/10`. Another VPN may own that range. Tailscale uses `100.64.0.0/10`; stop it for this test.
- **The stand-in prints `Wintun adapter Ranz default not created: error N`.** The adapter could not come up. Look for an older adapter of that name with `Get-NetAdapter -Name "Ranz default"`, for example one that a stand-in left when it was killed instead of stopped. The stand-in waits 5 seconds for an old adapter of the same name to go before it gives up.

## How CI proves it

The job `first_test` of `.github/workflows/windows.yml` runs on `windows-latest` (x64) and `windows-11-arm` (arm64), in the full set of the workflow (it needs `plan`, `build_and_test` and `sign_and_integrity`, and runs when the plan says `full`). It copies the three artifacts of step 1 to the folders of that step, and then `.github/scripts/first-test.ps1` runs the steps of this file one after the other.

- **The script reads this file.** The markers `<!-- step: ... -->` and `<!-- gap: ... -->` give the ids in order. A step of the script that is not the next one in the file fails, and so does a step of the file that the script never ran. So the order and the set of steps cannot drift.
- **The commands are the commands of this file.** A block `powershell run` is run by the script, line by line, in the folder and the PowerShell of the runner, after it fills in the values in angle brackets from what it measured. A block `powershell background` is started and left running, and the script stops it at the end of its step. A command that exits with an error fails the step. The script then checks what the step says you see: the services, the files, the JSON of the API, the pages of the web UI, the audit records, the ping.
- **One machine plays both PCs.** The runner is PC A and PC B. It switches the `RANZ_*` variables of the window when the PC changes, so that PC B reads the Controller through the address of the runner and the fingerprint, as a second PC would. `<PC-A>` is the address of the runner that is not loopback. Step 10 finds the install of step 5 there already, which is safe.
- **The Node service of the runner joins.** Step 20 runs on the one Node service of the runner, as `pc-a`, in place of the stand-in for that Node; the stand-in keeps playing `pc-b`. Before the settings of the runbook, the script sets a wrong TLS fingerprint and then a wrong static key with `ranz node controller set`, and waits for the node log to say which check failed. After the right settings it waits for the refusal of the key in the audit log, then for `pc-a` connected at its acknowledged Generation, and after the restart of the Controller for `pc-a` connected again.
- **A Gap is read from the sources.** At the Gap step, which the script runs last, it looks in the sources for what the document says is missing: a listener or a front door in the Node service (Gap 3), a firewall rule in `ranz install` (Gap 4), a verb for the audit log in the CLI (Gap 5). When one is there, the job fails, until this file has real steps for it. It also checks that Gaps 1 and 2 stay closed: the Node service sets the control stream of its overlay, and the CLI has the verbs of step 20.
- **What CI cannot do.** It cannot try two PCs, a browser, or the Gaps. The web UI is checked by its pages and by the API calls that the pages make. The overlay between two Nodes is the stand-in, with one real Wintun adapter and a fake host.
