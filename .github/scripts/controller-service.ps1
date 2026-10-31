param(
	[string] $BinDir = 'build\ranz',
	# The signed rqlited.exe that this ranz.exe carries as its Payload (the signing step of ranz.yml)
	[string] $Member = $env:RQLITED_SIGNED
)

$ErrorActionPreference = 'Stop'

# ranz controller as a Windows service (SDN-2, #178; ONE-1, #310: the controller is a subcommand of
# the one executable ranz, and the service runs ranz.exe controller). Installed with its own rqlite
# member as its sidecar (ONE-4, #313: the rqlited.exe that ranz.exe carries as a Payload, with no
# -rqlited flag and no rqlited beside ranz.exe) and with plain HTTP on port 80, the service must:
# - write its rqlite member as payload\rqlited.exe in its data directory, with the bytes of the
#   signed Payload and a valid Authenticode signature, and run that file; write it again at the next
#   start when it was deleted while the service was stopped, and, while the service is stopped, let
#   reset-admin write it again and run it;
# - run as its virtual account NT SERVICE\ranz-controller, not LocalSystem, with an unrestricted
#   service SID that is the serviceSID of controller/service_windows.go, from the command line
#   ranz.exe controller with the flags it was installed with; run with the
#   process mitigations of internal/mitigation and load DLLs from System32 only, as go test reads
#   its process from outside (TestProcess), and say so in its log (ADR-0039, SEC-1 #279);
# - reserve the URL prefixes of port 80 in HTTP.sys for that account at install, and remove them
#   at uninstall;
# - serve the API and the control stream on TCP 443, told apart by ALPN;
# - serve port 80 through HTTP.sys, which the runner's system holds already: its own answer on
#   the ACME HTTP-01 path, and a 301 to HTTPS on the TLS port for the rest of the port unless
#   another HTTP.sys user held that catch-all first (on the runner one does), nothing else;
# - create the admin token at its first start, with its secret in admin.token in the data
#   directory, and keep it across restarts (SDN-14, #190);
# - create the intent of a first install at its first start as revision 1: VRF default, its
#   Network with the automatic pool and the starter rule (ADR-0034, SDN-3 #179);
# - refuse a call without a token (401) and an apply with a viewer token (403), and answer the
#   admin token from an address of the host that is not loopback, with the TLS fingerprint of
#   its status pinned, while a wrong fingerprint fails;
# - report the Personal tier through `ranz get licence` while no licence key is installed;
# - take an intent from `ranz apply`, push generation 1 to a simulated node (ranz-nodesim) and
#   record its acknowledgement;
# - keep the intent, the acknowledged generation and its keys across a restart of the service:
#   the same Noise static key (a node with the key it had before still connects) and the same TLS
#   key (the same fingerprint) from the key storage provider;
# - fall back to TCP 5555 when 443 is taken, warn about it in the Application log, report it in
#   its capabilities, and keep 5555 after 443 is free again (ADR-0020);
# - keep each apply as a revision across those restarts, and through `ranz` (SDN-13, #189): show
#   what a revision changed with `ranz diff`, roll back by itself an apply with -confirm that
#   nobody confirmed and record the event, return to a revision with `ranz rollback`, and keep
#   an apply that `ranz confirm` confirmed;
# - once admin.token is deleted, get a new admin token from `ranz controller reset-admin`, run by
#   the runner's elevated account with the flags of the service, while the service runs and while
#   it is stopped: reset-admin prints the secret, writes it to admin.token, and the API answers
#   it as admin;
# - leave its files as AUD1-DT-10 (#458) says (controller-hostfiles.ps1): a data directory that
#   install made owned by the Administrators, with a protected access list; a backup written for
#   SYSTEM and the Administrators only, whatever its folder lets in, that holds the secret of a
#   target sealed and is named by what `ranz controller backup` says, and whose restore under the
#   running service brings the target back with its secret; and no start of the service in a
#   data directory that a standard user owns;
# - write the TLS fingerprint file that ranz trusts (AUD1-DT-14, #496): owned by SYSTEM, the
#   Administrators or its own account, with no rule for another account that writes it, and refused
#   by ranz, with the folder named and no token sent, in a folder that the Users group may write
#   (controller-hostfiles.ps1);
# - refuse the API from an address outside the admin source allowlist (SDN-39, #232): with the
#   list set to documentation addresses, the runner's own address, which is not loopback, gets 403
#   and an admin-access-refused event while loopback still passes, and with the list removed the
#   address passes again;
# - write its starts and stops to the Application log (event IDs 1 and 2 of
#   controller/service_windows.go), a warning for each start on the fallback (4) and for
#   each reset-admin (5), and no failure entry (3).

$bin = (Resolve-Path $BinDir).Path
$ranz = Join-Path $bin 'ranz.exe'
$nodesim = Join-Path $bin 'ranz-nodesim.exe'
if (-not $Member -or -not (Test-Path -LiteralPath $Member)) {
	throw 'the signed rqlited.exe of the Payload is not named: pass -Member, or set RQLITED_SIGNED as the signing step of ranz.yml does'
}

# serviceName of controller (the package of ranz controller), its TLS port (the default -listen,
# and the fallback), and the prefixes that port.PlainPrefixes makes of -http-listen :80
$service = 'ranz-controller'
$api = 'https://127.0.0.1'
$control = '127.0.0.1:443'
$acmePrefix = 'http://+:80/.well-known/acme-challenge/'
$redirectPrefix = 'http://*:80/'
# The account of the service and its SID (serviceAccount and serviceSID of service_windows.go)
$account = "NT SERVICE\$service"
$serviceSid = 'S-1-5-80-3572785604-795126647-2475823641-2319294638-1653438898'

$data = Join-Path $env:RUNNER_TEMP 'ranz-controller-data'
# adminTokenFile of controller: the secret of the admin token of the first start
$tokenFile = Join-Path $data 'admin.token'
# Toward a loopback address ranz checks the TLS fingerprint that the controller writes to this directory (AUD1-DT-13, #461)
$env:RANZ_CONTROLLER_DIR = $data
# Where the controller writes its rqlite member: payloadDir of controller/ and the name of the Payload
$memberFile = Join-Path $data 'payload\rqlited.exe'
$work = Join-Path $env:RUNNER_TEMP 'ranz-controller-check'
New-Item -ItemType Directory -Force -Path $work | Out-Null

# How long the service may take to serve, and a node to acknowledge (s)
$waitSeconds = 60

$since = (Get-Date).AddSeconds(-2)

# Run a program, fail on a non-zero exit code, return its standard output
function Invoke-Checked([string] $exe, [string[]] $argv) {
	$out = & $exe @argv
	if ($LASTEXITCODE -ne 0) { throw "$(Split-Path -Leaf $exe) $($argv -join ' ') exited with code $LASTEXITCODE" }
	return ($out -join "`n")
}

# One ranz call with the admin token, its JSON answer as an object
function Invoke-Ranz([string[]] $argv) {
	return (Invoke-Checked $ranz (@('-server', $api, '-token-file', $tokenFile) + $argv)) | ConvertFrom-Json
}

# One ranz call that the controller must refuse with the HTTP status $status; ranz prints the
# status after the controller's error
function Assert-Refused([string[]] $argv, [int] $status) {
	$errFile = Join-Path $work 'ranz.err'
	& $ranz @argv 2> $errFile | Out-Null
	$code = $LASTEXITCODE
	$msg = (Get-Content -LiteralPath $errFile -Raw)
	if ($code -eq 0 -or $msg -notmatch "\($status ") { throw "ranz $($argv -join ' ') was not refused with ${status} (exit code $code): $msg" }
	Write-Host "refused: ranz $($argv -join ' '): $($msg.Trim())"
}

# One reset-admin with the flags of the service, its JSON answer as an object; its messages, and
# the output of the rqlited it runs while the service is stopped, go to the log
function Invoke-ResetAdmin {
	$errFile = Join-Path $work 'reset-admin.err'
	$out = & $ranz controller reset-admin -data $data 2> $errFile
	$code = $LASTEXITCODE
	Get-Content -LiteralPath $errFile | ForEach-Object { Write-Host "  reset-admin: $_" }
	if ($code -ne 0) { throw "ranz controller reset-admin exited with code $code" }
	return ($out -join "`n") | ConvertFrom-Json
}

# Wait until the API answers the admin token; the first start writes the token file
function Wait-Api {
	$end = (Get-Date).AddSeconds($waitSeconds)
	while ($true) {
		& $ranz -server $api -token-file $tokenFile status 2>$null | Out-Null
		if ($LASTEXITCODE -eq 0) { return }
		if ((Get-Date) -ge $end) { throw "the API of $service did not answer on $api within $waitSeconds s" }
		Start-Sleep -Milliseconds 500
	}
}

function Wait-Acked([string] $node, [int] $generation) {
	$end = (Get-Date).AddSeconds($waitSeconds)
	while ($true) {
		$n = (Invoke-Ranz @('get', 'nodes')).nodes | Where-Object { $_.name -eq $node }
		if ($n -and $n.ackedGeneration -eq $generation) { return $n }
		if ((Get-Date) -ge $end) { throw "$node did not acknowledge generation $generation within $waitSeconds s: $($n | ConvertTo-Json -Compress)" }
		Start-Sleep -Milliseconds 200
	}
}

# The simulated node opens the stream on the address $addr and must get the full state as
# generation 1; it prints each update it applied and acknowledged as one line of JSON
function Test-Node([string] $addr, [string] $controllerKey) {
	$received = Invoke-Checked $nodesim @('-key', $key, '-controller', $addr, '-controller-key', $controllerKey, '-until', '1', '-timeout', "${waitSeconds}s")
	$update = ($received.Trim() -split "`n")[0] | ConvertFrom-Json
	if ($update.generation -ne '1' -or $update.baseGeneration -or @($update.set).Count -ne 3) {
		throw "the node on $addr did not get the full state (3 objects) as generation 1: $received"
	}
	return $received
}

# Port 80 outside the ACME path: when the controller holds the catch-all prefix it must redirect
# to $target; when another HTTP.sys user held it first (the runner has one), the controller must
# have left it to that user, so the answer is not the controller's redirect.
function Test-Redirect([string] $target) {
	$redirect = (& curl.exe -s -o NUL -w '%{http_code} %{redirect_url}' 'http://127.0.0.1/api/v1/status')
	if ($script:redirectOurs) {
		Write-Host "port 80, the controller's catch-all: $redirect"
		if ($redirect -ne "301 $target") { throw "port 80 answered '$redirect', not a 301 to $target" }
	} else {
		Write-Host "port 80, the catch-all of the HTTP.sys user that held it first: $redirect"
		if ($redirect -eq "301 $target") { throw "port 80 redirects for the controller although another HTTP.sys user holds $redirectPrefix" }
	}
}

function Get-URLReservation([string] $prefix) {
	return ((& netsh http show urlacl "url=$prefix") -join "`n")
}

# The hardening of ADR-0039 on the running service: its account and the SID Windows gives it, and
# its process read from outside by TestProcess of internal/mitigation, with the debug privilege of
# the runner's elevated account: every mitigation that is not off is set, and every DLL is in
# System32. Its log records them.
function Test-Hardening {
	$svc = Get-CimInstance Win32_Service -Filter "Name='$service'"
	if ($svc.StartName -ne $account) { throw "$service runs as '$($svc.StartName)', not its virtual account $account" }
	$sidType = (& sc.exe qsidtype $service | Out-String)
	if ($sidType -notmatch 'UNRESTRICTED') { throw "the service SID type of $service is not unrestricted:`n$sidType" }
	$sid = (& sc.exe showsid $service | Out-String)
	if ($sid -notmatch [regex]::Escape($serviceSid)) { throw "Windows gives $account another SID than serviceSID ($serviceSid):`n$sid" }
	Write-Host "$service runs as $account ($serviceSid), process $($svc.ProcessId)"
	# The service is the controller subcommand of the one executable (ONE-1): ranz.exe controller
	if ($svc.PathName -notmatch '\\ranz\.exe"? controller ') { throw "$service runs '$($svc.PathName)', not ranz.exe controller with its flags" }
	Write-Host "$service runs $($svc.PathName)"
	Push-Location (Join-Path $PSScriptRoot '..\..')
	try {
		$env:RANZ_MITIGATION_PID = "$($svc.ProcessId)"
		go test -count=1 -v -run '^TestProcess$' ./controller/internal/mitigation
		$code = $LASTEXITCODE
	} finally {
		Remove-Item Env:RANZ_MITIGATION_PID -ErrorAction SilentlyContinue
		Pop-Location
	}
	if ($code -ne 0) { throw "the process of $service lacks a mitigation or loaded a DLL outside System32 (go test exited with code $code)" }
	$log = Get-Content -LiteralPath (Join-Path $data 'controller.log') -Raw
	if ($log -notmatch [regex]::Escape('msg="DLLs load from System32 only"') -or $log -match [regex]::Escape('msg="process mitigation not set"')) {
		throw 'controller.log does not record the process mitigations and the DLL search of the service'
	}
}

# The rqlite member of the controller (ONE-4, #313): no file of rqlite beside ranz.exe, and the file
# that the controller wrote under its data directory has the bytes of the signed Payload and a valid
# Authenticode signature
function Test-MemberFile {
	$beside = @(Get-ChildItem -LiteralPath $bin -Filter 'rqlite*' -ErrorAction SilentlyContinue)
	if ($beside.Count -gt 0) { throw "ranz.exe has files of rqlite beside it: $($beside.Name -join ', ')" }
	if (-not (Test-Path -LiteralPath $memberFile)) { throw "the controller did not write its rqlite member to ${memberFile}" }
	$want = (Get-FileHash -Algorithm SHA256 -LiteralPath $Member).Hash
	$have = (Get-FileHash -Algorithm SHA256 -LiteralPath $memberFile).Hash
	if ($have -ne $want) { throw "the rqlite member in $memberFile has the SHA-256 $have, not the $want of the Payload" }
	$sig = Get-AuthenticodeSignature -FilePath $memberFile
	if ($sig.Status -ne 'Valid') { throw "the rqlite member in $memberFile has the signature status $($sig.Status): $($sig.StatusMessage)" }
	Write-Host "rqlite member: $memberFile has the bytes of the signed Payload ($have) and a valid signature of $($sig.SignerCertificate.Subject)"
}

# The same, and the rqlited.exe process that runs is that file
function Test-Member {
	Test-MemberFile
	$running = @(Get-CimInstance Win32_Process -Filter "Name='rqlited.exe'" | Where-Object { $_.ExecutablePath -eq $memberFile })
	if ($running.Count -ne 1) { throw "expected one rqlited.exe process that runs $memberFile, found $($running.Count)" }
	Write-Host "rqlite member: process $($running[0].ProcessId) runs it"
}

# Delete the rqlite member while the service is stopped. The process that ran it may hold the file
# for a moment after the service reported Stopped.
function Remove-Member {
	$end = (Get-Date).AddSeconds(10)
	while ($true) {
		try {
			Remove-Item -LiteralPath $memberFile -ErrorAction Stop
			break
		} catch {
			if ((Get-Date) -ge $end) { throw "could not delete ${memberFile}: $_" }
			Start-Sleep -Milliseconds 200
		}
	}
	Write-Host "rqlite member: $memberFile deleted while the service is stopped"
}

function Get-ServiceEvents {
	@(Get-WinEvent -LogName Application -FilterXPath "*[System[Provider[@Name='$service']]]" -ErrorAction SilentlyContinue |
		Where-Object { $_.TimeCreated -ge $since } | Sort-Object RecordId)
}

function Show-Diagnostics {
	Write-Host "Application log entries of ${service}:"
	Get-ServiceEvents | ForEach-Object {
		Write-Host ("  {0:u} id {1} level {2}: {3}" -f $_.TimeCreated, $_.Id, $_.Level, (($_.Properties | ForEach-Object { $_.Value }) -join ' | '))
	}
	Get-Service -Name $service -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "service ${service}: $($_.Status)" }
	$log = Join-Path $data 'controller.log'
	if (Test-Path -LiteralPath $log) {
		Write-Host "last lines of ${log}:"
		Get-Content -LiteralPath $log -Tail 60 | ForEach-Object { Write-Host "  $_" }
	}
}

# Who listens on TCP 80 before the controller starts: process 4 (System) is HTTP.sys, and the
# request queues show which HTTP.sys user registered which URL on the port
Get-NetTCPConnection -LocalPort 80 -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
	Write-Host "TCP 80 before the check: $($_.LocalAddress) held by process $($_.OwningProcess) ($((Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName))"
}
& netsh http show servicestate view=requestq | Select-String -Pattern ':80/' -SimpleMatch -Context 12, 0 | ForEach-Object { Write-Host $_ }

# Test-DataDirOwner, Test-Backup and Test-ServiceRefusesDataDir (AUD1-DT-10, #458), Test-FingerprintFile (AUD1-DT-14, #496),
# Test-DataDirChildren (AUD1-DT-18, #503)
. (Join-Path $PSScriptRoot 'controller-hostfiles.ps1')

$hold = $null
try {
	Write-Host (Invoke-Checked $ranz @('controller', 'install', '-data', $data, '-http-listen', ':80'))
	Test-DataDirOwner
	foreach ($p in @($acmePrefix, $redirectPrefix)) {
		$acl = Get-URLReservation $p
		if ($acl -notmatch [regex]::Escape($p) -or $acl -notmatch [regex]::Escape($account)) { throw "install made no URL reservation of $p for ${account}:`n$acl" }
	}
	Write-Host "install reserved both URL prefixes of port 80 for $account"
	# The virtual account, unlike LocalSystem, has no right to the runner's directory of the
	# executable: it gets read and execute there, as every account has in Program Files. It needs
	# nothing for rqlited: the controller writes it under its own data directory (ONE-4, #313).
	& icacls $bin /grant "${account}:(OI)(CI)RX" | Out-Null
	if ($LASTEXITCODE -ne 0) { throw "icacls $bin exited with code $LASTEXITCODE" }

	Start-Service -Name $service
	Wait-Api
	Test-Hardening
	Test-Member
	$status = Invoke-Ranz @('status')
	Write-Host "status: $($status | ConvertTo-Json -Compress -Depth 4)"
	if (-not $status.tlsFingerprint) { throw 'the status names no TLS fingerprint' }
	# The service wrote the TLS fingerprint that it serves to its data directory, and ranz checks a loopback address by
	# it (AUD1-DT-13, #461): every call above went through that check. Where ranz finds no such file it sends no token
	# and says what to give it, -tls-fingerprint takes the place of the file, and a wrong one is refused.
	$fingerprintFile = Join-Path $data 'tls.fingerprint'
	if ((Get-Content -LiteralPath $fingerprintFile -Raw).Trim() -ne $status.tlsFingerprint) { throw "tls.fingerprint does not hold the TLS fingerprint of the status, $($status.tlsFingerprint)" }
	$noFile = Join-Path $work 'no-controller'
	$noFileErr = Join-Path $work 'ranz-no-fingerprint.err'
	& $ranz -server $api -token-file $tokenFile -controller-dir $noFile whoami 2> $noFileErr | Out-Null
	if ($LASTEXITCODE -eq 0 -or (Get-Content -LiteralPath $noFileErr -Raw) -notmatch 'sends no token.*-tls-fingerprint') { throw "ranz called a loopback address with no fingerprint to check it by (exit code $LASTEXITCODE): $(Get-Content -LiteralPath $noFileErr -Raw)" }
	$byFlag = (Invoke-Checked $ranz @('-server', $api, '-token-file', $tokenFile, '-controller-dir', $noFile, '-tls-fingerprint', $status.tlsFingerprint, 'whoami')) | ConvertFrom-Json
	if ($byFlag.name -ne 'admin') { throw "ranz with -tls-fingerprint did not get the admin token: $($byFlag | ConvertTo-Json -Compress)" }
	& $ranz -server $api -token-file $tokenFile -tls-fingerprint ('00' * 32) whoami 2>$null | Out-Null
	if ($LASTEXITCODE -eq 0) { throw 'ranz accepted the certificate of the controller on loopback with a wrong TLS fingerprint' }
	Write-Host 'ranz checks the controller on loopback by the fingerprint in its data directory, or by the flag, and sends no token without one'
	# ranz trusts that file only when no other account can have written it or its folder (AUD1-DT-14, #496)
	Test-FingerprintFile
	if ($status.capabilities.tlsPort -ne 443 -or $status.capabilities.tlsPortFallback) { throw 'the TLS port is not 443 with 443 free' }
	if ($status.capabilities.plainHttp -notmatch 'HTTP\.sys') { throw "port 80 does not run on HTTP.sys: $($status.capabilities.plainHttp)" }
	if ($status.capabilities.plainHttp -notmatch [regex]::Escape($acmePrefix)) { throw "the controller does not hold the ACME path of port 80: $($status.capabilities.plainHttp)" }
	# No licence key is installed: the Personal tier is in force (ADR-0036)
	$licence = Invoke-Ranz @('get', 'licence')
	Write-Host "licence: $($licence | ConvertTo-Json -Compress -Depth 4)"
	if ($licence.tier -ne 'Personal' -or $licence.state -ne 'none' -or $licence.nodes -lt 1) { throw 'without a licence key the licence in force is not the Personal tier' }
	$script:redirectOurs = $status.capabilities.plainHttp -match [regex]::Escape($redirectPrefix)
	if (-not $script:redirectOurs) {
		$log = Get-Content -LiteralPath (Join-Path $data 'controller.log') -Raw
		if ($log -notmatch [regex]::Escape("another HTTP.sys user holds this URL prefix") -or $log -notmatch [regex]::Escape($redirectPrefix)) {
			throw "the controller does not hold $redirectPrefix and logged no warning about it"
		}
		Write-Host "another HTTP.sys user holds $redirectPrefix on this host: the controller shares port 80 with it and keeps the ACME path"
	}

	# RBAC: the first start created the admin token, a call without a token is refused, and the
	# API answers a client on an address of the host that is not loopback, which the controller
	# refused before it had roles; that client checks the certificate by its TLS fingerprint
	$adminSecret = (Get-Content -LiteralPath $tokenFile -Raw).Trim()
	$me = Invoke-Ranz @('whoami')
	if ($me.name -ne 'admin' -or $me.role -ne 'admin') { throw "the token of admin.token is $($me | ConvertTo-Json -Compress), not the admin token" }
	Assert-Refused @('-server', $api, 'status') 401
	$hostAddr = (Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred |
		Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } | Select-Object -First 1).IPAddress
	if (-not $hostAddr) { throw 'the runner has no IPv4 address outside loopback' }
	$hostApi = "https://$hostAddr"
	$remote = (Invoke-Checked $ranz @('-server', $hostApi, '-token-file', $tokenFile, '-tls-fingerprint', $status.tlsFingerprint, 'whoami')) | ConvertFrom-Json
	if ($remote.role -ne 'admin') { throw "the API on $hostApi did not answer the admin token: $($remote | ConvertTo-Json -Compress)" }
	Write-Host "the API on $hostApi (not loopback) answers the admin token: $($remote | ConvertTo-Json -Compress)"
	Assert-Refused @('-server', $hostApi, '-tls-fingerprint', $status.tlsFingerprint, 'whoami') 401
	& $ranz -server $hostApi -token-file $tokenFile -tls-fingerprint ('00' * 32) whoami 2>$null | Out-Null
	if ($LASTEXITCODE -eq 0) { throw "ranz accepted the certificate of $hostApi with a wrong TLS fingerprint" }
	$viewer = Invoke-Ranz @('token', 'create', '-role', 'viewer', 'ci-viewer')
	if ($viewer.role -ne 'viewer' -or $viewer.token -notmatch '^ranz_') { throw "the viewer token is $($viewer | ConvertTo-Json -Compress)" }
	$viewerFile = Join-Path $work 'viewer.token'
	Set-Content -LiteralPath $viewerFile -Value $viewer.token -Encoding ascii

	Test-Redirect 'https://127.0.0.1/api/v1/status'
	$acmeBody = Join-Path $work 'acme.txt'
	$acmeCode = (& curl.exe -s -o $acmeBody -w '%{http_code}' 'http://127.0.0.1/.well-known/acme-challenge/none')
	$acmeText = (Get-Content -LiteralPath $acmeBody -Raw).Trim()
	Write-Host "port 80, ACME path: $acmeCode '$acmeText'"
	if ($acmeCode -ne '404' -or $acmeText -ne '404 page not found') { throw "the ACME path of port 80 is not the controller's (it answered $acmeCode '$acmeText')" }

	$key = Join-Path $work 'node.key'
	$pub = (Invoke-Checked $nodesim @('-key', $key, '-pubkey')).Trim()
	$intent = @{
		resources = @(
			@{ kind = 'VRF'; name = 'corp'; spec = @{ id = 10; ula = 'fd12:3456:789a::/48' } },
			@{ kind = 'Network'; name = 'corp-lan'; spec = @{ vrf = 'corp'; ipv4Pool = '10.10.0.0/24' } },
			@{ kind = 'Node'; name = 'branch-1'; spec = @{ publicKey = $pub; vrfs = @('corp') } }
		)
	}
	$file = Join-Path $work 'intent.json'
	$intent | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $file -Encoding utf8NoBOM
	# The first start made the intent of a first install
	$firstInstall = 'VRF/default,Network/default,Policy/default-allow-all'
	$first = @((Invoke-Ranz @('get', 'resources')).resources)
	if ((($first | ForEach-Object { "$($_.kind)/$($_.name)" }) -join ',') -ne $firstInstall) { throw "the first start made the intent $($first | ConvertTo-Json -Compress -Depth 6)" }
	Write-Host "first start: $($first | ConvertTo-Json -Compress -Depth 6)"
	Assert-Refused @('-server', $api, '-token-file', $viewerFile, 'apply', '-f', $file) 403
	if ((((Invoke-Ranz @('get', 'resources')).resources | ForEach-Object { "$($_.kind)/$($_.name)" }) -join ',') -ne $firstInstall) { throw "the refused apply of the viewer changed the intent" }
	$applied = Invoke-Ranz @('apply', '-f', $file)
	Write-Host "applied: $($applied | ConvertTo-Json -Compress)"
	if (@($applied.nodes).Count -ne 1 -or $applied.nodes[0].name -ne 'branch-1' -or $applied.nodes[0].generation -ne 1) {
		throw "the apply did not give branch-1 generation 1"
	}
	Write-Host "ranz-nodesim received: $(Test-Node $control $status.publicKey)"
	Wait-Acked 'branch-1' 1 | Out-Null

	Restart-Service -Name $service
	Wait-Api
	$names = (Invoke-Ranz @('get', 'resources')).resources | ForEach-Object { "$($_.kind)/$($_.name)" }
	if (($names -join ',') -ne 'VRF/corp,VRF/default,Network/corp-lan,Network/default,Node/branch-1,Policy/default-allow-all') { throw "the intent after the restart is $($names -join ', ')" }
	$node = Wait-Acked 'branch-1' 1
	if ($node.generation -ne 1) { throw "branch-1 is at generation $($node.generation) after the restart, not 1" }
	$after = Invoke-Ranz @('status')
	if ($after.publicKey -ne $status.publicKey) { throw "the Noise static key changed across the restart: $($status.publicKey), then $($after.publicKey)" }
	if ($after.tlsFingerprint -ne $status.tlsFingerprint) { throw "the TLS key changed across the restart: $($status.tlsFingerprint), then $($after.tlsFingerprint)" }
	if ((Get-Content -LiteralPath $tokenFile -Raw).Trim() -ne $adminSecret) { throw 'the restart wrote a new admin token' }
	$viewerAfter = (Invoke-Checked $ranz @('-server', $api, '-token-file', $viewerFile, 'whoami')) | ConvertFrom-Json
	if ($viewerAfter.role -ne 'viewer') { throw "the viewer token after the restart is $($viewerAfter | ConvertTo-Json -Compress)" }
	Test-Node $control $status.publicKey | Out-Null
	Write-Host 'after the restart: the same intent, generation, Noise static key, TLS key and tokens, and the node connects with the key it knew'

	# Hold TCP 443 (IPv4 and IPv6) and start again: the controller falls back to 5555. The rqlite
	# member is deleted from disk while the service is stopped (ONE-4, #313): the next start must
	# write it again, after the check of its hash and its signature, and the store is as it was.
	Stop-Service -Name $service
	Remove-Member
	$hold = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::IPv6Any, 443)
	$hold.Server.DualMode = $true
	$hold.Start()
	Start-Service -Name $service
	$api = 'https://127.0.0.1:5555'
	Wait-Api
	Test-Member
	$names = (Invoke-Ranz @('get', 'resources')).resources | ForEach-Object { "$($_.kind)/$($_.name)" }
	if (($names -join ',') -ne 'VRF/corp,VRF/default,Network/corp-lan,Network/default,Node/branch-1,Policy/default-allow-all') { throw "the intent after the member was written again is $($names -join ', ')" }
	Write-Host 'the member was written again after it was deleted while the service was stopped, and the intent is as it was'
	$fallback = Invoke-Ranz @('status')
	Write-Host "status with 443 taken: $($fallback | ConvertTo-Json -Compress -Depth 4)"
	if ($fallback.capabilities.tlsPort -ne 5555 -or -not $fallback.capabilities.tlsPortFallback) { throw 'with 443 taken the controller does not report the fallback to 5555' }
	Test-Node '127.0.0.1:5555' $status.publicKey | Out-Null
	Test-Redirect 'https://127.0.0.1:5555/api/v1/status'
	$hold.Stop()
	$hold = $null

	# 443 is free again, and the controller keeps 5555 (ADR-0020: the fallback happens once)
	Restart-Service -Name $service
	Wait-Api
	$kept = Invoke-Ranz @('status')
	if ($kept.capabilities.tlsPort -ne 5555 -or -not $kept.capabilities.tlsPortFallback) { throw 'with 443 free again the controller left its fallback' }
	Write-Host 'the TLS port fell back to 5555 with 443 taken, and stays there with 443 free again'

	# Revisions: the first start is revision 1 and the apply above revision 2, also after the
	# restarts
	$revisions = @((Invoke-Ranz @('get', 'revisions')).revisions)
	if ($revisions.Count -ne 2 -or $revisions[0].operation -ne 'first-start' -or $revisions[1].operation -ne 'apply') { throw "the revisions are not the first start and the one apply: $($revisions | ConvertTo-Json -Compress -Depth 4)" }
	$intent.resources[0].spec.mtu = 1400
	$mtuFile = Join-Path $work 'intent-mtu.json'
	$intent | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $mtuFile -Encoding utf8NoBOM
	$trial = Invoke-Ranz @('apply', '-f', $mtuFile, '-confirm', '5s')
	if ($trial.revision -ne 3 -or -not $trial.confirmBy) { throw "apply -confirm did not make revision 3 with a deadline: $($trial | ConvertTo-Json -Compress)" }
	$diff = Invoke-Ranz @('diff', '2', '3')
	$changes = @($diff.changes)
	if ($changes.Count -ne 1 -or $changes[0].action -ne 'changed' -or $changes[0].kind -ne 'VRF' -or (@($changes[0].fields) -join ',') -ne 'mtu') {
		throw "ranz diff 2 3 is not the MTU change of VRF corp: $($diff | ConvertTo-Json -Compress -Depth 6)"
	}
	# Nobody confirms revision 3, so the service rolls it back by itself after 5 s
	$end = (Get-Date).AddSeconds($waitSeconds)
	while (@((Invoke-Ranz @('get', 'events')).events).Count -eq 0) {
		if ((Get-Date) -ge $end) { throw "no automatic rollback within $waitSeconds s of the unconfirmed apply" }
		Start-Sleep -Milliseconds 500
	}
	$events = @((Invoke-Ranz @('get', 'events')).events)
	if ($events.Count -ne 1 -or $events[0].type -ne 'automatic-rollback' -or $events[0].revision -ne 4 -or $events[0].reverts -ne 3) {
		throw "the events are not the automatic rollback of revision 3: $($events | ConvertTo-Json -Compress)"
	}
	Write-Host "event: $($events[0].message)"
	# A rollback changes the intent, so it needs operator: the viewer token is refused
	Assert-Refused @('-server', $api, '-token-file', $viewerFile, 'rollback', '3') 403
	$back = Invoke-Ranz @('rollback', '3')
	if ($back.revision -ne 5) { throw "ranz rollback 3 made revision $($back.revision), not 5" }
	$vrf = (Invoke-Ranz @('get', 'resources')).resources | Where-Object { $_.kind -eq 'VRF' -and $_.name -eq 'corp' }
	if ($vrf.spec.mtu -ne 1400) { throw "after ranz rollback 3 the MTU of corp is $($vrf.spec.mtu), not the 1400 of revision 3" }
	$confirmApply = Invoke-Ranz @('apply', '-f', $file, '-confirm', '60s')
	$confirmed = Invoke-Ranz @('confirm', "$($confirmApply.revision)")
	if ($confirmed.confirm.state -ne 'confirmed') { throw "ranz confirm $($confirmApply.revision) answered $($confirmed | ConvertTo-Json -Compress -Depth 4)" }
	$operations = ((Invoke-Ranz @('get', 'revisions')).revisions | ForEach-Object { $_.operation }) -join ','
	if ($operations -ne 'first-start,apply,apply,automatic-rollback,rollback,apply') { throw "the revisions are $operations" }
	Write-Host "revisions: $operations; the unconfirmed apply came back by itself with an event, the confirmed one stays"

	# Offline recovery of the admin access: nobody has admin.token any more, and reset-admin, run
	# by the runner's elevated account, makes a new admin token in the store of the running service
	Remove-Item -LiteralPath $tokenFile
	$reset = Invoke-ResetAdmin
	if ($reset.role -ne 'admin' -or $reset.name -notmatch '^admin-' -or $reset.token -notmatch '^ranz_') { throw "reset-admin printed $($reset | ConvertTo-Json -Compress)" }
	if ((Get-Content -LiteralPath $tokenFile -Raw).Trim() -ne $reset.token) { throw 'reset-admin did not write the secret it printed to admin.token' }
	$me = Invoke-Ranz @('whoami')
	if ($me.name -ne $reset.name -or $me.role -ne 'admin') { throw "the token of the new admin.token is $($me | ConvertTo-Json -Compress), not $($reset.name)" }
	$names = ((Invoke-Ranz @('token', 'list')).tokens | ForEach-Object { $_.name }) -join ','
	Write-Host "reset-admin with the service running: $($reset.name) answers as admin; the tokens are $names"
	# The same with the service stopped: reset-admin runs the service's rqlited on its data itself.
	# With the member deleted too (ONE-4, #313), reset-admin writes it again, after the check of its
	# hash and its signature, and runs it.
	Stop-Service -Name $service
	Remove-Item -LiteralPath $tokenFile
	Remove-Member
	$offline = Invoke-ResetAdmin
	Test-MemberFile
	if ($offline.role -ne 'admin' -or $offline.name -eq $reset.name -or $offline.token -notmatch '^ranz_') { throw "reset-admin with the service stopped printed $($offline | ConvertTo-Json -Compress)" }
	if ((Get-Content -LiteralPath $tokenFile -Raw).Trim() -ne $offline.token) { throw 'reset-admin with the service stopped did not write the secret it printed to admin.token' }
	Start-Service -Name $service
	Wait-Api
	$me = Invoke-Ranz @('whoami')
	if ($me.name -ne $offline.name -or $me.role -ne 'admin') { throw "after reset-admin with the service stopped, admin.token is $($me | ConvertTo-Json -Compress), not $($offline.name)" }
	$viewerAfter = (Invoke-Checked $ranz @('-server', $api, '-token-file', $viewerFile, 'whoami')) | ConvertFrom-Json
	if ($viewerAfter.role -ne 'viewer') { throw "after reset-admin the viewer token is $($viewerAfter | ConvertTo-Json -Compress)" }
	Write-Host "reset-admin with the service stopped: $($offline.name) answers as admin once the service runs again, and the other tokens stay"

	# The admin source allowlist (SDN-39, #232). The service reads the list once in 2 s, so each
	# change gets a wait. With the list set to documentation addresses, the runner's own address,
	# which is not loopback, is refused with 403 before its token is looked at, and the refusal is
	# an event; loopback still passes, and with the list removed the address passes again.
	$hostApi = "https://${hostAddr}:5555"
	$viaHost = @('-server', $hostApi, '-token-file', $tokenFile, '-tls-fingerprint', $status.tlsFingerprint)
	$listed = Invoke-Ranz @('admin-sources', 'set', '192.0.2.0/24')
	if (@($listed.prefixes).Count -ne 1 -or $listed.prefixes[0] -ne '192.0.2.0/24') { throw "ranz admin-sources set printed $($listed | ConvertTo-Json -Compress)" }
	Start-Sleep -Seconds 4
	Assert-Refused ($viaHost + @('whoami')) 403
	$me = Invoke-Ranz @('whoami')
	if ($me.role -ne 'admin') { throw "loopback is not served while the allowlist holds documentation addresses: $($me | ConvertTo-Json -Compress)" }
	$refusals = @((Invoke-Ranz @('get', 'events')).events | Where-Object { $_.type -eq 'admin-access-refused' })
	if ($refusals.Count -lt 1) { throw "the refusal of the address of the runner, ${hostAddr}, is no event" }
	Write-Host "event: $($refusals[0].message)"
	$cleared = Invoke-Ranz @('admin-sources', 'clear')
	if (@($cleared.prefixes).Count -ne 0) { throw "ranz admin-sources clear printed $($cleared | ConvertTo-Json -Compress)" }
	Start-Sleep -Seconds 4
	$remote = (Invoke-Checked $ranz ($viaHost + @('whoami'))) | ConvertFrom-Json
	if ($remote.role -ne 'admin') { throw "the address of the runner is not served with the allowlist removed: $($remote | ConvertTo-Json -Compress)" }
	Write-Host "admin source allowlist: ${hostAddr} is refused while the list holds documentation addresses only, loopback passes, and the address passes again once the list is removed"

	Test-Backup

	Stop-Service -Name $service
	$started = @(Get-ServiceEvents | Where-Object { $_.Id -eq 1 })
	$stopped = @(Get-ServiceEvents | Where-Object { $_.Id -eq 2 })
	$failed = @(Get-ServiceEvents | Where-Object { $_.Id -eq 3 })
	$warned = @(Get-ServiceEvents | Where-Object { $_.Id -eq 4 })
	$resets = @(Get-ServiceEvents | Where-Object { $_.Id -eq 5 })
	if ($started.Count -ne 5 -or $stopped.Count -ne 5) { throw "expected 5 started and 5 stopped entries, found $($started.Count) and $($stopped.Count)" }
	if ($warned.Count -ne 3) { throw "expected 3 fallback warnings (event ID 4), found $($warned.Count)" }
	if ($resets.Count -ne 2) { throw "expected 2 reset-admin warnings (event ID 5), found $($resets.Count)" }
	if ($failed.Count -gt 0) { throw "$service wrote $($failed.Count) failure entries (event ID 3)" }
	Write-Host "Application log: $($resets[0].Message)"

	Test-ServiceRefusesDataDir
	Test-DataDirChildren

	Write-Host (Invoke-Checked $ranz @('controller', 'uninstall'))
	foreach ($p in @($acmePrefix, $redirectPrefix)) {
		$acl = Get-URLReservation $p
		if ($acl -match [regex]::Escape($p)) { throw "uninstall left the URL reservation of ${p}:`n$acl" }
	}
	Write-Host 'uninstall removed the URL reservations'
} catch {
	Show-Diagnostics
	throw
} finally {
	if ($hold) { $hold.Stop() }
	# Leave no service behind. sc.exe fails for a service that is already gone, which is not an
	# error of this step, and the exit code it leaves must not become the step's.
	if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
		& sc.exe stop $service | Out-Null
		& sc.exe delete $service | Out-Null
	}
	$global:LASTEXITCODE = 0
}

Show-Diagnostics
Write-Host 'ok'
