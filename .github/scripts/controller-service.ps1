param([string] $BinDir = 'build\controller')

$ErrorActionPreference = 'Stop'

# ranz-controller as a Windows service (SDN-2, #178). Installed with rqlited as its sidecar and
# with plain HTTP on port 80, the service must:
# - reserve the URL prefixes of port 80 in HTTP.sys at install, and remove them at uninstall;
# - serve the API and the control stream on TCP 443, told apart by ALPN;
# - serve port 80 through HTTP.sys, which the runner's system holds already: its own answer on
#   the ACME HTTP-01 path, and a 301 to HTTPS on the TLS port for the rest of the port unless
#   another HTTP.sys user held that catch-all first (on the runner one does), nothing else;
# - report the Personal tier through `ranz get licence` while no licence key is installed;
# - take an intent from `ranz apply`, push generation 1 to a simulated node (ranz-nodesim) and
#   record its acknowledgement;
# - keep the intent, the acknowledged generation and its keys across a restart of the service:
#   the same Noise static key (a node with the key it had before still connects) and the same TLS
#   key (the same fingerprint) from the key storage provider;
# - fall back to TCP 5555 when 443 is taken, warn about it in the Application log, report it in
#   its capabilities, and keep 5555 after 443 is free again (ADR-0020);
# - write its starts and stops to the Application log (event IDs 1 and 2 of
#   cmd/ranz-controller/service_windows.go), a warning for each start on the fallback (4), and no
#   failure entry (3).

$bin = (Resolve-Path $BinDir).Path
$controller = Join-Path $bin 'ranz-controller.exe'
$ranz = Join-Path $bin 'ranz.exe'
$nodesim = Join-Path $bin 'ranz-nodesim.exe'

# serviceName of cmd/ranz-controller, its TLS port (the default -listen, and the fallback), and
# the prefixes that port.PlainPrefixes makes of -http-listen :80
$service = 'ranz-controller'
$api = 'https://127.0.0.1'
$control = '127.0.0.1:443'
$acmePrefix = 'http://+:80/.well-known/acme-challenge/'
$redirectPrefix = 'http://*:80/'

$data = Join-Path $env:RUNNER_TEMP 'ranz-controller-data'
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

# One ranz call, its JSON answer as an object
function Invoke-Ranz([string[]] $argv) {
	return (Invoke-Checked $ranz (@('-server', $api) + $argv)) | ConvertFrom-Json
}

function Wait-Api {
	$end = (Get-Date).AddSeconds($waitSeconds)
	while ($true) {
		& $ranz -server $api status 2>$null | Out-Null
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

$hold = $null
try {
	Write-Host (Invoke-Checked $controller @('install', '-data', $data, '-rqlited', $env:RQLITED, '-http-listen', ':80'))
	foreach ($p in @($acmePrefix, $redirectPrefix)) {
		$acl = Get-URLReservation $p
		if ($acl -notmatch [regex]::Escape($p) -or $acl -notmatch 'SYSTEM') { throw "install made no URL reservation of $p for SYSTEM:`n$acl" }
	}
	Write-Host 'install reserved both URL prefixes of port 80 for SYSTEM'

	Start-Service -Name $service
	Wait-Api
	$status = Invoke-Ranz @('status')
	Write-Host "status: $($status | ConvertTo-Json -Compress -Depth 4)"
	if (-not $status.tlsFingerprint) { throw 'the status names no TLS fingerprint' }
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
	if (($names -join ',') -ne 'VRF/corp,Network/corp-lan,Node/branch-1') { throw "the intent after the restart is $($names -join ', ')" }
	$node = Wait-Acked 'branch-1' 1
	if ($node.generation -ne 1) { throw "branch-1 is at generation $($node.generation) after the restart, not 1" }
	$after = Invoke-Ranz @('status')
	if ($after.publicKey -ne $status.publicKey) { throw "the Noise static key changed across the restart: $($status.publicKey), then $($after.publicKey)" }
	if ($after.tlsFingerprint -ne $status.tlsFingerprint) { throw "the TLS key changed across the restart: $($status.tlsFingerprint), then $($after.tlsFingerprint)" }
	Test-Node $control $status.publicKey | Out-Null
	Write-Host 'after the restart: the same intent, generation, Noise static key and TLS key, and the node connects with the key it knew'

	# Hold TCP 443 (IPv4 and IPv6) and start again: the controller falls back to 5555
	Stop-Service -Name $service
	$hold = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::IPv6Any, 443)
	$hold.Server.DualMode = $true
	$hold.Start()
	Start-Service -Name $service
	$api = 'https://127.0.0.1:5555'
	Wait-Api
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

	Stop-Service -Name $service
	$started = @(Get-ServiceEvents | Where-Object { $_.Id -eq 1 })
	$stopped = @(Get-ServiceEvents | Where-Object { $_.Id -eq 2 })
	$failed = @(Get-ServiceEvents | Where-Object { $_.Id -eq 3 })
	$warned = @(Get-ServiceEvents | Where-Object { $_.Id -eq 4 })
	if ($started.Count -ne 4 -or $stopped.Count -ne 4) { throw "expected 4 started and 4 stopped entries, found $($started.Count) and $($stopped.Count)" }
	if ($warned.Count -ne 2) { throw "expected 2 fallback warnings (event ID 4), found $($warned.Count)" }
	if ($failed.Count -gt 0) { throw "$service wrote $($failed.Count) failure entries (event ID 3)" }

	Write-Host (Invoke-Checked $controller @('uninstall'))
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
