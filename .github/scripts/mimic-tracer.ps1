param([string] $BuildDir = 'build')

$ErrorActionPreference = 'Stop'

# The mimic tracer (CORE-P2-7, #424; SDN-94, #423; ADR-0023), run by the build job of windows.yml on x64 and arm64 after the
# mimic transport: a mimic server and its client that the operator declares in the Intent of a real Controller, and nothing
# typed on a Node. A `ranz controller` with rqlited as its sidecar, on test ports, and three nodes of the new core in vpntest
# (mimictrace, src/vpntest/mimictracetest.c), with ranz.exe of the build next to vpntest.exe, which each node starts as its
# mimicry sidecar (`ranz mimic`). The Intent holds the Node mimic-server, with a mimic endpoint, the Node mimic-client and
# the Listener mimic-edge of mimic-server, whose certificate is one of the LocalMachine\My store that this script makes and
# whose mimic section names the address of the sidecar. vpntest and this script take turns by files in the folder of the
# script:
# - vpntest writes "up" once mimic-server made the key of its mimic server and reported it, mimic-client got its link and
#   its Noise session came up over the mimic transport with the same binding at both ends, and a link with a wrong short id
#   was spliced to the decoy: the file holds the public key of the server. The API must show that key as the one that the
#   Node reported, and the link of mimic-client to the address of the section. The script then applies the Intent with
#   another address and writes "changed";
# - vpntest writes "restarted" once the sidecars restarted with the new address and the server, restarted, reported the same
#   key: the API must still show that key, and the link to the new address. The script then applies the Intent without the
#   mimic section and writes "removed";
# - vpntest writes "gone" once the sidecars stopped and the settings and the key were gone: the API must show that the Node
#   reports no key and that no Node has a link. The script then stops the controller and writes "stopped", and vpntest looks
#   for the private key in the files of this folder, which hold the store and the log of the controller.
# vpntest must print "MIMICTRACE TEST OK" and "NO MEMORY LEAKS".

$bin = (Resolve-Path $BuildDir).Path
$ranz = Join-Path $bin 'ranz.exe'
$vpntest = Join-Path $bin 'vpntest.exe'

$work = Join-Path $env:RUNNER_TEMP 'mimic-tracer'
if (Test-Path -LiteralPath $work) { Remove-Item -Recurse -Force -LiteralPath $work }
$data = Join-Path $work 'data'
New-Item -ItemType Directory -Force -Path $work | Out-Null
# adminTokenFile of controller: the secret of the admin token of the first start
$tokenFile = Join-Path $data 'admin.token'
# Toward a loopback address ranz checks the TLS fingerprint that the controller writes to this directory (AUD1-DT-13, #461)
$env:RANZ_CONTROLLER_DIR = $data
$controllerOut = Join-Path $work 'controller.out'
$controllerErr = Join-Path $work 'controller.err'
$traceOut = Join-Path $work 'vpntest.out'
$traceErr = Join-Path $work 'vpntest.err'

# Test ports, never 443: the TLS port of the controller and its rqlited, the front door and QUIC of the Listener, and the two
# addresses of the mimic server (MIMICTRACE_FIRST and MIMICTRACE_SECOND of mimictracetest.c)
$tls = '127.0.0.1:39843'
$api = "https://$tls"
$rqliteHttp = '127.0.0.1:39801'
$rqliteRaft = '127.0.0.1:39802'
$frontDoor = 39844
$first = '127.0.0.1:39845'
$second = '127.0.0.1:39846'
$serverName = 'decoy.test'

# The static keys of mimic-server and mimic-client in mimictracetest.c: the X25519 public keys of the scalars 1 to 32 and 33 to
# 64, the keys of the controller conformance tests
$serverKey = 'B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw='
$clientKey = 'WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns='

# How long the controller may take to serve, and vpntest to reach its next file (s)
$waitSeconds = 300

if (-not $env:RQLITED) { throw 'RQLITED is not set: the step "Install rqlited for the default VRF tracer" did not run, as a step before it failed' }

# One ranz call with the admin token, its JSON answer as an object
function Invoke-Ranz([string[]] $argv) {
	$out = & $ranz (@('-server', $api, '-token-file', $tokenFile) + $argv)
	if ($LASTEXITCODE -ne 0) { throw "ranz $($argv -join ' ') exited with code $LASTEXITCODE" }
	return ($out -join "`n") | ConvertFrom-Json
}

# What the controller explains of the Listener mimic-edge: its mimic section, the key that its Node reported and the links
function Get-Listener {
	$out = & $ranz explain -server $api -token-file $tokenFile -o json -listener mimic-edge
	if ($LASTEXITCODE -ne 0) { throw "ranz explain -listener mimic-edge exited with code $LASTEXITCODE" }
	return ($out -join "`n") | ConvertFrom-Json
}

# Wait until the explanation of the Listener passes the check, and return it
function Wait-Listener([scriptblock] $check, [string] $what) {
	$end = (Get-Date).AddSeconds(60)
	while ($true) {
		$l = Get-Listener
		if (& $check $l) {
			Write-Host "the controller explains the Listener mimic-edge: $($l | ConvertTo-Json -Compress -Depth 6)"
			return $l
		}
		if ((Get-Date) -ge $end) { throw "the controller does not explain that ${what}: $($l | ConvertTo-Json -Compress -Depth 6)" }
		Start-Sleep -Milliseconds 500
	}
}

# Apply the Intent of the two Nodes and of the Listener mimic-edge, with the mimic server at $address, or with none for ''
function Set-Intent([string] $name, [string] $address) {
	$server = @{ publicKey = $serverKey }
	$listener = [ordered]@{ node = 'mimic-server'; port = $frontDoor; quicPort = $frontDoor; certificate = @{ ksp = $cert.Thumbprint } }
	if ($address) {
		# The endpoint that the clients dial, and the section of the server role of the sidecar, with a decoy of its own whose
		# certificate stands for a real one in a test
		$server.endpoints = @(@{ transport = 'mimic'; address = $address })
		$listener.mimic = [ordered]@{ listen = $address; serverNames = @($serverName); decoy = @{ selfSigned = $true } }
	}
	$intent = @{ resources = @(
		@{ kind = 'Node'; name = 'mimic-server'; spec = $server },
		@{ kind = 'Node'; name = 'mimic-client'; spec = @{ publicKey = $clientKey } },
		@{ kind = 'Listener'; name = 'mimic-edge'; spec = $listener }) }
	$file = Join-Path $work "$name.json"
	$intent | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $file -Encoding utf8NoBOM
	Write-Host "the Intent ${name}: $(Get-Content -LiteralPath $file -Raw)"
	$applied = Invoke-Ranz @('apply', '-f', $file)
	Write-Host "applied: $($applied | ConvertTo-Json -Compress -Depth 4)"
}

# Wait until vpntest wrote the file $name into the folder, and return its path
function Wait-File([string] $name) {
	$path = Join-Path $work $name
	$end = (Get-Date).AddSeconds($waitSeconds)
	while (-not (Test-Path -LiteralPath $path)) {
		if ($trace.HasExited) { throw "vpntest mimictrace exited with code $($trace.ExitCode) before it wrote $name" }
		if ((Get-Date) -ge $end) { throw "vpntest mimictrace did not write $name within $waitSeconds s" }
		Start-Sleep -Milliseconds 500
	}
	return $path
}

function Write-File([string] $name) {
	Set-Content -LiteralPath (Join-Path $work $name) -Value 'ok' -Encoding ascii
}

function Show-Output([string] $what, [string] $file, [int] $tail) {
	if (Test-Path -LiteralPath $file) {
		Write-Host "--- ${what}:"
		Get-Content -LiteralPath $file -Tail $tail -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $_" }
	}
}

# Stop the controller and its rqlited
function Stop-Controller {
	if ($ctl -and -not $ctl.HasExited) { Stop-Process -Id $ctl.Id -Force -ErrorAction SilentlyContinue; $ctl.WaitForExit() }
	Get-Process -Name 'rqlited' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

$ctl = $null
$trace = $null
$cert = $null
try {
	$ctl = Start-Process -FilePath $ranz -PassThru -NoNewWindow -RedirectStandardOutput $controllerOut -RedirectStandardError $controllerErr -ArgumentList @(
		'controller', '-data', $data, '-listen', $tls, '-name', 'mimic', '-rqlited', $env:RQLITED, '-rqlite', "http://$rqliteHttp", '-rqlite-raft', $rqliteRaft)
	# The handle keeps the exit code of the process for ExitCode
	$null = $ctl.Handle

	# The first start writes the admin token, then the API answers it
	$end = (Get-Date).AddSeconds($waitSeconds)
	while ($true) {
		if ($ctl.HasExited) { throw "ranz controller exited with code $($ctl.ExitCode) before it served" }
		if ((Test-Path -LiteralPath $tokenFile) -and ((Get-Content -LiteralPath $tokenFile -Raw) -match "`n$")) {
			& $ranz -server $api -token-file $tokenFile status 2>$null | Out-Null
			if ($LASTEXITCODE -eq 0) { break }
		}
		if ((Get-Date) -ge $end) { throw "ranz controller did not serve on $api within $waitSeconds s" }
		Start-Sleep -Milliseconds 500
	}
	$status = Invoke-Ranz @('status')
	Write-Host "controller: publicKey $($status.publicKey)"

	# The certificate of the front door of the Listener, its key in the software key storage provider of the machine
	$cert = New-SelfSignedCertificate -Subject 'CN=mimic-edge' -DnsName 'localhost' -CertStoreLocation Cert:\LocalMachine\My -KeyAlgorithm ECDSA_nistP256 `
		-Provider 'Microsoft Software Key Storage Provider' -NotAfter (Get-Date).AddDays(1)

	Set-Intent 'mimic-first' $first

	# The nodes join and run the mimic server and its client
	$trace = Start-Process -FilePath $vpntest -PassThru -NoNewWindow -RedirectStandardOutput $traceOut -RedirectStandardError $traceErr -ArgumentList @(
		'mimictrace', $tls, $status.publicKey, $work)
	$null = $trace.Handle

	# up: the key that the Node made and reported is the one that the controller explains, and mimic-client has its link
	$up = Wait-File 'up'
	$key = "$(Get-Content -LiteralPath $up -Raw)".Trim()
	if ($key -notmatch '^[0-9a-f]{64}$') { throw "the file up holds no public key: '$key'" }
	Write-Host "vpntest: mimic-server made the key of its mimic server, whose public key is $key"
	$null = Wait-Listener {
		param($l)
		$links = @($l.links | Where-Object { $_ })
		$l.keyReported -and $l.publicKey -eq $key -and $l.mimic.listen -eq $first -and $links.Count -eq 1 -and $links[0].node -eq 'mimic-client' -and
			$links[0].address -eq $first -and $links[0].serverName -eq $serverName
	} "mimic-server reported the key $key and mimic-client has a link to $first"

	# changed: the mimic server at another address
	Set-Intent 'mimic-second' $second
	Write-File 'changed'

	# restarted: the restarted server reported the same key
	$null = Wait-File 'restarted'
	$null = Wait-Listener {
		param($l)
		$links = @($l.links | Where-Object { $_ })
		$l.keyReported -and $l.publicKey -eq $key -and $l.mimic.listen -eq $second -and $links.Count -eq 1 -and $links[0].address -eq $second
	} "mimic-server reported the same key $key after its restart and the address $second, and mimic-client has a link to it"

	# removed: no mimic section
	Set-Intent 'mimic-none' ''
	Write-File 'removed'

	# gone: the Node reported that it has no key, and no Node has a link
	$null = Wait-File 'gone'
	$null = Wait-Listener {
		param($l)
		-not $l.mimic -and -not $l.keyReported -and @($l.links | Where-Object { $_ }).Count -eq 0
	} 'the Listener has no mimic section, mimic-server reports no key and no Node has a link'

	# stopped: vpntest looks for the private key in what the controller kept
	Stop-Controller
	Write-Host 'the controller and its rqlited stopped'
	Write-File 'stopped'

	if (-not $trace.WaitForExit($waitSeconds * 1000)) { throw "vpntest mimictrace did not finish within $waitSeconds s of the stop of the controller" }
	$out = Get-Content -LiteralPath $traceOut -Raw
	Write-Host $out
	if ($out -notmatch '(?m)^MIMICTRACE TEST OK\r?$') { throw 'vpntest mimictrace failed' }
	if ($out -notmatch 'NO MEMORY LEAKS') { throw 'vpntest mimictrace leaked memory' }
	Write-Host 'ok'
} catch {
	if ($trace -and -not $trace.HasExited) { Stop-Process -Id $trace.Id -Force -ErrorAction SilentlyContinue; $trace.WaitForExit() }
	Stop-Controller
	Show-Output 'vpntest mimictrace' $traceOut 300
	Show-Output 'vpntest mimictrace (stderr)' $traceErr 50
	Show-Output 'ranz controller' $controllerErr 150
	throw
} finally {
	if ($trace -and -not $trace.HasExited) { Stop-Process -Id $trace.Id -Force -ErrorAction SilentlyContinue; $trace.WaitForExit() }
	Stop-Controller
	if ($cert) { Remove-Item -LiteralPath "Cert:\LocalMachine\My\$($cert.Thumbprint)" -DeleteKey -ErrorAction SilentlyContinue }
}
