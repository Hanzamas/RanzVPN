param(
	[string] $BuildDir = 'build'
)

$ErrorActionPreference = 'Stop'

# The WireGuard Device tracer (SDN-80, #375): the multi-node check of a WireGuard Device on one runner (seam 3 of #45 as
# ADR-0002 amended it on 2026-10-21: several node processes on one runner stand in for several hosts). A `ranz controller`
# with rqlited as its sidecar, on test ports; the two nodes of vpntest devicetrace (src/vpntest/devicetrace.c): gw, the
# gateway, with a Wintun adapter and the WireGuard interface of WireGuardNT, and host, whose fake host is the overlay host;
# and ranz-wgpeer (controller/cmd/ranz-wgpeer), a stock WireGuard client on wireguard-go and its netstack that holds the
# private key of the Device. The script checks that
# - the gateway reports the Capability wireguard with the key of its WireGuard interface, and the configuration that the
#   controller renders for the Device names that key, the DNS name of the gateway and its port;
# - the gateway listens on UDP 51820, the default, and the client completes its handshake with it, pings host and opens a
#   TCP connection to host, through which a line goes and comes back;
# - ranz get devices shows the last handshake and the traffic of the Device that the gateway reported;
# - a Policy rule that denies the Device blocks the same ping once the gateway acknowledged the rule, and the policy of
#   the gateway counts the drops;
# - with the rule gone and wireguard.port of the gateway set to another port, the gateway listens there and no longer on
#   51820, the configuration names the new port, and the client reaches host through it.
# The output of the processes is shown when a check fails.

$bin = (Resolve-Path $BuildDir).Path
$ranz = Join-Path $bin 'ranz.exe'
$vpntest = Join-Path $bin 'vpntest.exe'
$wgpeer = Join-Path $bin 'ranz-wgpeer.exe'

$work = Join-Path $env:RUNNER_TEMP 'device-tracer'
$data = Join-Path $work 'data'
New-Item -ItemType Directory -Force -Path $work | Out-Null
# adminTokenFile of controller: the secret of the admin token of the first start
$tokenFile = Join-Path $data 'admin.token'
$controllerOut = Join-Path $work 'controller.out'
$controllerErr = Join-Path $work 'controller.err'
$traceOut = Join-Path $work 'vpntest.out'
$traceErr = Join-Path $work 'vpntest.err'
$ready = Join-Path $work 'ready'
$stop = Join-Path $work 'stop'
$deviceKey = Join-Path $work 'phone.key'
$deviceConfig = Join-Path $work 'phone.conf'

# Test ports, never 443 and not the ones of sdn-tracer.ps1: the TLS port of the controller and its rqlited
$tls = '127.0.0.1:39543'
$api = "https://$tls"
$rqliteHttp = '127.0.0.1:39501'
$rqliteRaft = '127.0.0.1:39502'

# The static keys of gw and host in devicetrace.c: the X25519 public keys of the scalars 1 to 32 and 33 to 64
$gwKey = 'B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw='
$hostKey = 'WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns='
# The DNS name of the gateway that the configuration of the Device names, the default port and the one set later
$endpoint = 'localhost'
$defaultPort = 51820
$otherPort = 51821
# The port of the TCP connection to the fake host, which echoes on any port
$tcpPort = 7

# How long the controller may take to serve, the nodes to join and a state to be acknowledged (s)
$waitSeconds = 180

# One ranz call with the admin token, its JSON answer as an object
function Invoke-Ranz([string[]] $argv) {
	$out = & $ranz (@('-server', $api, '-token-file', $tokenFile) + $argv)
	if ($LASTEXITCODE -ne 0) { throw "ranz $($argv -join ' ') exited with code $LASTEXITCODE" }
	return ($out -join "`n") | ConvertFrom-Json
}

# Apply the resources of an intent document
function Invoke-Apply([string] $name, [object[]] $resources) {
	$file = Join-Path $work "$name.json"
	@{ resources = $resources } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $file -Encoding utf8NoBOM
	$applied = Invoke-Ranz @('apply', '-f', $file)
	Write-Host "applied ${name}: $($applied | ConvertTo-Json -Compress -Depth 4)"
}

# The text of a file that a process may still write to
function Read-Shared([string] $path) {
	if (-not (Test-Path -LiteralPath $path)) { return '' }
	$stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
	try { return (New-Object System.IO.StreamReader($stream)).ReadToEnd() } finally { $stream.Dispose() }
}

function Show-Output([string] $what, [string] $file, [int] $tail) {
	if (Test-Path -LiteralPath $file) {
		Write-Host "--- ${what}:"
		(Read-Shared $file) -split "`r?`n" | Select-Object -Last $tail | ForEach-Object { Write-Host "  $_" }
	}
}

# The state of the node name that the API shows, once it is connected and acknowledged a Generation above after
function Wait-Acknowledged([string] $name, [long] $after) {
	$end = (Get-Date).AddSeconds($waitSeconds)
	while ($true) {
		$s = @((Invoke-Ranz @('get', 'nodes')).nodes | Where-Object { $_.name -eq $name })
		if ($s.Count -eq 1 -and $s[0].connected -and $s[0].generation -gt $after -and $s[0].ackedGeneration -eq $s[0].generation) { return $s[0] }
		if ($trace.HasExited) { throw "vpntest devicetrace exited with code $($trace.ExitCode)" }
		if ((Get-Date) -ge $end) { throw "node $name did not acknowledge a Generation above $after within $waitSeconds s: $($s | ConvertTo-Json -Compress -Depth 4)" }
		Start-Sleep -Milliseconds 500
	}
}

# Whether something of the System process (WireGuardNT is a driver) listens on the UDP port
function Test-Listening([int] $port) {
	return @(Get-NetUDPEndpoint -LocalPort $port -ErrorAction SilentlyContinue).Count -gt 0
}

# Wait until the UDP port is listened on, or no longer is
function Wait-Listening([int] $port, [bool] $on) {
	$end = (Get-Date).AddSeconds(30)
	while ((Test-Listening $port) -ne $on) {
		if ((Get-Date) -ge $end) { throw "UDP port $port is $(if ($on) { 'not listened on' } else { 'still listened on' }) after 30 s" }
		Start-Sleep -Milliseconds 500
	}
	Get-NetUDPEndpoint -LocalPort $port -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "UDP $($_.LocalAddress):$($_.LocalPort), process $($_.OwningProcess)" }
}

# The configuration of the Device as the controller renders it, saved for the client and checked against the gateway
function Get-DeviceConfig([string] $wireguardKey, [int] $port) {
	$text = (& $ranz -server $api -token-file $tokenFile get device-config phone) -join "`n"
	if ($LASTEXITCODE -ne 0) { throw "ranz get device-config phone exited with code $LASTEXITCODE" }
	Write-Host $text
	foreach ($line in "PublicKey = $wireguardKey", "Endpoint = ${endpoint}:$port", 'PersistentKeepalive = 25') {
		if ($text -notmatch "(?m)^$([regex]::Escape($line))$") { throw "the configuration of the Device has no line '$line'" }
	}
	Set-Content -LiteralPath $deviceConfig -Value $text -Encoding utf8NoBOM
}

# One run of the client: its lines, which must hold each of want
function Invoke-Client([string[]] $argv, [string[]] $want) {
	$out = & $wgpeer (@('-config', $deviceConfig, '-key', $deviceKey) + $argv) 2>&1 | ForEach-Object { "$_" }
	$code = $LASTEXITCODE
	$out | ForEach-Object { Write-Host "  $_" }
	if ($code -ne 0) { throw "ranz-wgpeer $($argv -join ' ') exited with code $code" }
	foreach ($w in $want) {
		if (-not ($out | Where-Object { $_ -like "$w*" })) { throw "ranz-wgpeer $($argv -join ' ') printed no line '$w'" }
	}
}

# Stop the processes of the check that still run, and the rqlited of the controller
function Stop-All {
	if ($trace -and -not $trace.HasExited) { Stop-Process -Id $trace.Id -Force -ErrorAction SilentlyContinue; $trace.WaitForExit() }
	if ($ctl -and -not $ctl.HasExited) { Stop-Process -Id $ctl.Id -Force -ErrorAction SilentlyContinue; $ctl.WaitForExit() }
	Get-Process -Name 'rqlited' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

$ctl = $null
$trace = $null
try {
	$ctl = Start-Process -FilePath $ranz -PassThru -NoNewWindow -RedirectStandardOutput $controllerOut -RedirectStandardError $controllerErr -ArgumentList @(
		'controller', '-data', $data, '-listen', $tls, '-name', 'device-tracer', '-rqlited', $env:RQLITED, '-rqlite', "http://$rqliteHttp", '-rqlite-raft', $rqliteRaft)
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

	# The Device: a key pair of its own, as a stock client makes one, and the Nodes of the tracer in VRF default of the
	# first start, gw with its WireGuard end
	$devicePublic = "$(& $wgpeer -genkey $deviceKey)".Trim()
	if ($LASTEXITCODE -ne 0 -or $devicePublic -notmatch '^[A-Za-z0-9+/]{43}=$') { throw "ranz-wgpeer -genkey printed '$devicePublic' (exit code $LASTEXITCODE)" }
	$gateway = @{ kind = 'Node'; name = 'gw'; spec = @{ publicKey = $gwKey; wireguard = @{ endpoint = $endpoint } } }
	Invoke-Apply 'tracer' @(
		$gateway,
		@{ kind = 'Node'; name = 'host'; spec = @{ publicKey = $hostKey } },
		@{ kind = 'Device'; name = 'phone'; spec = @{ network = 'default'; gateway = 'gw'; publicKey = $devicePublic; tags = @('phones') } })
	$phone = (Invoke-Ranz @('get', 'resources')).resources | Where-Object { $_.kind -eq 'Device' -and $_.name -eq 'phone' }
	Write-Host "Device phone: $($phone.spec | ConvertTo-Json -Compress)"
	if ($phone.spec.address -notmatch '^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.') { throw 'the Device has no address of the pool of Network default' }

	# The nodes join; the gateway brings its WireGuard interface up for the Device
	$trace = Start-Process -FilePath $vpntest -PassThru -NoNewWindow -RedirectStandardOutput $traceOut -RedirectStandardError $traceErr -ArgumentList @(
		'devicetrace', $tls, $status.publicKey, $ready, $stop)
	$null = $trace.Handle
	$end = (Get-Date).AddSeconds($waitSeconds)
	while (-not (Test-Path -LiteralPath $ready)) {
		if ($trace.HasExited) { throw "vpntest devicetrace exited with code $($trace.ExitCode) before it was ready" }
		if ((Get-Date) -ge $end) { throw "vpntest devicetrace was not ready within $waitSeconds s" }
		Start-Sleep -Milliseconds 500
	}
	$said = Read-Shared $traceOut
	Write-Host $said
	if ($said -match '\[FAIL\]') { throw 'a check of vpntest devicetrace failed' }
	$m = [regex]::Match($said, 'DEVICETRACE NODE host ADDRESS ([0-9.]+) HOST fake')
	if (-not $m.Success) { throw 'vpntest devicetrace printed no address of host' }
	$hostAddress = $m.Groups[1].Value
	$m = [regex]::Match($said, 'DEVICETRACE NODE gw ADDRESS ([0-9.]+) WIREGUARD PORT ([0-9]+)')
	if (-not $m.Success -or [int] $m.Groups[2].Value -ne $defaultPort) { throw "the WireGuard interface of gw is not on UDP port $defaultPort" }

	# The Capability wireguard of the gateway, with the key of its WireGuard interface
	$gw = Wait-Acknowledged 'gw' 0
	$null = Wait-Acknowledged 'host' 0
	Write-Host "API: node gw at generation $($gw.generation), capabilities $($gw.capabilities | ConvertTo-Json -Compress)"
	if (-not $gw.capabilities.wireguard -or $gw.capabilities.wireguardKey -notmatch '^[A-Za-z0-9+/]{43}=$') { throw 'gw does not report the Capability wireguard with the key of its WireGuard interface' }
	$wireguardKey = $gw.capabilities.wireguardKey

	# The gateway listens on the default port, and the client reaches host through it
	Wait-Listening $defaultPort $true
	Get-DeviceConfig $wireguardKey $defaultPort
	Invoke-Client @('-ping', $hostAddress, '-tcp', "${hostAddress}:$tcpPort", '-timeout', '30s') @('WGPEER HANDSHAKE OK', "WGPEER PING OK $hostAddress", "WGPEER TCP OK ${hostAddress}:$tcpPort")

	# The gateway reports the last handshake and the traffic of the Device
	$end = (Get-Date).AddSeconds(60)
	while ($true) {
		$listed = @((Invoke-Ranz @('get', 'devices')).devices | Where-Object { $_.name -eq 'phone' })
		if ($listed.Count -eq 1 -and $listed[0].lastHandshake -and $listed[0].txBytes -gt 0 -and $listed[0].rxBytes -gt 0) { break }
		if ((Get-Date) -ge $end) { throw "ranz get devices shows no handshake and no traffic of the Device within 60 s: $($listed | ConvertTo-Json -Compress)" }
		Start-Sleep -Seconds 1
	}
	Write-Host "API: Device phone: $($listed[0] | ConvertTo-Json -Compress)"

	# A rule that denies the Device blocks the same ping once the gateway acknowledged it
	$before = $gw.generation
	Invoke-Apply 'deny' @(@{ kind = 'Policy'; name = 'deny-phones'; spec = @{ vrf = 'default'; action = 'deny'; priority = 10; from = @{ tags = @('phones') }; protocol = 'icmp' } })
	$gw = Wait-Acknowledged 'gw' $before
	Invoke-Client @('-ping', $hostAddress, '-blocked', '-timeout', '9s') @('WGPEER HANDSHAKE OK', "WGPEER PING BLOCKED $hostAddress")

	# The rule goes, and the gateway moves to another port
	$before = $gw.generation
	$null = Invoke-Ranz @('delete', 'Policy', 'deny-phones')
	$gateway.spec.wireguard.port = $otherPort
	Invoke-Apply 'port' @($gateway)
	$gw = Wait-Acknowledged 'gw' $before
	Wait-Listening $otherPort $true
	Wait-Listening $defaultPort $false
	Get-DeviceConfig $wireguardKey $otherPort
	Invoke-Client @('-ping', $hostAddress, '-tcp', "${hostAddress}:$tcpPort", '-timeout', '30s') @('WGPEER HANDSHAKE OK', "WGPEER PING OK $hostAddress", "WGPEER TCP OK ${hostAddress}:$tcpPort")

	# The nodes stop, and the gateway takes its WireGuard interface away
	New-Item -ItemType File -Force -Path $stop | Out-Null
	if (-not $trace.WaitForExit($waitSeconds * 1000)) { throw "vpntest devicetrace did not finish within $waitSeconds s of the stop file" }
	$out = Read-Shared $traceOut
	Write-Host $out
	if ($out -notmatch 'DEVICETRACE TEST OK') { throw 'vpntest devicetrace failed' }
	if ($out -notmatch 'NO MEMORY LEAKS') { throw 'vpntest devicetrace leaked memory' }
	$m = [regex]::Match($out, 'DEVICETRACE HOST ECHOES ([0-9]+) ACCEPTED ([0-9]+) ECHOED ([0-9]+)')
	if (-not $m.Success -or [int] $m.Groups[1].Value -lt 2 -or [int] $m.Groups[2].Value -lt 2 -or [int] $m.Groups[3].Value -lt 2) { throw 'the fake host of host did not answer the two pings and the two TCP connections of the Device' }
	$m = [regex]::Match($out, 'DEVICETRACE POLICY gw RULES [0-9]+ DROPPED ([0-9]+)')
	if (-not $m.Success -or [int] $m.Groups[1].Value -lt 3) { throw 'the policy of gw did not drop the three echo requests of the denied Device' }
	Wait-Listening $otherPort $false
	Write-Host 'ok'
} catch {
	Stop-All
	Show-Output 'vpntest devicetrace' $traceOut 200
	Show-Output 'vpntest devicetrace (stderr)' $traceErr 50
	Show-Output 'ranz controller' $controllerErr 120
	throw
} finally {
	Stop-All
}
