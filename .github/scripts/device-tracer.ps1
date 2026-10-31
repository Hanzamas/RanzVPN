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
# - a second Device of the same gateway, which stays up, answers the ping of the first while the starter rule of VRF
#   default lets every packet between them through: the filters of the gateway that netsh wfp lists block the forwarding
#   between two Devices on its WireGuard interface, and permit this pair;
# - Devices of two gateways meet in the overlay: host is the gateway of tablet, on a port of its own, and stands for a
#   gateway on a host of its own. One runner holds both gateways, and Windows would forward between their two WireGuard
#   interfaces directly, so the routes of the WireGuard interface of host to tablet are taken away after each state that
#   host applies (Remove-HostRoutes), and the fake host of host answers for tablet. The client of phone pings tablet and
#   opens a TCP connection to it through gw, the overlay and host, whose policies each judge the packets between the two
#   Devices by their tags;
# - a Policy rule that denies the Device blocks the same ping to host once the gateway acknowledged the rule, and the
#   policy of the gateway counts the drops; the ping of the second Device is blocked too, and the gateway lets no pair of
#   its Devices meet while the rule holds: the filters of the forward layers match no protocol, so a rule of some flows
#   keeps two Devices of one gateway apart whole (ADR-0029 amendment of 2026-10-27). The rule denies the ICMP of the
#   Device only, so the ping to tablet is blocked as well, and the TCP connection to tablet still goes through;
# - with the rule gone and wireguard.port of the gateway set to another port, the gateway listens there and no longer on
#   51820, the configuration names the new port, and the client reaches host through it;
# - a Device whose keys the controller makes (SDN-82, #377): `ranz device create` makes its key pair and its PresharedKey,
#   applies it and prints its finished configuration with the private key and the PresharedKey in it, and the QR code of it
#   into a PNG file. The client takes that configuration as it is, with no key file: the gateway terminates the Device with
#   the PresharedKey, so the client completes its handshake, pings host and opens a TCP connection to it, while the same
#   configuration without its PresharedKey line gets no handshake. The controller shows neither key again, in the
#   configuration that it renders later or in its output, and the revocation of the Device takes it from the gateway with
#   the next Generation, after which its client gets no handshake either.
# The output of the processes is shown when a check fails, with the node log of vpntest devicetrace (Stop-Trace).

$bin = (Resolve-Path $BuildDir).Path
$ranz = Join-Path $bin 'ranz.exe'
$vpntest = Join-Path $bin 'vpntest.exe'
$wgpeer = Join-Path $bin 'ranz-wgpeer.exe'

$work = Join-Path $env:RUNNER_TEMP 'device-tracer'
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
$ready = Join-Path $work 'ready'
$stop = Join-Path $work 'stop'
$deviceKey = Join-Path $work 'phone.key'
$deviceConfig = Join-Path $work 'phone.conf'
# The second Device of the gateway, which stays up while phone tries to reach it
$laptopKey = Join-Path $work 'laptop.key'
$laptopConfig = Join-Path $work 'laptop.conf'
$laptopOut = Join-Path $work 'laptop.out'
$laptopErr = Join-Path $work 'laptop.err'
# The Device of host, which the fake host of host plays: no client holds its key
$tabletKey = Join-Path $work 'tablet.key'

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
# The port of host, the gateway of tablet; vpntest prints the index of its WireGuard interface ($hostInterface)
$hostPort = 51822
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

function Show-Listening([int] $port) {
	Get-NetUDPEndpoint -LocalPort $port -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "UDP $($_.LocalAddress):$($_.LocalPort), process $($_.OwningProcess)" }
}

# Wait until the UDP port is listened on, or no longer is, within $waitSeconds (FIX-11, #438: the gateway may take longer
# than a fixed window on a slow runner). On a timeout the state of the gateway goes out with the error: who listens on
# its ports, the ranges that Windows keeps that hold one, and, from the catch below, the lines of vpntest about its
# WireGuard interface and its node log.
function Wait-Listening([int] $port, [bool] $on) {
	$start = Get-Date
	$end = $start.AddSeconds($waitSeconds)
	while ((Test-Listening $port) -ne $on) {
		if ((Get-Date) -ge $end) {
			Write-Host "--- the UDP ports of the gateways:"
			foreach ($p in $defaultPort, $otherPort, $hostPort) { Show-Listening $p }
			$hits = @(Get-ExcludedRanges @($defaultPort, $otherPort, $hostPort))
			Write-Host "UDP port ranges that Windows keeps, with a port of a gateway: $(if ($hits.Count -gt 0) { $hits -join ', ' } else { 'none' })"
			throw "UDP port $port is $(if ($on) { 'not listened on' } else { 'still listened on' }) after $waitSeconds s"
		}
		Start-Sleep -Milliseconds 500
	}
	Write-Host "UDP port $port is $(if ($on) { 'listened on' } else { 'no longer listened on' }) after $([int] ((Get-Date) - $start).TotalSeconds) s"
	Show-Listening $port
}

# The UDP port ranges that Windows keeps from binding (netsh int ipv4|ipv6 show excludedportrange) that hold one of ports,
# as "family first-last"; the socket of WireGuardNT on such a port fails with error 5 (access denied)
function Get-ExcludedRanges([int[]] $ports) {
	$hits = @()
	foreach ($family in 'ipv4', 'ipv6') {
		$lines = & netsh.exe interface $family show excludedportrange protocol=udp
		if ($LASTEXITCODE -ne 0) { throw "netsh interface $family show excludedportrange exited with code $LASTEXITCODE" }
		foreach ($line in $lines) {
			$m = [regex]::Match("$line", '^\s*([0-9]+)\s+([0-9]+)')
			if (-not $m.Success) { continue }
			$first = [int] $m.Groups[1].Value
			$last = [int] $m.Groups[2].Value
			if (@($ports | Where-Object { $_ -ge $first -and $_ -le $last }).Count -gt 0) { $hits += "$family $first-$last" }
		}
	}
	return $hits
}

# The ports of the gateway free of the ranges that Windows keeps: the Windows NAT service (winnat) reserves ranges of the
# dynamic ports for Hyper-V, which may hold 51820 on a runner, and takes new ones when it starts again
function Clear-ExcludedRanges([int[]] $ports) {
	$hits = @(Get-ExcludedRanges $ports)
	if ($hits.Count -eq 0) { return }
	Write-Host "UDP port ranges that Windows keeps, with a port of the gateway: $($hits -join ', '); the Windows NAT service starts again"
	& net.exe stop winnat | Out-Null
	& net.exe start winnat | Out-Null
	$hits = @(Get-ExcludedRanges $ports)
	if ($hits.Count -gt 0) { throw "UDP port ranges that Windows keeps still hold a port of the gateway ($($ports -join ', ')): $($hits -join ', ')" }
}

# host stands for a gateway on a host of its own: the routes of its WireGuard interface to tablet go, which each state that
# host applies installs again, so the host of the runner reaches tablet as another host would, through the adapter of gw
# and the overlay. The routes are found by the addresses of tablet; none of them may be left.
function Remove-HostRoutes {
	$routes = @(Get-NetRoute -InterfaceIndex $hostInterface -ErrorAction SilentlyContinue | Where-Object { Test-TabletRoute $_.DestinationPrefix })
	foreach ($r in $routes) {
		Write-Host "the route $($r.DestinationPrefix) of the WireGuard interface of host (interface $hostInterface) goes: host stands for a gateway on a host of its own"
		Remove-NetRoute -InputObject $r -Confirm:$false
	}
	$left = @(Get-NetRoute -InterfaceIndex $hostInterface -ErrorAction SilentlyContinue | Where-Object { Test-TabletRoute $_.DestinationPrefix })
	if ($left.Count -gt 0) { throw "the WireGuard interface of host (interface $hostInterface) still routes $($left.DestinationPrefix -join ', ') to tablet" }
}

# Whether the prefix of a route is the host route of an address of tablet
function Test-TabletRoute([string] $prefix) {
	$address, $length = $prefix -split '/'
	$ip = [System.Net.IPAddress]::Parse($address)
	if ([int] $length -ne $ip.GetAddressBytes().Length * 8) { return $false }
	return (@($tabletAddresses | Where-Object { $_.Equals($ip) }).Count -gt 0)
}

# The configuration of the Device name as the controller renders it, saved into file for the client and checked against the
# gateway
function Get-DeviceConfig([string] $name, [string] $file, [string] $wireguardKey, [int] $port) {
	$text = (& $ranz -server $api -token-file $tokenFile get device-config $name) -join "`n"
	if ($LASTEXITCODE -ne 0) { throw "ranz get device-config $name exited with code $LASTEXITCODE" }
	Write-Host $text
	foreach ($line in "PublicKey = $wireguardKey", "Endpoint = ${endpoint}:$port", 'PersistentKeepalive = 25') {
		if ($text -notmatch "(?m)^$([regex]::Escape($line))$") { throw "the configuration of Device $name has no line '$line'" }
	}
	Set-Content -LiteralPath $file -Value $text -Encoding utf8NoBOM
}

# A key pair of a Device, as a stock client makes one: its private key into file, its public key returned
function New-DeviceKey([string] $file) {
	$public = "$(& $wgpeer -genkey $file)".Trim()
	if ($LASTEXITCODE -ne 0 -or $public -notmatch '^[A-Za-z0-9+/]{43}=$') { throw "ranz-wgpeer -genkey printed '$public' (exit code $LASTEXITCODE)" }
	return $public
}

# One run of the client: its lines, which must hold each of want. It reads the configuration of the file config and the
# private key of the file that $key names (-key FILE), none for a finished configuration that holds the private key
function Invoke-Client([string[]] $argv, [string[]] $want, [string] $config = $deviceConfig, [string[]] $key = @('-key', $deviceKey)) {
	$out = & $wgpeer (@('-config', $config) + $key + $argv) 2>&1 | ForEach-Object { "$_" }
	$code = $LASTEXITCODE
	$out | ForEach-Object { Write-Host "  $_" }
	if ($code -ne 0) { throw "ranz-wgpeer $($argv -join ' ') exited with code $code" }
	foreach ($w in $want) {
		if (-not ($out | Where-Object { $_ -like "$w*" })) { throw "ranz-wgpeer $($argv -join ' ') printed no line '$w'" }
	}
}

# A client of the configuration in the file config that must get no handshake with the gateway: it comes up, and gives up
# after a few seconds. what says which client it is, for the message of the check. Its exit code is the answer that the
# check wants, so it does not stay in $LASTEXITCODE: the step of the workflow ends with that variable as its own exit code.
function Assert-NoHandshake([string] $config, [string] $what) {
	$out = & $wgpeer -config $config -ping $hostAddress -timeout 6s 2>&1 | ForEach-Object { "$_" }
	$code = $LASTEXITCODE
	$global:LASTEXITCODE = 0
	$out | ForEach-Object { Write-Host "  $_" }
	if ($code -eq 0 -or -not ($out | Where-Object { $_ -like '*no handshake with the gateway*' })) {
		throw "$what completed a handshake with the gateway, or failed in another way (exit code $code)"
	}
}

# A failed check of the script: vpntest devicetrace, if it still runs, gets a stop file that says so, which makes it print
# the state of its nodes and their node log on its way out, within $waitSeconds. The file is renamed into place, so that
# vpntest never reads it half written.
function Stop-Trace {
	if (-not $trace -or $trace.HasExited) { return }
	$file = "$stop.tmp"
	Set-Content -LiteralPath $file -Value 'failed' -Encoding utf8NoBOM
	Move-Item -LiteralPath $file -Destination $stop -Force
	if (-not $trace.WaitForExit($waitSeconds * 1000)) { Write-Host "vpntest devicetrace did not finish within $waitSeconds s of the stop file" }
}

# Stop the processes of the check that still run, and the rqlited of the controller
function Stop-All {
	if ($laptop -and -not $laptop.HasExited) { Stop-Process -Id $laptop.Id -Force -ErrorAction SilentlyContinue; $laptop.WaitForExit() }
	if ($trace -and -not $trace.HasExited) { Stop-Process -Id $trace.Id -Force -ErrorAction SilentlyContinue; $trace.WaitForExit() }
	if ($ctl -and -not $ctl.HasExited) { Stop-Process -Id $ctl.Id -Force -ErrorAction SilentlyContinue; $ctl.WaitForExit() }
	Get-Process -Name 'rqlited' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

$ctl = $null
$trace = $null
$laptop = $null
try {
	Clear-ExcludedRanges @($defaultPort, $otherPort, $hostPort)

	$ctl =Start-Process -FilePath $ranz -PassThru -NoNewWindow -RedirectStandardOutput $controllerOut -RedirectStandardError $controllerErr -ArgumentList @(
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

	# The Devices, each with a key pair of its own, and the Nodes of the tracer in VRF default of the first start, gw with
	# its WireGuard end, and host with one of its own, on its own port, as the gateway of tablet
	$gateway = @{ kind = 'Node'; name = 'gw'; spec = @{ publicKey = $gwKey; wireguard = @{ endpoint = $endpoint } } }
	Invoke-Apply 'tracer' @(
		$gateway,
		@{ kind = 'Node'; name = 'host'; spec = @{ publicKey = $hostKey; wireguard = @{ endpoint = $endpoint; port = $hostPort } } },
		@{ kind = 'Device'; name = 'phone'; spec = @{ network = 'default'; gateway = 'gw'; publicKey = (New-DeviceKey $deviceKey); tags = @('phones') } },
		@{ kind = 'Device'; name = 'laptop'; spec = @{ network = 'default'; gateway = 'gw'; publicKey = (New-DeviceKey $laptopKey); tags = @('laptops') } },
		@{ kind = 'Device'; name = 'tablet'; spec = @{ network = 'default'; gateway = 'host'; publicKey = (New-DeviceKey $tabletKey); tags = @('tablets') } })
	$devices = @((Invoke-Ranz @('get', 'resources')).resources | Where-Object { $_.kind -eq 'Device' })
	foreach ($d in $devices) {
		Write-Host "Device $($d.name): $($d.spec | ConvertTo-Json -Compress)"
		if ($d.spec.address -notmatch '^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.') { throw "Device $($d.name) has no address of the pool of Network default" }
	}
	$laptopAddress = ($devices | Where-Object { $_.name -eq 'laptop' }).spec.address
	$tablet = ($devices | Where-Object { $_.name -eq 'tablet' }).spec
	$tabletAddress = $tablet.address
	# The addresses of tablet, which host routes through its WireGuard interface (Remove-HostRoutes)
	$tabletAddresses = @(@($tablet.address, $tablet.ipv6Address) | Where-Object { $_ } | ForEach-Object { [System.Net.IPAddress]::Parse($_) })

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
	$m = [regex]::Match($said, 'DEVICETRACE NODE host ADDRESS ([0-9.]+) HOST fake WIREGUARD PORT ([0-9]+) INTERFACE ([0-9]+) DEVICES ([0-9]+) PAIRS ([0-9]+)')
	if (-not $m.Success) { throw 'vpntest devicetrace printed no address of host' }
	$hostAddress = $m.Groups[1].Value
	$hostInterface = [int] $m.Groups[3].Value
	if ([int] $m.Groups[2].Value -ne $hostPort -or [int] $m.Groups[4].Value -ne 1 -or [int] $m.Groups[5].Value -ne 0) {
		throw "the WireGuard interface of host is not on UDP port $hostPort with tablet, its one Device"
	}
	$m = [regex]::Match($said, 'DEVICETRACE NODE gw ADDRESS ([0-9.]+) WIREGUARD PORT ([0-9]+) INTERFACE [0-9]+ DEVICES ([0-9]+) PAIRS ([0-9]+)')
	if (-not $m.Success -or [int] $m.Groups[2].Value -ne $defaultPort -or [int] $m.Groups[3].Value -ne 2 -or [int] $m.Groups[4].Value -ne 1) {
		throw "the WireGuard interface of gw is not on UDP port $defaultPort with the two Devices, which the starter rule lets meet"
	}

	# The Capability wireguard of each gateway, with the key of its WireGuard interface
	$gw = Wait-Acknowledged 'gw' 0
	$overlay = Wait-Acknowledged 'host' 0
	Write-Host "API: node gw at generation $($gw.generation), capabilities $($gw.capabilities | ConvertTo-Json -Compress)"
	if (-not $gw.capabilities.wireguard -or $gw.capabilities.wireguardKey -notmatch '^[A-Za-z0-9+/]{43}=$') { throw 'gw does not report the Capability wireguard with the key of its WireGuard interface' }
	$wireguardKey = $gw.capabilities.wireguardKey
	Write-Host "API: node host at generation $($overlay.generation), capabilities $($overlay.capabilities | ConvertTo-Json -Compress)"
	if (-not $overlay.capabilities.wireguard) { throw 'host does not report the Capability wireguard, and it is the gateway of tablet' }
	# The Hello of a node reports the Capability bgpPeering when ranz.exe, which holds its sidecar, is next to it (SDN-77-R2, #532),
	# as it is next to vpntest.exe here: the controller refuses a node without it as a member of a VRF that peers by BGP
	if (-not $gw.capabilities.bgpPeering -or -not $overlay.capabilities.bgpPeering) { throw 'gw and host do not report the Capability bgpPeering, and ranz.exe is next to vpntest.exe' }

	# The gateway listens on the default port, and the client reaches host through it
	Wait-Listening $defaultPort $true
	Get-DeviceConfig 'phone' $deviceConfig $wireguardKey $defaultPort
	Invoke-Client @('-ping', $hostAddress, '-tcp', "${hostAddress}:$tcpPort", '-timeout', '30s') @('WGPEER HANDSHAKE OK', "WGPEER PING OK $hostAddress", "WGPEER TCP OK ${hostAddress}:$tcpPort")

	# Devices of two gateways: host listens on its own port as the gateway of tablet, and phone reaches tablet through gw,
	# the overlay and host, whose policies each judge the packets between the two Devices
	Wait-Listening $hostPort $true
	Remove-HostRoutes
	Invoke-Client @('-ping', $tabletAddress, '-tcp', "${tabletAddress}:$tcpPort", '-timeout', '30s') @('WGPEER HANDSHAKE OK', "WGPEER PING OK $tabletAddress", "WGPEER TCP OK ${tabletAddress}:$tcpPort")

	# Two Devices of the gateway meet where the policy lets them: laptop stays up and answers the ping of phone, since the
	# starter rule of VRF default lets every packet between them through. The filters of the gateway are among the filters
	# of the Windows Filtering Platform: the block of the forwarding between two Devices, and the permits of this pair.
	$filters = Join-Path $work 'wfp-filters.xml'
	& netsh.exe wfp show filters file=$filters | Out-Null
	if ($LASTEXITCODE -ne 0) { throw "netsh wfp show filters exited with code $LASTEXITCODE" }
	foreach ($name in 'Ranz VPN: no forwarding between two WireGuard Devices of a gateway', 'Ranz VPN: two WireGuard Devices that the policy lets meet') {
		if (-not (Select-String -LiteralPath $filters -SimpleMatch $name -Quiet)) { throw "netsh wfp show filters lists no filter '$name'" }
	}
	Get-DeviceConfig 'laptop' $laptopConfig $wireguardKey $defaultPort
	$laptop = Start-Process -FilePath $wgpeer -PassThru -NoNewWindow -RedirectStandardOutput $laptopOut -RedirectStandardError $laptopErr -ArgumentList @(
		'-config', $laptopConfig, '-key', $laptopKey, '-serve', '300s')
	$null = $laptop.Handle
	$end = (Get-Date).AddSeconds(60)
	while ((Read-Shared $laptopOut) -notmatch 'WGPEER SERVING') {
		if ($laptop.HasExited) { throw "the client of laptop exited with code $($laptop.ExitCode):`n$(Read-Shared $laptopOut)$(Read-Shared $laptopErr)" }
		if ((Get-Date) -ge $end) { throw 'the client of laptop did not complete its handshake within 60 s' }
		Start-Sleep -Milliseconds 500
	}
	Write-Host (Read-Shared $laptopOut)
	Invoke-Client @('-ping', $laptopAddress, '-timeout', '30s') @('WGPEER HANDSHAKE OK', "WGPEER PING OK $laptopAddress")

	# The gateway reports the last handshake and the traffic of the Device
	$end = (Get-Date).AddSeconds(60)
	while ($true) {
		$listed = @((Invoke-Ranz @('get', 'devices')).devices | Where-Object { $_.name -eq 'phone' })
		if ($listed.Count -eq 1 -and $listed[0].lastHandshake -and $listed[0].txBytes -gt 0 -and $listed[0].rxBytes -gt 0) { break }
		if ((Get-Date) -ge $end) { throw "ranz get devices shows no handshake and no traffic of the Device within 60 s: $($listed | ConvertTo-Json -Compress)" }
		Start-Sleep -Seconds 1
	}
	Write-Host "API: Device phone: $($listed[0] | ConvertTo-Json -Compress)"

	# A rule that denies the Device blocks the same ping once the gateway acknowledged it: to host, in the overlay, and to
	# laptop, on the gateway, which keeps the pair apart from then on
	$before = $gw.generation
	$hostBefore = $overlay.generation
	Invoke-Apply 'deny' @(@{ kind = 'Policy'; name = 'deny-phones'; spec = @{ vrf = 'default'; action = 'deny'; priority = 10; from = @{ tags = @('phones') }; protocol = 'icmp' } })
	$gw = Wait-Acknowledged 'gw' $before
	Invoke-Client @('-ping', $hostAddress, '-blocked', '-timeout', '9s') @('WGPEER HANDSHAKE OK', "WGPEER PING BLOCKED $hostAddress")
	Invoke-Client @('-ping', $laptopAddress, '-blocked', '-timeout', '9s') @('WGPEER HANDSHAKE OK', "WGPEER PING BLOCKED $laptopAddress")
	# The rule denies only the ICMP of phone, which the filters of the forward layers cannot tell from its TCP: gw keeps the
	# pair apart whole while the rule holds (ADR-0029 amendment of 2026-10-27), as vpntest prints for that Generation
	$apart = "gw: generation $($gw.generation); WireGuard interface up 1 on UDP port $defaultPort, 2 Devices, [0-9]+ routes, kept apart 1, 0 pairs"
	if ((Read-Shared $traceOut) -notmatch $apart) { throw "gw does not keep phone and laptop apart at generation $($gw.generation), under a rule that denies only the ICMP of phone" }
	Stop-Process -Id $laptop.Id -Force
	$laptop.WaitForExit()

	# The rule denies the ICMP of the phones only: tablet, a Device of the other gateway, gets no ping from phone, and the
	# TCP connection of phone to tablet still goes through, judged in the overlay by the policy of each gateway. host takes
	# the rule too, since its other end names any Device.
	$overlay = Wait-Acknowledged 'host' $hostBefore
	Remove-HostRoutes
	Invoke-Client @('-ping', $tabletAddress, '-blocked', '-timeout', '9s') @('WGPEER HANDSHAKE OK', "WGPEER PING BLOCKED $tabletAddress")
	Invoke-Client @('-tcp', "${tabletAddress}:$tcpPort", '-timeout', '30s') @('WGPEER HANDSHAKE OK', "WGPEER TCP OK ${tabletAddress}:$tcpPort")

	# The rule goes, and the gateway moves to another port
	$before = $gw.generation
	$null = Invoke-Ranz @('delete', 'Policy', 'deny-phones')
	$gateway.spec.wireguard.port = $otherPort
	Invoke-Apply 'port' @($gateway)
	$gw = Wait-Acknowledged 'gw' $before
	Wait-Listening $otherPort $true
	Wait-Listening $defaultPort $false
	Get-DeviceConfig 'phone' $deviceConfig $wireguardKey $otherPort
	Invoke-Client @('-ping', $hostAddress, '-tcp', "${hostAddress}:$tcpPort", '-timeout', '30s') @('WGPEER HANDSHAKE OK', "WGPEER PING OK $hostAddress", "WGPEER TCP OK ${hostAddress}:$tcpPort")

	# A Device whose keys the controller makes (SDN-82, #377). The gateway is connected and has reported the key of its
	# WireGuard interface, which `ranz device create` needs, and listens on the port that the configuration names now.
	# The finished configuration is written to a file that only this process reads, and holds the private key of the Device
	# and its PresharedKey, which the script never prints.
	$pocketConfig = Join-Path $work 'pocket.conf'
	$pocketPlain = Join-Path $work 'pocket-without-psk.conf'
	$pocketPng = Join-Path $work 'pocket.png'
	$pocketNote = Join-Path $work 'pocket.err'
	$before = $gw.generation
	& $ranz -server $api -token-file $tokenFile device create -network default -gateway gw -tags pockets -o $pocketConfig -qr-file $pocketPng pocket 2> $pocketNote
	if ($LASTEXITCODE -ne 0) { throw "ranz device create exited with code ${LASTEXITCODE}: $(Read-Shared $pocketNote)" }
	Write-Host (Read-Shared $pocketNote)
	$text = Get-Content -Raw -LiteralPath $pocketConfig
	foreach ($line in "PublicKey = $wireguardKey", "Endpoint = ${endpoint}:$otherPort", 'PersistentKeepalive = 25') {
		if ($text -notmatch "(?m)^$([regex]::Escape($line))\r?$") { throw "the finished configuration of Device pocket has no line '$line'" }
	}
	$pocketKeys = @{}
	foreach ($name in 'PrivateKey', 'PresharedKey') {
		$m = [regex]::Match($text, "(?m)^$name = ([A-Za-z0-9+/]{43}=)\r?$")
		if (-not $m.Success) { throw "the finished configuration of Device pocket has no line $name with a key" }
		$pocketKeys[$name] = $m.Groups[1].Value
	}
	$png = [System.IO.File]::ReadAllBytes($pocketPng)
	if ($png.Length -lt 1000 -or $png[0] -ne 0x89 -or [System.Text.Encoding]::ASCII.GetString($png, 1, 3) -ne 'PNG') { throw 'ranz device create wrote no PNG file of the QR code' }
	$gw = Wait-Acknowledged 'gw' $before

	# The client takes the finished configuration as it is, with no file for its private key, and reaches host: the gateway
	# terminates the Device with its PresharedKey
	Invoke-Client @('-ping', $hostAddress, '-tcp', "${hostAddress}:$tcpPort", '-timeout', '30s') @('WGPEER PRESHARED KEY yes', 'WGPEER HANDSHAKE OK', "WGPEER PING OK $hostAddress", "WGPEER TCP OK ${hostAddress}:$tcpPort") $pocketConfig @()

	# The same configuration without its PresharedKey line is that of a client that does not hold it, and gets no handshake
	Get-Content -LiteralPath $pocketConfig | Where-Object { $_ -notmatch '^PresharedKey = ' } | Set-Content -LiteralPath $pocketPlain -Encoding utf8NoBOM
	Assert-NoHandshake $pocketPlain 'a client without the PresharedKey of Device pocket'

	# The controller shows neither key again, in the configuration that it renders later or in its own output
	$later = (& $ranz -server $api -token-file $tokenFile get device-config pocket) -join "`n"
	if ($LASTEXITCODE -ne 0) { throw "ranz get device-config pocket exited with code $LASTEXITCODE" }
	foreach ($name in $pocketKeys.Keys) {
		if ($later.Contains($pocketKeys[$name])) { throw "the configuration that the controller renders later holds the $name of Device pocket" }
		foreach ($file in $controllerOut, $controllerErr) {
			if ((Read-Shared $file).Contains($pocketKeys[$name])) { throw "the output of the controller holds the $name of Device pocket" }
		}
	}

	# The revocation takes the Device from the gateway with the next Generation, and its client gets no handshake any more
	$before = $gw.generation
	$null = Invoke-Ranz @('delete', 'Device', 'pocket')
	$gw = Wait-Acknowledged 'gw' $before
	Assert-NoHandshake $pocketConfig 'the client of the revoked Device pocket'

	# The nodes stop, and the gateway takes its WireGuard interface away
	New-Item -ItemType File -Force -Path $stop | Out-Null
	if (-not $trace.WaitForExit($waitSeconds * 1000)) { throw "vpntest devicetrace did not finish within $waitSeconds s of the stop file" }
	$out = Read-Shared $traceOut
	Write-Host $out
	if ($out -notmatch 'DEVICETRACE TEST OK') { throw 'vpntest devicetrace failed' }
	if ($out -notmatch 'NO MEMORY LEAKS') { throw 'vpntest devicetrace leaked memory' }
	$m = [regex]::Match($out, 'DEVICETRACE HOST ECHOES ([0-9]+) ACCEPTED ([0-9]+) ECHOED ([0-9]+)')
	if (-not $m.Success -or [int] $m.Groups[1].Value -lt 2 -or [int] $m.Groups[2].Value -lt 2 -or [int] $m.Groups[3].Value -lt 2) { throw 'the fake host of host did not answer the two pings and the two TCP connections of the Device' }
	# For tablet: the one ping under the starter rule, and a TCP connection under either rule
	$m = [regex]::Match($out, 'DEVICETRACE HOST DEVICES ECHOES ([0-9]+) ACCEPTED ([0-9]+) ECHOED ([0-9]+)')
	if (-not $m.Success -or [int] $m.Groups[1].Value -lt 1 -or [int] $m.Groups[2].Value -lt 2 -or [int] $m.Groups[3].Value -lt 2) { throw 'the fake host of host did not answer, for tablet, the ping and the two TCP connections of phone' }
	# Three echo requests to host and three to tablet: gw drops them on their way into the overlay
	$m = [regex]::Match($out, 'DEVICETRACE POLICY gw RULES [0-9]+ DROPPED ([0-9]+)')
	if (-not $m.Success -or [int] $m.Groups[1].Value -lt 6) { throw 'the policy of gw did not drop the echo requests of the denied Device to host and to tablet' }
	if ($out -notmatch "DEVICETRACE WIREGUARD gw UP 1 PORT $otherPort DEVICES 2 APART 1 PAIRS 1") { throw "the WireGuard interface of gw was not up on UDP port $otherPort with its filters and the two Devices, which the starter rule lets meet again, until the stop" }
	if ($out -notmatch "DEVICETRACE WIREGUARD host UP 1 PORT $hostPort DEVICES 1 APART 1 PAIRS 0") { throw "the WireGuard interface of host was not up on UDP port $hostPort with its filters and tablet until the stop" }
	Wait-Listening $otherPort $false
	Wait-Listening $hostPort $false
	Write-Host 'ok'
} catch {
	Stop-Trace
	Stop-All
	Show-Output 'vpntest devicetrace' $traceOut 400
	Show-Output 'vpntest devicetrace (stderr)' $traceErr 50
	Show-Output 'ranz controller' $controllerErr 120
	throw
} finally {
	Stop-All
}
