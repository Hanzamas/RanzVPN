# The QTIP step of the XDP job (CORE-S7-2, #83; ADR-0018 decisions 2 and 5; seam 3 of #45 as the ADR-0002 amendment of
# 2026-10-21 has it: two node processes on one runner, each on its own KM-TEST adapter), on Windows Server 2022 and 2025
# x64, after the step of the L2 adapter (kmtest.ps1), with the XDP runtime that the signed ranz.exe installs and the
# msquic.dll of the pinned package next to vpntest:
# 1. ranz install. vpntest qtip in one process: the rule (Windows Server x64 only), the msquic release that ships QTIP,
#    default off, opt-in and the normal datapath as before, a QTIP listener on 8443 that holds both the TCP and the UDP
#    port, which plain QUIC over the loopback does not reach (msquic takes the packets of a QTIP listener from XDP only),
#    and the QuicXdp and Qtip settings of a node, here with the XDP runtime.
# 2. The wire between the two nodes, the physical side of the ADR-0002 amendment: an internal Hyper-V switch (the Hyper-V
#    role and its PowerShell module are features of the windows-2022 and windows-2025 images) with a host vNIC for each
#    node, both with XDP. A KM-TEST adapter cannot be the wire: XDP sends the frames of an AF_XDP socket down to the
#    miniport, below its own hooks, and a KM-TEST adapter sends nowhere what reaches it (send.c of the XDP LWF of
#    xdp-for-windows 1.4.0). The wire is set up as the DuoNic pair on which msquic tests its XDP datapath and QTIP on one
#    host (vm-setup/duonic/duonic.ps1 of microsoft/corenet-ci): the vNIC of node-s has 198.18.85.1/24 and the vNIC of
#    node-c 198.18.85.2/24, and each vNIC has a permanent neighbour entry for the address of the other node, with the MAC
#    of the other vNIC, and a /32 route to it with metric 0, so that the host takes the route between the two addresses
#    out of the vNICs and not over the loopback. msquic needs it on both ends: the client takes its source address from
#    the host, and both ends resolve their route with GetBestRoute2 from their own address and take the neighbour entry
#    of its next hop (RawResolveRoute of datapath_raw_socket_win.c of msquic 2.6.2). An address of node-s that is no
#    address of the host leaves node-s without a route back: msquic answers the TCP handshake of QTIP on the route of the
#    frame that it received (datapath_raw_socket.c), but the QUIC packets of its connection on a route that it resolves.
# 3. Two server node processes. node-s (vpntest qtip serve STOPFILE) brings up its own KM-TEST adapter with XDP and its
#    Listener with QTIP on 8443, and prints READY with the thumbprint of its certificate; from outside, Get-NetTCPConnection
#    and Get-NetUDPEndpoint must show TCP 8443 and UDP 8443 held by its process. node-c (vpntest qtip dial THUMBPRINT
#    198.18.85.1) brings up its own KM-TEST adapter with XDP, finds both ports held from its process and the QTIP listener
#    of node-s out of reach of plain QUIC over the loopback, and dials node-s over QTIP across the wire: the
#    QUIC-over-TCP-header link must come up, and node-s must say that its overlay took the stream. The frames that the two
#    vNICs counted go to the job summary with the link, and the frames of port 8443 that pktmon captured on the adapters
#    during the dial go to the log.
# 4. The wire goes, then ranz uninstall.
# Each run of vpntest is a process of its own with a time limit.
param(
	[Parameter(Mandatory = $true)]
	[string] $Ranz,
	[Parameter(Mandatory = $true)]
	[string] $Vpntest,
	[string] $Runner = ''
)

$ErrorActionPreference = 'Stop'
# Native exit codes are checked by hand below
$PSNativeCommandUseErrorActionPreference = $false

$ranzExe = (Resolve-Path -LiteralPath $Ranz).Path
$vpntestExe = (Resolve-Path -LiteralPath $Vpntest).Path
# TRANSPORT_QUIC_QTIP_PORT of src/Core/Transport.h
$port = 8443
$firewallRule = 'ranz-qtip'
$script:failures = @()
$script:runs = 0
# The wire: an internal Hyper-V switch, the host vNIC that New-VMSwitch makes with it for node-c, and one more for node-s
$wireSwitch = 'ranz-qtip'
$dialNic = "vEthernet ($wireSwitch)"
$serveNic = "vEthernet ($wireSwitch-s)"
# node-c on the wire, the prefix length of the wire, and node-s on the wire: the addresses of the two vNICs
$dialWire = '198.18.85.2'
$wireLength = 24
$serveWire = '198.18.85.1'
# The packet capture of the dial (pktmon, in the image of Windows Server since 2019), for the log
$capture = Join-Path $env:RUNNER_TEMP 'qtip-dial.etl'

# A step that failed: the job goes on with the next one and fails at the end
function Add-Failure([string] $step) {
	$script:failures += $step
	Write-Host "::error::$step"
}

# Run ranz.exe with arguments: its exit code and its output, standard error included
function Invoke-Ranz([string[]] $argv) {
	$out = (& $ranzExe @argv 2>&1 | Out-String)
	$code = $LASTEXITCODE
	Write-Host "ranz $($argv -join ' '): exit $code`n$out"
	return [pscustomobject]@{ Code = $code; Out = $out }
}

# The text of a file that a process may still write to
function Read-Shared([string] $path) {
	if (-not (Test-Path -LiteralPath $path)) { return '' }
	$fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
	try {
		return (New-Object System.IO.StreamReader($fs)).ReadToEnd()
	} finally {
		$fs.Dispose()
	}
}

# Start vpntest qtip with arguments as a process of its own: the process and the files of its output
function Start-Qtip([string[]] $argv) {
	$script:runs++
	$out = Join-Path $env:RUNNER_TEMP "qtip-$($script:runs).out"
	$err = Join-Path $env:RUNNER_TEMP "qtip-$($script:runs).err"
	Write-Host "vpntest qtip $($argv -join ' ')"
	$p = Start-Process -FilePath $vpntestExe -ArgumentList (@('qtip') + $argv) -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError $err
	# The handle keeps the exit code of the process
	$null = $p.Handle
	return [pscustomobject]@{ Process = $p; Out = $out; Err = $err }
}

# Wait for a run to end, $minutes at most, and give its output; it passed when it printed its OK marker and no leak, and
# ended, and did not skip for a missing msquic.dll
function Wait-Qtip($run, [int] $minutes) {
	$ended = $run.Process.WaitForExit($minutes * 60000)
	if (-not $ended) {
		Stop-Process -Id $run.Process.Id -Force -ErrorAction SilentlyContinue
		$ended = $run.Process.WaitForExit(30000)
		Write-Host "::error::vpntest qtip did not end within $minutes minutes: stopped$(if (-not $ended) { ', and it does not end' })"
	}
	$text = (Read-Shared $run.Out) + (Read-Shared $run.Err)
	Write-Host $text
	$skipped = $text -match 'the test is skipped'
	if ($skipped) { Write-Host '::error::vpntest qtip skipped: msquic.dll is not next to vpntest' }
	$ok = $text -match '(?m)^QTIP TEST OK' -and $text -match 'NO MEMORY LEAKS' -and -not $skipped
	return [pscustomobject]@{ Ok = ($ok -and $ended); Text = $text }
}

# An adapter of the wire once it is up, or $null after a minute
function Wait-Nic([string] $name) {
	$deadline = (Get-Date).AddMinutes(1)
	while ((Get-Date) -lt $deadline) {
		$nic = Get-NetAdapter -Name $name -ErrorAction SilentlyContinue
		if ($nic -and $nic.Status -eq 'Up') { return $nic }
		Start-Sleep -Milliseconds 500
	}
	return $null
}

# The wire between node-c and node-s (step 2 above): the vNIC of each node with its address, both with XDP, and on each
# vNIC the neighbour entry and the /32 route of the address of the other node, as duonic.ps1 has them. It throws what
# went wrong.
function New-Wire {
	Remove-VMSwitch -Name $wireSwitch -Force -ErrorAction SilentlyContinue
	$null = New-VMSwitch -Name $wireSwitch -SwitchType Internal -ErrorAction Stop
	$null = Add-VMNetworkAdapter -ManagementOS -SwitchName $wireSwitch -Name "$wireSwitch-s" -ErrorAction Stop
	$c = Wait-Nic $dialNic
	$s = Wait-Nic $serveNic
	if (-not $c -or -not $s) { throw "the vNICs of the switch $wireSwitch did not come up: $dialNic $([bool]$c), $serveNic $([bool]$s)" }

	# The XDP LWF that ranz install put on the runner binds to a new adapter
	foreach ($nic in @($c, $s)) {
		$b = $null
		$deadline = (Get-Date).AddSeconds(30)
		while ((Get-Date) -lt $deadline) {
			$b = Get-NetAdapterBinding -Name $nic.Name -ComponentID ms_xdp -ErrorAction SilentlyContinue
			if ($b) { break }
			Start-Sleep -Milliseconds 500
		}
		if (-not $b) { throw "XDP (ms_xdp) is not bound to $($nic.Name)" }
		if (-not $b.Enabled) { Enable-NetAdapterBinding -Name $nic.Name -ComponentID ms_xdp -ErrorAction Stop }
	}

	# The two ends: each vNIC with the address of its node, and the other vNIC with the address of the other node
	$ends = @(
		[pscustomobject]@{ Nic = $c; Address = $dialWire; Peer = $s; PeerAddress = $serveWire },
		[pscustomobject]@{ Nic = $s; Address = $serveWire; Peer = $c; PeerAddress = $dialWire }
	)

	# No DHCP, no other IPv4 address, and no duplicate address detection, whose probes the other vNIC of the same host
	# receives: each vNIC gets the address of its node and nothing else
	foreach ($e in $ends) {
		Set-NetIPInterface -InterfaceIndex $e.Nic.ifIndex -AddressFamily IPv4 -Dhcp Disabled -DadTransmits 0 -ErrorAction Stop
		Get-NetIPAddress -InterfaceIndex $e.Nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
		$null = New-NetIPAddress -InterfaceIndex $e.Nic.ifIndex -IPAddress $e.Address -PrefixLength $wireLength -ErrorAction Stop
	}
	foreach ($e in $ends) {
		$ip = $null
		$deadline = (Get-Date).AddSeconds(30)
		while ((Get-Date) -lt $deadline) {
			$ip = Get-NetIPAddress -InterfaceIndex $e.Nic.ifIndex -IPAddress $e.Address -ErrorAction SilentlyContinue
			if ($ip -and $ip.AddressState -eq 'Preferred') { break }
			Start-Sleep -Milliseconds 500
		}
		if (-not $ip -or $ip.AddressState -ne 'Preferred') { throw "$($e.Address) on $($e.Nic.Name) is not preferred: $(if ($ip) { $ip.AddressState } else { 'no address' })" }
	}

	# Each vNIC reaches the other node at the MAC of the other vNIC, with a neighbour entry that never goes stale, on a /32
	# route that wins over the route of the host to an address of its own ("Without these routing rules, applications
	# would have to explicitly bind to a source address", duonic.ps1)
	foreach ($e in $ends) {
		$null = New-NetNeighbor -InterfaceIndex $e.Nic.ifIndex -IPAddress $e.PeerAddress -LinkLayerAddress ($e.Peer.MacAddress -replace '-', '') -State Permanent -ErrorAction Stop
		$null = New-NetRoute -InterfaceIndex $e.Nic.ifIndex -DestinationPrefix "$($e.PeerAddress)/32" -NextHop '0.0.0.0' -RouteMetric 0 -PolicyStore ActiveStore -ErrorAction Stop
	}

	# The host takes the route to each node out of the vNIC of the other node, from the address of the other node
	foreach ($e in $ends) {
		$found = @(Find-NetRoute -RemoteIPAddress $e.PeerAddress -ErrorAction Stop)
		$elsewhere = @($found | Where-Object { $_.InterfaceIndex -ne $e.Nic.ifIndex })
		$from = @($found | Where-Object { $_.IPAddress -eq $e.Address })
		if ($found.Count -eq 0 -or $elsewhere.Count -gt 0 -or $from.Count -eq 0) {
			throw "the route to $($e.PeerAddress) does not leave $($e.Nic.Name) (interface $($e.Nic.ifIndex)) from $($e.Address): $(@($found | ForEach-Object { "interface $($_.InterfaceIndex) $($_.IPAddress)$($_.DestinationPrefix)" }) -join '; ')"
		}
	}

	Write-Host "the wire: the internal switch $wireSwitch; node-c's vNIC $dialNic (interface $($c.ifIndex), MAC $($c.MacAddress)) with $dialWire/$wireLength and node-s's vNIC $serveNic (interface $($s.ifIndex), MAC $($s.MacAddress)) with $serveWire/$wireLength, each with the neighbour entry and the /32 route of the other address"
	return [pscustomobject]@{ Dial = $c; Serve = $s }
}

# Start pktmon on the adapters for the TCP and UDP frames of port 8443, for the log of the dial; a capture that does not
# start is said and is no failure
function Start-Capture {
	try {
		$null = & pktmon stop 2>&1
		$null = & pktmon filter remove 2>&1
		$out = (& pktmon filter add qtip -p $port 2>&1 | Out-String)
		if ($LASTEXITCODE -ne 0) { throw "pktmon filter add: $out" }
		Remove-Item -LiteralPath $capture -Force -ErrorAction SilentlyContinue
		$out = (& pktmon start --capture --comp nics --file-name $capture 2>&1 | Out-String)
		if ($LASTEXITCODE -ne 0) { throw "pktmon start: $out" }
		return $true
	} catch {
		Write-Host "no packet capture of the dial: $($_.Exception.Message)"
		return $false
	}
}

# ... and stop it and print what it captured, as text
function Stop-Capture {
	try {
		$null = & pktmon stop 2>&1
		$null = & pktmon filter remove 2>&1
		$text = Join-Path $env:RUNNER_TEMP 'qtip-dial.txt'
		# pktmon format, or pktmon etl2txt on the builds that name it so
		$out = (& pktmon format $capture -o $text 2>&1 | Out-String)
		if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $text)) { $out = (& pktmon etl2txt $capture --out $text 2>&1 | Out-String) }
		if (-not (Test-Path -LiteralPath $text)) { throw "the capture could not be read: $out" }
		$lines = @(Get-Content -LiteralPath $text)
		Write-Host "the frames of port $port that pktmon captured on the adapters during the dial ($($lines.Count) lines, the first 400):"
		$lines | Select-Object -First 400 | ForEach-Object { Write-Host "  $_" }
	} catch {
		Write-Host "the packet capture of the dial: $($_.Exception.Message)"
	}
}

# The unicast frames that a vNIC of the wire sent and received so far, $null when it has no statistics
function Get-Frames([string] $name) {
	$st = Get-NetAdapterStatistics -Name $name -ErrorAction SilentlyContinue
	if (-not $st) { return $null }
	return [pscustomobject]@{ Sent = [int64]$st.SentUnicastPackets; Received = [int64]$st.ReceivedUnicastPackets }
}

# What the vNIC name counted between before and after, as a line
function Format-Frames([string] $name, $before, $after) {
	if (-not $before -or -not $after) { return "$name has no statistics" }
	return "$name sent $($after.Sent - $before.Sent) and received $($after.Received - $before.Received) unicast frames"
}

$os = Get-CimInstance Win32_OperatingSystem
Write-Host "$($os.Caption), build $($os.BuildNumber), on the runner $Runner, $([Environment]::ProcessorCount) processors"
if (-not (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $vpntestExe) 'msquic.dll'))) { Add-Failure 'msquic.dll is not next to vpntest' }

# The node processes take sessions on their ports: an inbound rule for vpntest, as a product that listens has its own
New-NetFirewallRule -DisplayName $firewallRule -Direction Inbound -Program $vpntestExe -Action Allow -Profile Any | Out-Null

# 1. The XDP runtime, then the checks of one process
$r = Invoke-Ranz @('install')
if ($r.Code -ne 0) { Add-Failure "ranz install exited with code $($r.Code)" }
$one = Wait-Qtip (Start-Qtip @()) 5
if (-not $one.Ok) { Add-Failure 'vpntest qtip in one process' }
if ($one.Text -notmatch 'the XDP runtime of ranz install is installed') { Add-Failure 'vpntest qtip did not find the XDP runtime that ranz install put on the runner' }

# 2. The wire between the two nodes, before they start: msquic finds the XDP interfaces of the host when it starts
try {
	$null = New-Wire
} catch {
	Add-Failure "the wire between node-c and node-s: $($_.Exception.Message)"
	Get-Service -Name vmms, vmcompute, hns -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "service $($_.Name): $($_.Status)" }
}

# 3. Two server node processes, each on its own KM-TEST adapter with XDP, joined by the wire
$stop = Join-Path $env:RUNNER_TEMP 'qtip-serve.stop'
Remove-Item -LiteralPath $stop -Force -ErrorAction SilentlyContinue
$serve = Start-Qtip @('serve', $stop)
$thumbprint = $null
$deadline = (Get-Date).AddMinutes(3)
while ((Get-Date) -lt $deadline -and -not $serve.Process.HasExited) {
	$m = [regex]::Match((Read-Shared $serve.Out), '(?m)^QTIP SERVE READY ([0-9A-Fa-f]{40})')
	if ($m.Success) {
		$thumbprint = $m.Groups[1].Value
		break
	}
	Start-Sleep -Milliseconds 500
}

if (-not $thumbprint) {
	Add-Failure 'node-s did not say QTIP SERVE READY'
} else {
	# From outside: the QTIP listener of node-s holds both the TCP and the UDP port (msquic binds the TCP one without listening)
	$id = $serve.Process.Id
	$tcp = @(Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -eq $id })
	$udp = @(Get-NetUDPEndpoint -LocalPort $port -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -eq $id })
	Write-Host "node-s (process $id) holds TCP $port in $($tcp.Count) socket(s) ($(@($tcp | ForEach-Object { "$($_.LocalAddress) $($_.State)" }) -join '; ')) and UDP $port in $($udp.Count) ($(@($udp | ForEach-Object { $_.LocalAddress }) -join '; '))"
	if ($tcp.Count -lt 1) { Add-Failure "the QTIP listener of node-s holds no TCP $port" }
	if ($udp.Count -lt 1) { Add-Failure "the QTIP listener of node-s holds no UDP $port" }

	# node-c dials node-s at its address on the wire: the QUIC-over-TCP-header link must come up
	$c0 = Get-Frames $dialNic
	$s0 = Get-Frames $serveNic
	$captured = Start-Capture
	$dial = Wait-Qtip (Start-Qtip @('dial', $thumbprint, $serveWire)) 5
	if ($captured) { Stop-Capture }
	if (-not $dial.Ok) { Add-Failure 'vpntest qtip dial: node-c' }
	$link = [regex]::Match($dial.Text, '(?m)^QTIP LINK (UP|DOWN).*$')
	$record = $(if ($link.Success) { $link.Value.Trim() } else { 'QTIP LINK: node-c printed no line of the link' })
	if (-not $link.Success -or $link.Groups[1].Value -ne 'UP') { Add-Failure "the QTIP link between node-c and node-s did not come up: $record" }
	$frames = "$(Format-Frames $dialNic $c0 (Get-Frames $dialNic)); $(Format-Frames $serveNic $s0 (Get-Frames $serveNic))"
	Write-Host "$record`n$frames"
	if ($env:GITHUB_STEP_SUMMARY) {
		"QTIP between two server node processes on $Runner, each on its own KM-TEST adapter with XDP, across an internal Hyper-V switch set up as the DuoNic pair of msquic: $record ($frames)" | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Encoding utf8 -Append
	}
}

New-Item -ItemType File -Force -Path $stop | Out-Null
$served = Wait-Qtip $serve 3
if (-not $served.Ok) { Add-Failure 'vpntest qtip serve: node-s' }
if ($thumbprint) {
	# The link reached the node: the overlay of node-s took node-c's stream from its QTIP listener, the only listener that
	# node-c dialled
	$took = [regex]::Match($served.Text, 'the overlay took ([0-9]+) streams')
	if (-not $took.Success -or [int64]$took.Groups[1].Value -lt 1) { Add-Failure 'the overlay of node-s took no stream from its QTIP listener' }
}

# 4. The wire goes, with its vNICs, then the drivers
Remove-VMSwitch -Name $wireSwitch -Force -ErrorAction SilentlyContinue
if (Get-NetAdapter -Name $dialNic, $serveNic -ErrorAction SilentlyContinue) { Add-Failure "a vNIC of the wire is still there after Remove-VMSwitch $wireSwitch" }
$r = Invoke-Ranz @('uninstall')
if ($r.Code -ne 0 -and $r.Code -ne 3010) { Add-Failure "ranz uninstall exited with code $($r.Code)" }

Remove-NetFirewallRule -DisplayName $firewallRule -ErrorAction SilentlyContinue

if ($script:failures.Count -gt 0) {
	throw "qtip: $($script:failures.Count) step(s) failed: $($script:failures -join '; ')"
}
Write-Host 'qtip: every step passed'
