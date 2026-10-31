param(
	[string] $BuildDir = 'build',
	# The architecture of this runner, x64 or arm64: what the nodes must report as their architecture (ONE-3, #312)
	[ValidateSet('x64', 'arm64')]
	[string] $Architecture = 'x64'
)

$ErrorActionPreference = 'Stop'

# The default VRF tracer (SDN-3, #179). A `ranz controller` with rqlited as its sidecar, on test ports,
# and two real nodes of the new core in vpntest (sdntrace, src/vpntest/sdntrace.c). The controller
# must:
# - create VRF default, its Network default with the automatic pool and the starter rule
#   default-allow-all at its first start (ADR-0034), and report them through the API;
# - give the two Node resources, which name no VRF, VRF default and an address each from its pool.
# The nodes must open their control streams to it, apply their state and acknowledge its
# Generation, which the API shows, and exchange ICMP echo over the in-process loopback transport;
# the API must also show the Capabilities that each node put in its Hello (ONE-3, #312): the architecture of
# this runner, and SeLow and the XDP runtime as this machine holds them, which the script reads from the
# registry and the files of Windows without the code of the node, and the Windows edition, Hyper-V and the
# Egress tier of each node (SDN-12, #188), which it reads from CIM, the services and the registry;
# once the controller stopped, they must still exchange it: they forward on the state they applied
# last. vpntest creates the file $pinged after the first echoes and waits for the control streams
# to go down; this script then checks the API and stops the controller. Once it stopped, vpntest also
# sends a stream of UDP datagrams from the host of each node to the host of the other and reports the
# rate that the overlay carried each way (SDN-53, #246). The output of the processes is read once
# they ended.

$bin = (Resolve-Path $BuildDir).Path
$ranz = Join-Path $bin 'ranz.exe'
$vpntest = Join-Path $bin 'vpntest.exe'

$work = Join-Path $env:RUNNER_TEMP 'sdn-tracer'
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
$pinged = Join-Path $work 'pinged'

# Test ports, never 443: the TLS port of the controller (the control stream and the API) and its rqlited
$tls = '127.0.0.1:39443'
$api = "https://$tls"
$rqliteHttp = '127.0.0.1:39401'
$rqliteRaft = '127.0.0.1:39402'

# The static keys of node-a and node-b in sdntrace.c: the X25519 public keys of the scalars 1 to 32 and
# 33 to 64, the keys of the controller conformance tests
$nodes = [ordered]@{ 'node-a' = 'B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw='; 'node-b' = 'WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns=' }

# How long the controller may take to serve, the nodes to join, and vpntest to finish (s)
$waitSeconds = 120

# One ranz call with the admin token, its JSON answer as an object
function Invoke-Ranz([string[]] $argv) {
	$out = & $ranz (@('-server', $api, '-token-file', $tokenFile) + $argv)
	if ($LASTEXITCODE -ne 0) { throw "ranz $($argv -join ' ') exited with code $LASTEXITCODE" }
	return ($out -join "`n") | ConvertFrom-Json
}

function Show-Output([string] $what, [string] $file, [int] $tail) {
	if (Test-Path -LiteralPath $file) {
		Write-Host "--- ${what}:"
		Get-Content -LiteralPath $file -Tail $tail -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $_" }
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
	# The first start sets the admin source allowlist that -admin-from names (AUD1-DT-6, #454), as ranz install --controller
	# passes it: loopback and the addresses of this runner. The nodes and this script come from loopback, which the list
	# always serves, and the control stream of the nodes is not behind the list, so the check runs with the list in force
	$runnerAddresses = @(Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred |
		Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } | ForEach-Object { $_.IPAddress } | Sort-Object -Unique)
	$adminFrom = (@('127.0.0.0/8') + $runnerAddresses) -join ','
	$ctl = Start-Process -FilePath $ranz -PassThru -NoNewWindow -RedirectStandardOutput $controllerOut -RedirectStandardError $controllerErr -ArgumentList @(
		'controller', '-data', $data, '-listen', $tls, '-name', 'tracer', '-admin-from', $adminFrom, '-rqlited', $env:RQLITED, '-rqlite', "http://$rqliteHttp", '-rqlite-raft', $rqliteRaft)
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
	Write-Host "controller: $($status | ConvertTo-Json -Compress -Depth 4)"
	# The list is in force: loopback and each address of this runner, which the list holds as /32
	$held = @($status.adminAccess.sources)
	if ($status.adminAccess.open -or $held -notcontains '127.0.0.0/8') { throw "the first start did not set the admin source allowlist of -admin-from ${adminFrom}: $($status.adminAccess | ConvertTo-Json -Compress)" }
	foreach ($address in $runnerAddresses) {
		if ($held -notcontains "$address/32") { throw "the admin source allowlist does not hold the address $address of this runner: $($held -join ',')" }
	}

	# The intent of the first start
	$resources = @((Invoke-Ranz @('get', 'resources')).resources)
	Write-Host "first start: $($resources | ConvertTo-Json -Compress -Depth 6)"
	$names = ($resources | ForEach-Object { "$($_.kind)/$($_.name)" }) -join ','
	if ($names -ne 'VRF/default,Network/default,Policy/default-allow-all') { throw "the first start made the intent $names" }
	$vrf = $resources[0].spec
	$network = $resources[1].spec
	$rule = $resources[2].spec
	if (-not $vrf.dns -or $vrf.mtu -ne 1280 -or $network.vrf -ne 'default' -or $network.mode -ne 'L3' -or $network.ipv4Pool -ne '100.64.0.0/10' -or
		$rule.vrf -ne 'default' -or $rule.action -ne 'allow') {
		throw "VRF default, its Network or the starter rule is not the one of a first install"
	}
	$revisions = @((Invoke-Ranz @('get', 'revisions')).revisions)
	if ($revisions.Count -ne 1 -or $revisions[0].operation -ne 'first-start') { throw "the revisions of the first start are $($revisions | ConvertTo-Json -Compress -Depth 4)" }

	# The two nodes, which name no VRF
	$intent = @{ resources = @($nodes.Keys | ForEach-Object { @{ kind = 'Node'; name = $_; spec = @{ publicKey = $nodes[$_] } } }) }
	$file = Join-Path $work 'nodes.json'
	$intent | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $file -Encoding utf8NoBOM
	$applied = Invoke-Ranz @('apply', '-f', $file)
	Write-Host "applied: $($applied | ConvertTo-Json -Compress -Depth 4)"
	$joined = (Invoke-Ranz @('get', 'resources')).resources | Where-Object { $_.kind -eq 'Node' }
	foreach ($n in $joined) {
		Write-Host "Node $($n.name): VRFs $(@($n.spec.vrfs) -join ','), addresses $($n.spec.addresses | ConvertTo-Json -Compress)"
		if ((@($n.spec.vrfs) -join ',') -ne 'default' -or $n.spec.addresses.default -notmatch '^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.') {
			throw "Node $($n.name) did not join VRF default with an address of its pool"
		}
	}

	# The real nodes join, apply their state and ping each other
	$trace = Start-Process -FilePath $vpntest -PassThru -NoNewWindow -RedirectStandardOutput $traceOut -RedirectStandardError $traceErr -ArgumentList @(
		'sdntrace', $tls, $status.publicKey, $pinged)
	$null = $trace.Handle
	$end = (Get-Date).AddSeconds($waitSeconds)
	while (-not (Test-Path -LiteralPath $pinged)) {
		if ($trace.HasExited) { throw "vpntest sdntrace exited with code $($trace.ExitCode) before the first echoes" }
		if ((Get-Date) -ge $end) { throw "vpntest sdntrace did not ping within $waitSeconds s" }
		Start-Sleep -Milliseconds 500
	}

	# The API shows the Generation each node acknowledged
	$end = (Get-Date).AddSeconds($waitSeconds)
	while ($true) {
		$states = @((Invoke-Ranz @('get', 'nodes')).nodes)
		$acked = @($states | Where-Object { $nodes.Contains($_.name) -and $_.connected -and $_.generation -ge 1 -and $_.ackedGeneration -eq $_.generation })
		if ($acked.Count -eq $nodes.Count) { break }
		if ((Get-Date) -ge $end) { throw "the API does not show both nodes connected at their acknowledged generation: $($states | ConvertTo-Json -Compress -Depth 4)" }
		Start-Sleep -Milliseconds 500
	}
	foreach ($s in $states) { Write-Host "API: node $($s.name) at generation $($s.generation), acknowledged $($s.ackedGeneration), connected $($s.connected)" }

	# The Capabilities of the nodes: a driver is there when its service is registered and its files are in
	# System32, and SeLow and the XDP runtime exist for x64 only (ADR-0022)
	$services = 'HKLM:\SYSTEM\CurrentControlSet\Services'
	$system32 = Join-Path $env:SystemRoot 'System32'
	$haveSeLow = $Architecture -eq 'x64' -and (Test-Path -LiteralPath "$services\SeLow") -and (Test-Path -LiteralPath (Join-Path $system32 'drivers\SeLow_x64.sys'))
	$haveXdp = $Architecture -eq 'x64' -and (Test-Path -LiteralPath "$services\xdp") -and (Test-Path -LiteralPath (Join-Path $system32 'drivers\xdp.sys')) -and (Test-Path -LiteralPath (Join-Path $system32 'xdpapi.dll'))
	# The Windows edition, Hyper-V and the Egress tier of each node (SDN-12, #188): the edition from the product type and the
	# SKU of the operating system as CIM reads them (Server for a host that is no workstation; the PRODUCT_* numbers of the
	# editions that the control protocol counts as Home, Pro and Enterprise), Hyper-V from the service of its Virtual Machine
	# Management, and the tier, the first that the runner supports: RRAS NAT (1) on a Windows Server whose Routing and Remote
	# Access runs as a LAN router (its service runs, and its router type has LAN routing), WinNAT (2) where Hyper-V and the
	# service of WinNAT are there, and else the proxy (3). A node counts a NAT network of WinNAT of another name than its own
	# (RanzVPN-Egress) once it looked at them, which it does when it serves WinNAT (src/Cedar/NodeEgressNat.c); the nodes of
	# the tracer are the exit of no VRF and never look, so the NAT networks that CIM lists here are printed and do not count
	$os = Get-CimInstance -ClassName Win32_OperatingSystem
	$editions = @{ 'Home' = @(98, 99, 100, 101); 'Pro' = @(48, 49, 161, 162, 164, 165); 'Enterprise' = @(4, 27, 70, 72, 84, 121, 122, 125, 126, 129, 130, 175, 188) }
	$sku = ''
	if ($os.ProductType -ne 1) {
		$sku = 'Server'
	} else {
		foreach ($edition in $editions.Keys) { if ($editions[$edition] -contains [int] $os.OperatingSystemSKU) { $sku = $edition } }
	}
	$haveHyperV = Test-Path -LiteralPath "$services\vmms"
	$rras = Get-Service -Name 'RemoteAccess' -ErrorAction SilentlyContinue
	$routerType = (Get-ItemProperty -LiteralPath "$services\RemoteAccess\Parameters" -Name 'RouterType' -ErrorAction SilentlyContinue).RouterType
	$haveRras = ($sku -eq 'Server') -and $rras -and ($rras.Status -eq 'Running') -and ($null -ne $routerType) -and (([int] $routerType -band 6) -ne 0)
	$haveWinNat = Test-Path -LiteralPath "$services\WinNat"
	$otherNats = 0
	if ($haveHyperV -and $haveWinNat) {
		try {
			$otherNats = @(Get-CimInstance -Namespace 'root/StandardCimv2' -ClassName 'MSFT_NetNat' | Where-Object { $_.Name -ne 'RanzVPN-Egress' }).Count
		} catch {
			Write-Host "this runner: the NAT networks of WinNAT cannot be listed ($_)"
		}
	}
	$tier = 3
	if ($haveRras) { $tier = 1 } elseif ($haveHyperV -and $haveWinNat) { $tier = 2 }
	Write-Host "this runner: $($os.Caption), product type $($os.ProductType), SKU $($os.OperatingSystemSKU): edition '$sku', Hyper-V $haveHyperV, Routing and Remote Access as a LAN router $haveRras, WinNAT $haveWinNat, $otherNats NAT networks of WinNAT of another program, which nodes that never looked do not count: Egress tier $tier"
	foreach ($s in $states | Where-Object { $nodes.Contains($_.name) }) {
		$caps = $s.capabilities
		if (-not $caps) { throw "the API lists no Capabilities for node $($s.name), which its Hello carries: $($s | ConvertTo-Json -Compress -Depth 4)" }
		Write-Host "API: node $($s.name) reports the architecture $($caps.architecture), SeLow $($caps.selow), XDP $($caps.xdp); this $Architecture runner has SeLow $haveSeLow and the XDP runtime $haveXdp"
		if ($caps.architecture -ne $Architecture) { throw "node $($s.name) reports the architecture '$($caps.architecture)' on a $Architecture runner" }
		if ([bool] $caps.selow -ne $haveSeLow) { throw "node $($s.name) reports SeLow $($caps.selow), and this runner has it: $haveSeLow" }
		if ([bool] $caps.xdp -ne $haveXdp) { throw "node $($s.name) reports XDP $($caps.xdp), and this runner has it: $haveXdp" }
		Write-Host "API: node $($s.name) reports the SKU '$($caps.sku)', Hyper-V $($caps.hyperV) and the Egress tier $($caps.egressTier)"
		if ("$($caps.sku)" -ne $sku) { throw "node $($s.name) reports the SKU '$($caps.sku)', and this runner is '$sku'" }
		if ([bool] $caps.hyperV -ne $haveHyperV) { throw "node $($s.name) reports Hyper-V $($caps.hyperV), and this runner has it: $haveHyperV" }
		if ([int] $caps.egressTier -ne $tier) { throw "node $($s.name) reports the Egress tier $($caps.egressTier), not $tier, the tier of this runner" }
		# The gateway of a Stretch of an L2 Network (SDN-63, #290): a Windows Server, whose VXLAN module runs on every node
		if ([bool] $caps.evpn -ne ($sku -eq 'Server')) { throw "node $($s.name) reports evpn $($caps.evpn), and this runner is '$sku': only a Windows Server can be the gateway of a Stretch" }
	}
	Write-Host 'the Hello of each node carried its Capabilities, which are the ones of this machine'

	# The controller stops; the nodes ping each other again on the state they applied
	Stop-Process -Id $ctl.Id -Force
	$ctl.WaitForExit()
	Get-Process -Name 'rqlited' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
	Write-Host 'the controller and its rqlited stopped'

	if (-not $trace.WaitForExit($waitSeconds * 1000)) { throw "vpntest sdntrace did not finish within $waitSeconds s of the stop of the controller" }
	$out = Get-Content -LiteralPath $traceOut -Raw
	Write-Host $out
	if ($out -notmatch 'SDNTRACE TEST OK') { throw 'vpntest sdntrace failed' }
	if ($out -notmatch 'NO MEMORY LEAKS') { throw 'vpntest sdntrace leaked memory' }
	# The rate between the two nodes, each way, once the controller stopped (SDN-53, #246)
	foreach ($pair in 'node-a to node-b', 'node-b to node-a') {
		if ($out -notmatch "(?m)^  \[INFO\] without the controller: ${pair}: [1-9][0-9]* datagrams of [0-9]+ bytes in [0-9]+ ms, [0-9]+ arrived, [0-9]+ refused: [0-9]+\.[0-9][0-9] Mbit/s") {
			throw "vpntest sdntrace reports no rate from $pair"
		}
	}
	Write-Host 'ok'
} catch {
	Stop-All
	Show-Output 'vpntest sdntrace' $traceOut 200
	Show-Output 'vpntest sdntrace (stderr)' $traceErr 50
	Show-Output 'ranz controller' $controllerErr 120
	throw
} finally {
	Stop-All
}
