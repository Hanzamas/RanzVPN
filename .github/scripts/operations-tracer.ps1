param(
	[string] $BuildDir = 'build'
)

$ErrorActionPreference = 'Stop'

# The operations tracer (SDN-50-N, #492): the live operations of the Controller on a harness Node. A `ranz controller` with
# rqlited as its sidecar, on test ports, and a real node of the new core in vpntest (opstrace, src/vpntest/operationstest.c).
# The script applies the Node resource node-a, with the static key of the test, and the L2 Network lan in VRF default; the
# node joins, holds lan and attaches the switch of lan, whose members client-a and client-b send ARP, IPv4 and IPv6 in VLAN
# 1 and the bridge IPv4 in VLAN 7. Then, through the API and the commands ranz mac-table and ranz ip-table of the controller:
# - the API shows that the Hello of node-a reported the Capability operations;
# - a read of the MAC table and of the IP table of lan answers ok for node-a, no longer unsupported, with the entries that
#   its switch learnt: the MAC address of each member with its VLAN and its name, and each address with its MAC address, each
#   with the time of its last frame;
# - a clear of the entry of the MAC address of client-a and of every entry of the IP table answers ok with the entries that
#   it took out, and the next reads show them gone;
# - once the test sent the traffic of the members again, the reads show the entries learnt again;
# - a table call on Network default, an L3 Network, is refused by the controller, which asks no node.
# The output of the processes is read once they ended.

$bin = (Resolve-Path $BuildDir).Path
$ranz = Join-Path $bin 'ranz.exe'
$vpntest = Join-Path $bin 'vpntest.exe'

$work = Join-Path $env:RUNNER_TEMP 'operations-tracer'
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
# The files of opstrace: it creates ready once the switch of lan learnt the traffic, sends the traffic again when again
# exists, and ends once stop exists
$ready = Join-Path $work 'ready'
$again = Join-Path $work 'again'
$stop = Join-Path $work 'stop'

# Test ports, never 443, and none of the other tracers: the TLS port of the controller (the control stream and the API) and
# its rqlited
$tls = '127.0.0.1:39643'
$api = "https://$tls"
$rqliteHttp = '127.0.0.1:39601'
$rqliteRaft = '127.0.0.1:39602'

# node-a of opstrace: the X25519 public key of its static scalars 1 to 32, as in sdntrace.c
$nodeKey = 'B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw='

# The tables that the switch of lan learns from the traffic of opstrace (operationstest.c), as the API lists them: by VLAN,
# then by address, each as "<vlan> <mac> <member>" for the MAC table and "<vlan> <address> <mac> <member>" for the IP table
$macTable = '1 02:00:00:00:50:0a client-a; 1 02:00:00:00:50:0b client-b; 7 02:00:00:00:50:1e bridge'
$ipTable = '1 10.20.0.8 02:00:00:00:50:0a client-a; 1 10.20.0.9 02:00:00:00:50:0b client-b; 1 fd00::9 02:00:00:00:50:0b client-b; 7 192.0.2.7 02:00:00:00:50:1e bridge'

# How long the controller may take to serve, the node to join, and vpntest to finish (s)
$waitSeconds = 120

# One ranz call with the admin token: its exit code and its output, the lines of stderr among them
function Invoke-RanzRaw([string[]] $argv) {
	$out = & $ranz (@('-server', $api, '-token-file', $tokenFile) + $argv) 2>&1
	return @{ Code = $LASTEXITCODE; Text = (($out | ForEach-Object { "$_" }) -join "`n") }
}

# One ranz call with the admin token, its JSON answer as an object
function Invoke-Ranz([string[]] $argv) {
	$r = Invoke-RanzRaw $argv
	if ($r.Code -ne 0) { throw "ranz $($argv -join ' ') exited with code $($r.Code): $($r.Text)" }
	return $r.Text | ConvertFrom-Json
}

# The result of node-a for a call on a table of lan, which must be ok: what ranz mac-table or ranz ip-table answers
function Get-NodeTable([string[]] $argv) {
	$res = Invoke-Ranz $argv
	$n = @($res.nodes) | Where-Object { $_.node -eq 'node-a' }
	if (-not $n) { throw "ranz $($argv -join ' ') answered no result for node-a: $($res | ConvertTo-Json -Compress -Depth 6)" }
	if ($n.status -ne 'ok') { throw "ranz $($argv -join ' '): node-a answered $($n.status) ($($n.message))" }
	return $n
}

# The entries of a read as one line, as $macTable and $ipTable write them; every entry must have the time of its last frame
function Format-Table($n, [bool] $ip) {
	$lines = @($n.entries) | ForEach-Object {
		if (-not $_.lastSeen) { throw "an entry has no time of its last frame: $($_ | ConvertTo-Json -Compress)" }
		if ($ip) { "$($_.vlan) $($_.address) $($_.mac) $($_.member)" } else { "$($_.vlan) $($_.mac) $($_.member)" }
	}
	return ($lines -join '; ')
}

# Read the table (mac or ip) of lan and check that it is $expect, with as many entries in its total
function Test-Table([string] $table, [string] $expect, [string] $what) {
	$n = Get-NodeTable @("$table-table", 'lan')
	$text = Format-Table $n ($table -eq 'ip')
	$count = @($n.entries).Count
	Write-Host "$what`: total $($n.total): $text"
	if ($text -ne $expect -or $n.total -ne $count) { throw "${what}: the $table table of lan on node-a is '$text' with the total $($n.total), not '$expect'" }
}

# Clear the table (mac or ip) of lan, one entry with its flag or every entry, and check that it took out $expect entries
function Test-Clear([string] $table, [string[]] $flags, [int] $expect, [string] $what) {
	$n = Get-NodeTable (@("$table-table", 'clear') + $flags + @('lan'))
	Write-Host "$what`: $($n.total) taken out"
	if ($n.total -ne $expect -or @($n.entries).Count -ne 0) { throw "${what}: node-a took out $($n.total) entries, not $expect" }
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

# Wait for the file of opstrace, while it runs
function Wait-File([string] $file, [string] $what) {
	$end = (Get-Date).AddSeconds($waitSeconds)
	while (-not (Test-Path -LiteralPath $file)) {
		if ($trace.HasExited) { throw "vpntest opstrace exited with code $($trace.ExitCode) before $what" }
		if ((Get-Date) -ge $end) { throw "vpntest opstrace did not get to $what within $waitSeconds s" }
		Start-Sleep -Milliseconds 200
	}
}

$ctl = $null
$trace = $null
try {
	# The controller, as the default VRF tracer starts it, with the admin source allowlist of loopback, where this script and
	# the node come from
	$ctl = Start-Process -FilePath $ranz -PassThru -NoNewWindow -RedirectStandardOutput $controllerOut -RedirectStandardError $controllerErr -ArgumentList @(
		'controller', '-data', $data, '-listen', $tls, '-name', 'operations', '-admin-from', '127.0.0.0/8', '-rqlited', $env:RQLITED, '-rqlite', "http://$rqliteHttp", '-rqlite-raft', $rqliteRaft)
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

	# node-a, which names no VRF and joins VRF default, and the L2 Network lan of VRF default
	$intent = @{ resources = @(
			@{ kind = 'Node'; name = 'node-a'; spec = @{ publicKey = $nodeKey } },
			@{ kind = 'Network'; name = 'lan'; spec = @{ vrf = 'default'; mode = 'L2' } }
		) }
	$file = Join-Path $work 'intent.json'
	$intent | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $file -Encoding utf8NoBOM
	$applied = Invoke-Ranz @('apply', '-f', $file)
	Write-Host "applied: $($applied | ConvertTo-Json -Compress -Depth 4)"

	# The harness Node joins, attaches the switch of lan and sends the traffic of its members
	$trace = Start-Process -FilePath $vpntest -PassThru -NoNewWindow -RedirectStandardOutput $traceOut -RedirectStandardError $traceErr -ArgumentList @(
		'opstrace', $tls, $status.publicKey, $ready, $again, $stop)
	$null = $trace.Handle
	Wait-File $ready 'the traffic of the members of lan'

	# Its Hello reported the Capability operations, and it acknowledged its state
	$end = (Get-Date).AddSeconds($waitSeconds)
	while ($true) {
		$node = @((Invoke-Ranz @('get', 'nodes')).nodes) | Where-Object { $_.name -eq 'node-a' }
		if ($node -and $node.connected -and $node.generation -ge 1 -and $node.ackedGeneration -eq $node.generation) { break }
		if ((Get-Date) -ge $end) { throw "the API does not show node-a connected at its acknowledged generation: $($node | ConvertTo-Json -Compress -Depth 4)" }
		Start-Sleep -Milliseconds 500
	}
	Write-Host "API: node-a at generation $($node.generation), Capabilities $($node.capabilities | ConvertTo-Json -Compress)"
	if (-not $node.capabilities.operations) { throw 'the API shows no Capability operations for node-a, which holds the L2 Network lan' }

	# The tables of lan through the controller: ok, with the entries that the switch learnt
	Test-Table 'mac' $macTable 'the MAC table of lan'
	Test-Table 'ip' $ipTable 'the IP table of lan'

	# A clear of one entry and of every entry, and the reads after them
	Test-Clear 'mac' @('-mac', '02:00:00:00:50:0a') 1 'a clear of the entry of client-a in the MAC table'
	Test-Table 'mac' '1 02:00:00:00:50:0b client-b; 7 02:00:00:00:50:1e bridge' 'the MAC table after it'
	Test-Clear 'ip' @() 4 'a clear of the IP table'
	Test-Table 'ip' '' 'the IP table after it'

	# The traffic that follows learns them again
	Remove-Item -LiteralPath $ready
	New-Item -ItemType File -Path $again | Out-Null
	Wait-File $ready 'the traffic of the members of lan again'
	Test-Table 'mac' $macTable 'the MAC table once the traffic came again'
	Test-Table 'ip' $ipTable 'the IP table once the traffic came again'

	# Network default is an L3 Network: the controller refuses the call and asks no node
	$r = Invoke-RanzRaw @('mac-table', 'default')
	Write-Host "ranz mac-table default: exit code $($r.Code): $($r.Text)"
	if ($r.Code -eq 0 -or $r.Text -notmatch 'L3 Network') { throw 'ranz mac-table default was not refused as a call on an L3 Network' }

	# The audit log holds the 8 calls on the tables that node-a answered, the reads among them
	$audit = @(@((Invoke-Ranz @('get', 'audit', '-kind', 'operation', '-limit', '1000')).records) | Where-Object { $_.kind -eq 'operation' -and $_.outcome -eq 'success' })
	Write-Host "audit: $($audit.Count) operation records with the outcome success"
	if ($audit.Count -lt 8) { throw "the audit log holds $($audit.Count) operation records with the outcome success, not the 8 calls on the tables that node-a answered" }

	New-Item -ItemType File -Path $stop | Out-Null
	if (-not $trace.WaitForExit($waitSeconds * 1000)) { throw "vpntest opstrace did not finish within $waitSeconds s of the stop file" }
	$out = Get-Content -LiteralPath $traceOut -Raw
	Write-Host $out
	if ($out -notmatch 'OPSTRACE TEST OK') { throw 'vpntest opstrace failed' }
	if ($out -notmatch 'NO MEMORY LEAKS') { throw 'vpntest opstrace leaked memory' }
	Write-Host 'ok'
} catch {
	Stop-All
	Show-Output 'vpntest opstrace' $traceOut 200
	Show-Output 'vpntest opstrace (stderr)' $traceErr 50
	Show-Output 'ranz controller' $controllerErr 120
	throw
} finally {
	Stop-All
}
