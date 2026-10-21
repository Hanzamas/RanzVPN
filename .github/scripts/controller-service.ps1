param([string] $BinDir = 'build\controller')

$ErrorActionPreference = 'Stop'

# ranz-controller as a Windows service (SDN-2, #178). Installed with rqlited as its sidecar and
# with plain HTTP on, the service must:
# - serve the API and the control stream on TCP 443, told apart by ALPN;
# - take an intent from `ranz apply`, push generation 1 to a simulated node (ranz-nodesim) and
#   record its acknowledgement;
# - redirect plain HTTP to HTTPS on 443 and serve nothing else there;
# - keep the intent, the acknowledged generation and its keys across a restart of the service:
#   the same Noise static key (a node with the key it had before still connects) and the same TLS
#   key (the same fingerprint) from the key storage provider;
# - write its start and stop to the Application log (event IDs 1 and 2 of
#   cmd/ranz-controller/service_windows.go) with no failure entry (event ID 3).

$bin = (Resolve-Path $BinDir).Path
$controller = Join-Path $bin 'ranz-controller.exe'
$ranz = Join-Path $bin 'ranz.exe'
$nodesim = Join-Path $bin 'ranz-nodesim.exe'

# serviceName of cmd/ranz-controller, the default -listen, and -http-listen as this check sets it
$service = 'ranz-controller'
$api = 'https://127.0.0.1'
$control = '127.0.0.1:443'
$plain = '127.0.0.1:80'

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
		if ((Get-Date) -ge $end) { throw "the API of $service did not answer within $waitSeconds s" }
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

try {
	Write-Host (Invoke-Checked $controller @('install', '-data', $data, '-rqlited', $env:RQLITED, '-http-listen', $plain))
	Start-Service -Name $service
	Wait-Api
	$status = Invoke-Ranz @('status')
	Write-Host "controller key $($status.publicKey), TLS fingerprint $($status.tlsFingerprint), control stream on $($status.controlAddress)"
	if (-not $status.tlsFingerprint) { throw 'the status names no TLS fingerprint' }

	# Plain HTTP only redirects: 301 to the same path over HTTPS on 443
	$redirect = (& curl.exe -s -o NUL -w '%{http_code} %{redirect_url}' "http://$plain/api/v1/status")
	Write-Host "plain HTTP: $redirect"
	if ($redirect -ne '301 https://127.0.0.1/api/v1/status') { throw "plain HTTP answered '$redirect', not a 301 to https://127.0.0.1/api/v1/status" }

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

	# The simulated node prints each update it applied and acknowledged as one line of JSON
	$received = Invoke-Checked $nodesim @('-key', $key, '-controller', $control, '-controller-key', $status.publicKey, '-until', '1', '-timeout', "${waitSeconds}s")
	Write-Host "ranz-nodesim received: $received"
	$update = ($received.Trim() -split "`n")[0] | ConvertFrom-Json
	if ($update.generation -ne '1' -or $update.baseGeneration -or @($update.set).Count -ne 3) {
		throw "the first update is not the full state (3 objects) as generation 1"
	}
	Wait-Acked 'branch-1' 1 | Out-Null

	Restart-Service -Name $service
	Wait-Api
	$names = (Invoke-Ranz @('get', 'resources')).resources | ForEach-Object { "$($_.kind)/$($_.name)" }
	if (($names -join ',') -ne 'VRF/corp,Network/corp-lan,Node/branch-1') { throw "the intent after the restart is $($names -join ', ')" }
	$node = Wait-Acked 'branch-1' 1
	if ($node.generation -ne 1) { throw "branch-1 is at generation $($node.generation) after the restart, not 1" }
	Write-Host "after the restart: $($names -join ', '); branch-1 at generation $($node.generation), acknowledged $($node.ackedGeneration)"
	$after = Invoke-Ranz @('status')
	if ($after.publicKey -ne $status.publicKey) { throw "the Noise static key changed across the restart: $($status.publicKey), then $($after.publicKey)" }
	if ($after.tlsFingerprint -ne $status.tlsFingerprint) { throw "the TLS key changed across the restart: $($status.tlsFingerprint), then $($after.tlsFingerprint)" }
	# The node still opens the stream with the controller key it knew before the restart
	$again = Invoke-Checked $nodesim @('-key', $key, '-controller', $control, '-controller-key', $status.publicKey, '-until', '1', '-timeout', "${waitSeconds}s")
	if ((($again.Trim() -split "`n")[0] | ConvertFrom-Json).generation -ne '1') { throw "after the restart the node did not get generation 1: $again" }
	Write-Host 'after the restart: the same Noise static key and TLS key, and the node connects with the key it knew'

	Stop-Service -Name $service
	$started = @(Get-ServiceEvents | Where-Object { $_.Id -eq 1 })
	$stopped = @(Get-ServiceEvents | Where-Object { $_.Id -eq 2 })
	$failed = @(Get-ServiceEvents | Where-Object { $_.Id -eq 3 })
	if ($started.Count -ne 2 -or $stopped.Count -ne 2) { throw "expected 2 started and 2 stopped entries, found $($started.Count) and $($stopped.Count)" }
	if ($failed.Count -gt 0) { throw "$service wrote $($failed.Count) failure entries (event ID 3)" }
	Write-Host (Invoke-Checked $controller @('uninstall'))
} catch {
	Show-Diagnostics
	throw
} finally {
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
