param(
	[string] $BuildDir = 'build'
)

$ErrorActionPreference = 'Stop'

# The tray tracer (SDN-55, #248; seam 3 of #45 as ADR-0002 amended it on 2026-10-21): ranz tray, the tray of a laptop, with a
# real Node and a real Controller on this runner. A `ranz controller` with rqlited as its sidecar, on test ports, whose
# Intent holds the User alice with a password, and the Node of vpntest traytrace (src/vpntest/traytrace.c): the client role
# on a Wintun adapter with the pipe of its logged-in user, and no Controller settings, as a laptop has before its first
# sign-in. ranz tray runs its verbs, which do what the items of its menu do:
# - ranz tray status says that the Node is not signed in;
# - ranz tray login signs alice in, with tray-browser.ps1 as the browser (RANZ_BROWSER), which opens the authorization page
#   and signs in on it as alice: the Controller makes the Node resource of the static key of the Node a device of alice, and
#   the Node takes the keys of the Controller on its pipe (enrol) and joins it;
# - ranz tray status then shows the Node connected, under the name of its device and with its address, and the API shows the
#   device of alice connected at the Generation that it acknowledged;
# - ranz tray down and up turn the client role of the Node off and on, as ranz tray status shows; ranz tray exit with a name
#   that the Node lists as no exit node ends with the refusal of the Node;
# - once the Node is gone, ranz tray status says that the Ranz service does not run, and so does a verb, each with the exit
#   code 3, and nothing fails otherwise.
# The output of the processes is shown when a check fails.

$bin = (Resolve-Path $BuildDir).Path
$ranz = Join-Path $bin 'ranz.exe'
$vpntest = Join-Path $bin 'vpntest.exe'
$browser = Join-Path $PSScriptRoot 'tray-browser.ps1'

$work = Join-Path $env:RUNNER_TEMP 'tray-tracer'
$data = Join-Path $work 'data'
New-Item -ItemType Directory -Force -Path $work | Out-Null
# adminTokenFile of controller: the secret of the admin token of the first start
$tokenFile = Join-Path $data 'admin.token'
# Toward a loopback address ranz checks the TLS fingerprint that the controller writes to this directory (AUD1-DT-13, #461);
# ranz tray takes it from here too
$env:RANZ_CONTROLLER_DIR = $data
$controllerOut = Join-Path $work 'controller.out'
$controllerErr = Join-Path $work 'controller.err'
$traceOut = Join-Path $work 'vpntest.out'
$traceErr = Join-Path $work 'vpntest.err'
$passwordFile = Join-Path $work 'alice.password'
# The files of traytrace: it creates ready once its client role runs with its pipe, and ends once stop exists
$ready = Join-Path $work 'ready'
$stop = Join-Path $work 'stop'

# Test ports, never 443, and none of the other tracers: the TLS port of the controller (the control stream, the API and the
# logins) and its rqlited
$tls = '127.0.0.1:39743'
$api = "https://$tls"
$rqliteHttp = '127.0.0.1:39701'
$rqliteRaft = '127.0.0.1:39702'

# The pipe of the logged-in user of the Node, which ranz tray reaches with -pipe
$pipe = "ranz-traytrace-$PID"

# The user who signs in, and the browser that signs in for her: ranz tray runs the command line of RANZ_BROWSER with the
# authorization page as its last argument, and tray-browser.ps1 writes what it did to its log
$user = 'alice'
$password = 'correct horse battery staple'
$env:RANZ_TRACER_USER = $user
$env:RANZ_TRACER_PASSWORD = $password
$env:RANZ_TRACER_BROWSER_LOG = Join-Path $work 'browser.log'
$env:RANZ_BROWSER = "pwsh -NoProfile -NonInteractive -File $browser"

# What ranz tray says when the Node service does not answer (traytext.go): which of them is for the Service Control Manager
$noService = @('Ranz is not installed on this PC', 'The Ranz service is not running', 'The Ranz service is starting',
	'The Ranz service runs, but this PC has no client set up', 'The Ranz service is not running, or Ranz is not installed')

# How long the controller may take to serve, the Node to join and the tray to show it (s)
$waitSeconds = 120

# One ranz call with the admin token, its JSON answer as an object
function Invoke-Ranz([string[]] $argv) {
	$out = & $ranz (@('-server', $api, '-token-file', $tokenFile) + $argv) 2>&1
	if ($LASTEXITCODE -ne 0) { throw "ranz $($argv -join ' ') exited with code ${LASTEXITCODE}: $(($out | ForEach-Object { "$_" }) -join "`n")" }
	return (($out | ForEach-Object { "$_" }) -join "`n") | ConvertFrom-Json
}

# One ranz tray call on the pipe of the Node: its exit code, its standard output and its standard error
function Invoke-Tray([string[]] $argv) {
	$out = Join-Path $work 'tray.out'
	$err = Join-Path $work 'tray.err'
	$p = Start-Process -FilePath $ranz -PassThru -NoNewWindow -Wait -RedirectStandardOutput $out -RedirectStandardError $err -ArgumentList (@('tray', '-pipe', $pipe) + $argv)
	$r = @{ Code = $p.ExitCode; Out = (Get-Content -LiteralPath $out -Raw); Err = (Get-Content -LiteralPath $err -Raw) }
	if ($null -eq $r.Out) { $r.Out = '' }
	if ($null -eq $r.Err) { $r.Err = '' }
	Write-Host "ranz tray $($argv -join ' '): exit code $($r.Code)"
	$r.Out -split "`r?`n" | Where-Object { $_ } | ForEach-Object { Write-Host "  $_" }
	$r.Err -split "`r?`n" | Where-Object { $_ } | ForEach-Object { Write-Host "  (stderr) $_" }
	return $r
}

# The first line of what ranz tray printed
function Get-Title([string] $text) {
	return (($text -split "`r?`n") | Select-Object -First 1)
}

# Wait until ranz tray status shows the title, every line of $lines and a line that matches $pattern (when it is not empty),
# while traytrace runs
function Wait-Tray([string] $title, [string[]] $lines, [string] $what, [string] $pattern = '') {
	$end = (Get-Date).AddSeconds($waitSeconds)
	while ($true) {
		$r = Invoke-Tray @('status')
		$shown = $r.Code -eq 0 -and (Get-Title $r.Out) -eq $title
		foreach ($line in $lines) { $shown = $shown -and (($r.Out -split "`r?`n") -contains $line) }
		if ($pattern) { $shown = $shown -and (@(($r.Out -split "`r?`n") -match $pattern).Count -gt 0) }
		if ($shown) { return $r }
		if ($trace.HasExited) { throw "vpntest traytrace exited with code $($trace.ExitCode) before $what" }
		if ((Get-Date) -ge $end) { throw "ranz tray status did not show $what within $waitSeconds s" }
		Start-Sleep -Seconds 1
	}
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
	# The controller, as the default VRF tracer starts it, with the admin source allowlist of loopback, where this script, the
	# tray and the Node come from
	$ctl = Start-Process -FilePath $ranz -PassThru -NoNewWindow -RedirectStandardOutput $controllerOut -RedirectStandardError $controllerErr -ArgumentList @(
		'controller', '-data', $data, '-listen', $tls, '-name', 'tray', '-admin-from', '127.0.0.0/8', '-rqlited', $env:RQLITED, '-rqlite', "http://$rqliteHttp", '-rqlite-raft', $rqliteRaft)
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

	# The User alice with her password, which the controller keeps as a hash outside the Intent
	Invoke-Ranz @('user', 'set', $user) | Out-Null
	Set-Content -LiteralPath $passwordFile -Value $password -Encoding utf8NoBOM
	$set = Invoke-Ranz @('user', 'password', '-f', $passwordFile, $user)
	if (-not $set.passwordSet) { throw "the password of $user was not set: $($set | ConvertTo-Json -Compress)" }

	# The Node of the laptop, which has no Controller settings yet
	$trace = Start-Process -FilePath $vpntest -PassThru -NoNewWindow -RedirectStandardOutput $traceOut -RedirectStandardError $traceErr -ArgumentList @(
		'traytrace', $pipe, $ready, $stop)
	$null = $trace.Handle
	$end = (Get-Date).AddSeconds($waitSeconds)
	while (-not (Test-Path -LiteralPath $ready)) {
		if ($trace.HasExited) { throw "vpntest traytrace exited with code $($trace.ExitCode) before its client role ran" }
		if ((Get-Date) -ge $end) { throw "the client role of vpntest traytrace did not run within $waitSeconds s" }
		Start-Sleep -Milliseconds 200
	}

	# Not signed in: the tray offers the sign-in, and no exit node
	$r = Invoke-Tray @('status')
	if ($r.Code -ne 0 -or (Get-Title $r.Out) -ne 'Not signed in') { throw "ranz tray status of a Node that was not signed in: exit code $($r.Code), '$(Get-Title $r.Out)'" }

	# The sign-in in the browser, and the enrolment of the Node
	$r = Invoke-Tray @('-server', $api, '-controller-dir', $data, 'login')
	if (Test-Path -LiteralPath $env:RANZ_TRACER_BROWSER_LOG) { Get-Content -LiteralPath $env:RANZ_TRACER_BROWSER_LOG | ForEach-Object { Write-Host "  (browser) $_" } }
	if ($r.Code -ne 0 -or $r.Out -notmatch "Signed in as $user\. This PC joins as (\S+)\.") { throw "ranz tray login did not sign $user in and enrol the Node: exit code $($r.Code)" }
	$device = $Matches[1]
	Write-Host "the Node is the device $device of $user"

	# The Node joins: the tray shows it connected under the name of its device and with its address, and the API the device of
	# alice, connected at the Generation that it acknowledged. The Node takes its name from its first Generation before it
	# builds the tables of that Generation, and its address once they are in (NodeOverlayApply), so a status between the two
	# shows the name without the address: the tray waits for both.
	Wait-Tray 'Connected' @("This PC: $device") 'the Node connected as the device of alice, with its address' '^Address: \d+\.\d+\.\d+\.\d+' | Out-Null
	$users = @((Invoke-Ranz @('user', 'list')).users | Where-Object { $_.name -eq $user })
	if ($users.Count -ne 1 -or @($users[0].devices | Where-Object { $_.name -eq $device }).Count -ne 1) { throw "the API lists no device $device of ${user}: $($users | ConvertTo-Json -Compress -Depth 5)" }
	$end = (Get-Date).AddSeconds($waitSeconds)
	while ($true) {
		$node = @((Invoke-Ranz @('get', 'nodes')).nodes | Where-Object { $_.name -eq $device })
		if ($node.Count -eq 1 -and $node[0].connected -and $node[0].generation -ge 1 -and $node[0].ackedGeneration -eq $node[0].generation) { break }
		if ((Get-Date) -ge $end) { throw "the API does not show the Node $device connected at its acknowledged generation: $($node | ConvertTo-Json -Compress -Depth 4)" }
		Start-Sleep -Milliseconds 500
	}
	Write-Host "API: $device of $user connected at generation $($node[0].generation)"

	# Turn Ranz off and on, as the item of the menu does: the client role of the Node goes down and comes up again
	$r = Invoke-Tray @('down')
	if ($r.Code -ne 0 -or (Get-Title $r.Out) -ne 'Ranz is turned off') { throw "ranz tray down: exit code $($r.Code), '$(Get-Title $r.Out)'" }
	Wait-Tray 'Ranz is turned off' @() 'the Node turned off' | Out-Null
	$r = Invoke-Tray @('up')
	if ($r.Code -ne 0) { throw "ranz tray up: exit code $($r.Code)" }
	Wait-Tray 'Connected' @("This PC: $device") 'the Node connected again' | Out-Null

	# The Controller of the tracer gives the Node no exit node, so the choice of one is refused by the Node, with its reason
	$r = Invoke-Tray @('exit', 'nosuch')
	if ($r.Code -ne 1 -or $r.Err -notmatch 'no exit node named nosuch') { throw "ranz tray exit nosuch: exit code $($r.Code), not the refusal of the Node" }
	$r = Invoke-Tray @('exit', 'none')
	if ($r.Code -ne 0 -or (Get-Title $r.Out) -ne 'Connected') { throw "ranz tray exit none: exit code $($r.Code)" }

	# The Node goes away: the tray says that the Ranz service does not run, and fails in no other way
	New-Item -ItemType File -Path $stop | Out-Null
	if (-not $trace.WaitForExit($waitSeconds * 1000)) { throw "vpntest traytrace did not finish within $waitSeconds s of the stop file" }
	$out = Get-Content -LiteralPath $traceOut -Raw
	Write-Host $out
	if ($out -notmatch 'TRAYTRACE TEST OK') { throw 'vpntest traytrace failed' }
	if ($out -notmatch 'NO MEMORY LEAKS') { throw 'vpntest traytrace leaked memory' }

	$r = Invoke-Tray @('status')
	if ($r.Code -ne 3 -or $noService -notcontains (Get-Title $r.Out)) { throw "ranz tray status without the Node: exit code $($r.Code), '$(Get-Title $r.Out)', not 3 and what the tray says without the service" }
	$r = Invoke-Tray @('up')
	if ($r.Code -ne 3 -or $r.Err -notmatch '^ranz tray: ' -or $noService -notcontains ((Get-Title $r.Err) -replace '^ranz tray: ', '')) { throw "ranz tray up without the Node: exit code $($r.Code), not 3 and what the tray says without the service" }
	Write-Host 'ok'
} catch {
	Stop-All
	Show-Output 'vpntest traytrace' $traceOut 200
	Show-Output 'vpntest traytrace (stderr)' $traceErr 50
	Show-Output 'ranz controller' $controllerErr 120
	throw
} finally {
	Stop-All
}
