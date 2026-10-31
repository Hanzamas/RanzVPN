param([string] $BuildDir = 'build')

$ErrorActionPreference = 'Stop'

# The Controller behind the front door of a node on the same host (SDN-73, #352; ADR-0035). Two
# processes on this runner: `ranz controller` on a test port of its own, with its handoff pipe, and
# the node of coretest's frontdoor test (coretest frontdoor-child node, src/coretest/frontdoor.c),
# whose front door listens on another test port of the loopback interface, never 443, with the owner
# table of a node beside its Controller: TLS with ALPN h2, http/1.1 or ranz-control/1, and TLS with
# the server name of the web UI (admin.frontdoor.test), go to the Controller's pipe. The checks:
# - the Controller listens on its own port as it does without a front door, and the API answers there;
# - through the front door the API answers over h2, over HTTP/1.1 and with the server name of the web
#   UI and no ALPN, and the status is the Controller's: the Controller runs the TLS handshake itself
#   (a client that offers no ALPN and no such server name, as the ranz client, stays with the node);
# - a node control stream (ALPN ranz-control/1, ranz-nodesim) through the front door reaches the
#   Controller, and the node enrols: it gets generation 1 and the API shows its acknowledgement;
# - once the Controller is gone, a connection through the front door is closed at once, and the
#   front door holds no socket of it: its counters show the refusal, and it stops at the end of its
#   input.
# The Go tests of controller/internal/port play the front door for the malformed handoffs
# (TestFrontDoorRefuses), the goroutines of a closed pipe (TestFrontDoorCloseLeavesNothing) and the
# client of each handoff, which the API and Control must see as the client dialed it
# (TestFrontDoorHandsOver, TestFrontDoorHandoffsKeepTheirClient; #534).

$bin = (Resolve-Path $BuildDir).Path
$ranz = Join-Path $bin 'ranz.exe'
$nodesim = Join-Path $bin 'ranz-nodesim.exe'
$coretest = Join-Path $bin 'coretest.exe'

$work = Join-Path $env:RUNNER_TEMP 'controller-frontdoor'
$data = Join-Path $work 'data'
New-Item -ItemType Directory -Force -Path $work | Out-Null
# adminTokenFile of controller: the secret of the admin token of the first start
$tokenFile = Join-Path $data 'admin.token'
# Toward a loopback address ranz checks the TLS fingerprint that the controller writes to this directory (AUD1-DT-13, #461)
$env:RANZ_CONTROLLER_DIR = $data
$controllerOut = Join-Path $work 'controller.out'
$controllerErr = Join-Path $work 'controller.err'

# Test ports, never 443: the Controller's own TLS port and its rqlited. The front door takes a port of
# its own (127.0.0.1:0) and prints it.
$tls = '127.0.0.1:39543'
$rqliteHttp = '127.0.0.1:39501'
$rqliteRaft = '127.0.0.1:39502'
$pipe = "\\.\pipe\ranz-ci-front-door-$PID"
# The owners of the node's table that do not run here: the signature owner and the absent one
$noSignature = "\\.\pipe\ranz-ci-front-door-$PID-signature"
$noAbsent = "\\.\pipe\ranz-ci-front-door-$PID-absent"
# The server name of the web UI in the node's table (FRONTDOOR_WEB_UI of frontdoor.c)
$webName = 'admin.frontdoor.test'

# How long the Controller may take to serve, and a node to acknowledge (s)
$waitSeconds = 120

function Invoke-Checked([string] $exe, [string[]] $argv) {
	$out = & $exe @argv
	if ($LASTEXITCODE -ne 0) { throw "$(Split-Path -Leaf $exe) $($argv -join ' ') exited with code $LASTEXITCODE" }
	return ($out -join "`n")
}

# One ranz call with the admin token on the server $server, its JSON answer as an object
function Invoke-Ranz([string] $server, [string[]] $argv) {
	return (Invoke-Checked $ranz (@('-server', $server, '-token-file', $tokenFile) + $argv)) | ConvertFrom-Json
}

function Show-Output([string] $what, [string] $file, [int] $tail) {
	if (Test-Path -LiteralPath $file) {
		Write-Host "--- ${what}:"
		Get-Content -LiteralPath $file -Tail $tail -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $_" }
	}
}

# A line of the node that starts with $prefix, within $waitSeconds
function Read-NodeLine([string] $prefix) {
	$end = (Get-Date).AddSeconds($waitSeconds)
	while ($true) {
		$task = $node.StandardOutput.ReadLineAsync()
		$left = [int][Math]::Max(0, ($end - (Get-Date)).TotalMilliseconds)
		if (-not $task.Wait($left)) { throw "the node printed no line $prefix within $waitSeconds s" }
		$line = $task.Result
		if ($null -eq $line) { throw "the node ended before it printed a line $prefix" }
		Write-Host "node: $line"
		if ($line.StartsWith('FAILED')) { throw "the node failed: $line" }
		if ($line.StartsWith($prefix)) { return $line }
	}
}

$ctl = $null
$node = $null
$cert = $null
try {
	$ctl = Start-Process -FilePath $ranz -PassThru -NoNewWindow -RedirectStandardOutput $controllerOut -RedirectStandardError $controllerErr -ArgumentList @(
		'controller', '-data', $data, '-listen', $tls, '-front-door-pipe', $pipe, '-name', 'frontdoor', '-rqlited', $env:RQLITED, '-rqlite', "http://$rqliteHttp", '-rqlite-raft', $rqliteRaft)
	# The handle keeps the exit code of the process for ExitCode
	$null = $ctl.Handle

	# The Controller on its own port: the first start writes the admin token, then the API answers it
	$own = "https://$tls"
	$end = (Get-Date).AddSeconds($waitSeconds)
	while ($true) {
		if ($ctl.HasExited) { throw "ranz controller exited with code $($ctl.ExitCode) before it served" }
		if ((Test-Path -LiteralPath $tokenFile) -and ((Get-Content -LiteralPath $tokenFile -Raw) -match "`n$")) {
			& $ranz -server $own -token-file $tokenFile status 2>$null | Out-Null
			if ($LASTEXITCODE -eq 0) { break }
		}
		if ((Get-Date) -ge $end) { throw "ranz controller did not serve on $own within $waitSeconds s" }
		Start-Sleep -Milliseconds 500
	}
	$status = Invoke-Ranz $own @('status')
	Write-Host "the Controller on its own port ${tls}: $($status | ConvertTo-Json -Compress -Depth 4)"
	if ((Get-Content -LiteralPath $controllerErr -Raw) -notmatch [regex]::Escape('msg="handoff pipe of the front door"')) { throw "the Controller did not open its handoff pipe $pipe" }
	$secret = (Get-Content -LiteralPath $tokenFile -Raw).Trim()

	# The node's certificate for the TLS of the new protocol, its key in the CNG key storage provider
	$cert = New-SelfSignedCertificate -Subject 'CN=localhost' -DnsName 'localhost' -CertStoreLocation Cert:\CurrentUser\My `
		-KeyAlgorithm ECDSA_nistP256 -Provider 'Microsoft Software Key Storage Provider' -KeyUsage DigitalSignature -NotAfter (Get-Date).AddDays(1)
	$psi = [System.Diagnostics.ProcessStartInfo]::new($coretest)
	foreach ($a in @('frontdoor-child', 'node', $cert.Thumbprint, '0', $pipe, $noSignature, $noAbsent)) { $psi.ArgumentList.Add($a) }
	$psi.UseShellExecute = $false
	$psi.RedirectStandardInput = $true
	$psi.RedirectStandardOutput = $true
	$node = [System.Diagnostics.Process]::Start($psi)
	$line = Read-NodeLine 'PORT'
	if ($line -notmatch '^PORT (\d+) KEY [0-9a-f]{64}$') { throw "the node printed '$line'" }
	$port = [int]$Matches[1]
	if ($port -eq 443) { throw 'the front door listens on 443' }
	$door = "127.0.0.1:$port"
	Write-Host "the node's front door listens on $door"

	# ALPN h2, and http/1.1: the status that answers is the Controller's, so the Controller ran the TLS
	# handshake itself (the node's TLS serves no HTTP)
	$headers = @{ Authorization = "Bearer $secret" }
	$h2 = Invoke-WebRequest -Uri "https://$door/api/v1/status" -Headers $headers -SkipCertificateCheck -HttpVersion 2.0
	if ($h2.StatusCode -ne 200 -or $h2.BaseResponse.Version.Major -ne 2 -or ($h2.Content | ConvertFrom-Json).publicKey -ne $status.publicKey) {
		throw "h2 through the front door: status $($h2.StatusCode), HTTP $($h2.BaseResponse.Version)"
	}
	Write-Host "h2 through the front door: HTTP $($h2.BaseResponse.Version), status $($h2.StatusCode)"
	$body = Join-Path $work 'http11.json'
	$http11 = (& curl.exe -s -k --http1.1 -o $body -w '%{http_code} %{http_version}' -H "Authorization: Bearer $secret" "https://$door/api/v1/status")
	if ($http11 -ne '200 1.1' -or (Get-Content -LiteralPath $body -Raw | ConvertFrom-Json).publicKey -ne $status.publicKey) { throw "http/1.1 through the front door: '$http11'" }
	Write-Host "http/1.1 through the front door: $http11"

	# The server name of the web UI and no ALPN: the web UI's page itself, and the API
	$page = (& curl.exe -s -k --no-alpn --resolve "${webName}:${port}:127.0.0.1" -o NUL -w '%{http_code}' "https://${webName}:${port}/")
	$body = Join-Path $work 'webui.json'
	$api = (& curl.exe -s -k --no-alpn --resolve "${webName}:${port}:127.0.0.1" -o $body -w '%{http_code}' -H "Authorization: Bearer $secret" "https://${webName}:${port}/api/v1/status")
	if ($page -notmatch '^(200|30[1278])$' -or $api -ne '200' -or (Get-Content -LiteralPath $body -Raw | ConvertFrom-Json).publicKey -ne $status.publicKey) { throw "the server name of the web UI through the front door: page $page, API $api" }
	Write-Host "the server name $webName without ALPN through the front door: the web UI ($page) and the API ($api)"

	# A node control stream through the front door: the node enrols and acknowledges generation 1
	$key = Join-Path $work 'node.key'
	$pub = (Invoke-Checked $nodesim @('-key', $key, '-pubkey')).Trim()
	$intent = @{ resources = @(@{ kind = 'Node'; name = 'behind-front-door'; spec = @{ publicKey = $pub } }) }
	$file = Join-Path $work 'intent.json'
	$intent | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $file -Encoding utf8NoBOM
	$applied = Invoke-Ranz $own @('apply', '-f', $file)
	Write-Host "applied: $($applied | ConvertTo-Json -Compress -Depth 4)"
	$received = Invoke-Checked $nodesim @('-key', $key, '-controller', $door, '-controller-key', $status.publicKey, '-until', '1', '-timeout', "${waitSeconds}s")
	$update = ($received.Trim() -split "`n")[0] | ConvertFrom-Json
	if ($update.generation -ne '1') { throw "the node behind the front door did not get generation 1: $received" }
	$end = (Get-Date).AddSeconds($waitSeconds)
	while ($true) {
		$n = (Invoke-Ranz $own @('get', 'nodes')).nodes | Where-Object { $_.name -eq 'behind-front-door' }
		if ($n -and $n.ackedGeneration -eq 1) { break }
		if ((Get-Date) -ge $end) { throw "the node did not acknowledge generation 1 within $waitSeconds s: $($n | ConvertTo-Json -Compress)" }
		Start-Sleep -Milliseconds 200
	}
	Write-Host 'a node control stream (ranz-control/1) through the front door: the node enrolled and acknowledged generation 1'

	# The Controller goes: a connection through the front door is closed, and the front door holds
	# no socket of it
	Stop-Process -Id $ctl.Id -Force
	$ctl.WaitForExit()
	Get-Process -Name 'rqlited' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
	$start = Get-Date
	$gone = (& curl.exe -s -k --http1.1 -o NUL -w '%{http_code}' --max-time 30 "https://$door/api/v1/status")
	$took = ((Get-Date) - $start).TotalSeconds
	if ($gone -ne '000' -or $took -ge 20) { throw "with the Controller gone, a connection through the front door answered '$gone' after $took s" }
	Write-Host ("with the Controller gone, the front door closes the connection ({0:N1} s)" -f $took)

	# The node ends at the end of its input: its counters (STATS accepted unrouted refused handed[5] sessions)
	$node.StandardInput.Close()
	$stats = Read-NodeLine 'STATS'
	$v = @($stats -split ' ' | Select-Object -Skip 1 | ForEach-Object { [long]$_ })
	if (-not $node.WaitForExit($waitSeconds * 1000) -or $node.ExitCode -ne 0) { throw "the node did not stop cleanly at the end of its input" }
	# 1 by Invoke-WebRequest over h2, 1 by curl over http/1.1 and at least 1 by the node control stream, by ALPN;
	# 2 by the server name of the web UI; and the one after the Controller went, refused
	if ($v[3] -lt 3 -or $v[4] -ne 2 -or $v[2] -lt 1 -or $v[7] -ne 0) { throw "the node's counters are $stats" }
	Write-Host "the node's front door: $($v[0]) accepted, $($v[3]) to the Controller by ALPN, $($v[4]) by the server name of its web UI, $($v[2]) refused"
} catch {
	Show-Output 'ranz controller' $controllerErr 80
	throw
} finally {
	if ($node -and -not $node.HasExited) { Stop-Process -Id $node.Id -Force -ErrorAction SilentlyContinue }
	if ($ctl -and -not $ctl.HasExited) { Stop-Process -Id $ctl.Id -Force -ErrorAction SilentlyContinue }
	Get-Process -Name 'rqlited' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
	if ($cert) { Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($cert.Thumbprint)" -DeleteKey -ErrorAction SilentlyContinue }
	$global:LASTEXITCODE = 0
}

Write-Host 'ok'
