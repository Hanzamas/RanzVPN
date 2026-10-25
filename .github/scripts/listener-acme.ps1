param([string] $BuildDir = 'build')

$ErrorActionPreference = 'Stop'
# A failing test must not stop the script before its output is printed
$PSNativeCommandUseErrorActionPreference = $false

# The ACME source of the Listener of a node (SDN-45, #238), run by the build job of windows.yml on x64 and arm64 after
# the C build, as the VM job of the ticket: the node and its ACME sidecar against a test ACME server on this runner.
#   - ranz (controller/cmd/ranz, Go) is built for this machine next to vpntest.exe, where the node looks for it and
#     starts it as `ranz acme`;
#   - the test ACME server is Pebble, the one of Let's Encrypt, at the pinned version below, which go install fetches
#     through the Go module proxy and checks against the checksum database. It runs with its own test configuration
#     (test/config/pebble-config.json of its module): the directory on https://localhost:14000/dir with the certificate
#     of its test CA (test/certs/pebble.minica.pem), the HTTP-01 challenge validated on port 5002, no random sleep
#     before a validation and no nonce refused on purpose;
#   - vpntest listeneracme runs the node with its Listener against it (src/vpntest/listeneracmetest.c): the certificate
#     of localhost issued, then renewed, and must print "LISTENERACME TEST OK" and "NO MEMORY LEAKS".
# The log of Pebble goes to build/harness-out/pebble.log and into the job log.

$pebbleVersion = 'v2.10.1'
$directory = 'https://localhost:14000/dir'
$challengePort = 5002

$build = (Resolve-Path -LiteralPath $BuildDir).Path
$out = Join-Path $build 'harness-out'
$bin = Join-Path $build 'pebble'
New-Item -ItemType Directory -Force -Path $out, $bin | Out-Null

# ranz and Pebble are pure Go; the gcc of the arm64 runner builds x64 code only
$env:CGO_ENABLED = '0'

go build -trimpath -o (Join-Path $build 'ranz.exe') ./controller/cmd/ranz
if ($LASTEXITCODE -ne 0) { throw "go build of ranz exited with $LASTEXITCODE" }

$env:GOBIN = $bin
go install "github.com/letsencrypt/pebble/v2/cmd/pebble@$pebbleVersion"
if ($LASTEXITCODE -ne 0) { throw "go install of pebble $pebbleVersion exited with $LASTEXITCODE" }
Remove-Item Env:\GOBIN
$pebble = Join-Path $bin 'pebble.exe'

# The module of Pebble holds its test configuration and the certificates that it names
$module = Join-Path (go env GOMODCACHE).Trim() "github.com\letsencrypt\pebble\v2@$pebbleVersion"
$roots = Join-Path $module 'test\certs\pebble.minica.pem'
if (-not (Test-Path -LiteralPath $roots)) { throw "the module of Pebble at $module has no test\certs\pebble.minica.pem" }

$env:PEBBLE_VA_NOSLEEP = '1'
$env:PEBBLE_WFE_NONCEREJECT = '0'
$pebbleLog = Join-Path $out 'pebble.log'
$server = Start-Process -FilePath $pebble -PassThru -NoNewWindow -WorkingDirectory $module `
	-ArgumentList @('-config', 'test\config\pebble-config.json') `
	-RedirectStandardOutput $pebbleLog -RedirectStandardError (Join-Path $out 'pebble.err')

$code = 1
$full = ''
try {
	$deadline = (Get-Date).AddSeconds(30)
	while ($true) {
		$status = (& curl.exe -s -o NUL -w '%{http_code}' --cacert $roots $directory | Out-String).Trim()
		if ($status -eq '200') { break }
		if ($server.HasExited) { throw "Pebble exited with $($server.ExitCode)" }
		if ((Get-Date) -gt $deadline) { throw "Pebble does not answer on $directory" }
		Start-Sleep -Milliseconds 500
	}
	Write-Host "Pebble $pebbleVersion answers on $directory"
	$global:LASTEXITCODE = 0

	$full = (Write-Output "q\n" | & (Join-Path $build 'vpntest.exe') listeneracme $directory $roots $challengePort | Out-String)
	$code = $LASTEXITCODE
	Write-Host $full
} finally {
	if (-not $server.HasExited) { Stop-Process -Id $server.Id -Force }
	Write-Host '--- pebble.log ---'
	Get-Content -LiteralPath $pebbleLog -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
	Get-Content -LiteralPath (Join-Path $out 'pebble.err') -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
}

$ok = ($full -cmatch '(?m)^LISTENERACME TEST OK\r?$')
$leak = ($full -cmatch 'NO MEMORY LEAKS')
if (-not $ok -or -not $leak) {
	throw "vpntest listeneracme failed (exit code $code, LISTENERACME TEST OK $ok, NO MEMORY LEAKS $leak)"
}
Write-Host 'Listener with ACME: ok'
