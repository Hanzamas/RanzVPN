param([string] $BuildDir = 'build')

$ErrorActionPreference = 'Stop'
# A failing test must not stop the script before its output is printed
$PSNativeCommandUseErrorActionPreference = $false

# The ACME source of the certificate of the Controller (SDN-92, #397), run by the build job of windows.yml on x64 and arm64
# after the step of the Listener of a node, with the same test setup (.github/scripts/listener-acme.ps1):
#   - the test ACME server is Pebble, the one of Let's Encrypt, at the pinned version below, which go install fetches
#     through the Go module proxy and checks against the checksum database. It runs with its own test configuration
#     (test/config/pebble-config.json of its module): the directory on https://localhost:14000/dir with the certificate
#     of its test CA (test/certs/pebble.minica.pem), its management interface on https://localhost:15000, which gives the
#     root of the certificates it issues, the HTTP-01 challenge validated on port 5002, no random sleep before a
#     validation and no nonce refused on purpose;
#   - go test runs TestServesACertificateOfAnACMEService of controller/internal/servercert against it: the certificate of
#     localhost issued for the key of the Controller and served as the chain that the service gave, kept across a restart,
#     renewed when it is due, and a name that Pebble refuses refused with the reason, with the challenge answered both by
#     the plain HTTP port of the Controller and by a port that the run listens on. The test is skipped without Pebble, so
#     the script fails when the output holds a skip in place of a pass.
# The log of Pebble goes to build/harness-out/pebble-controller.log and into the job log.

$pebbleVersion = 'v2.10.1'
$directory = 'https://localhost:14000/dir'
$management = 'https://localhost:15000'
$challengePort = 5002
$test = 'TestServesACertificateOfAnACMEService'

$build = (Resolve-Path -LiteralPath $BuildDir).Path
$out = Join-Path $build 'harness-out'
$bin = Join-Path $build 'pebble'
New-Item -ItemType Directory -Force -Path $out, $bin | Out-Null

# Pebble is pure Go, and so is the test; the gcc of the arm64 runner builds x64 code only
$env:CGO_ENABLED = '0'

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
$pebbleLog = Join-Path $out 'pebble-controller.log'
$server = Start-Process -FilePath $pebble -PassThru -NoNewWindow -WorkingDirectory $module `
	-ArgumentList @('-config', 'test\config\pebble-config.json') `
	-RedirectStandardOutput $pebbleLog -RedirectStandardError (Join-Path $out 'pebble-controller.err')

$code = 1
$full = ''
try {
	# Only whether Pebble answers: curl.exe of Windows checks revocation, which the test CA of Pebble has none of
	$deadline = (Get-Date).AddSeconds(30)
	while ($true) {
		$status = (& curl.exe -s -k -o NUL -w '%{http_code}' $directory | Out-String).Trim()
		if ($status -eq '200') { break }
		if ($server.HasExited) { throw "Pebble exited with $($server.ExitCode)" }
		if ((Get-Date) -gt $deadline) { throw "Pebble does not answer on $directory" }
		Start-Sleep -Milliseconds 500
	}
	Write-Host "Pebble $pebbleVersion answers on $directory"
	$global:LASTEXITCODE = 0

	$env:RANZ_PEBBLE_DIRECTORY = $directory
	$env:RANZ_PEBBLE_ROOTS = $roots
	$env:RANZ_PEBBLE_MANAGEMENT = $management
	$env:RANZ_PEBBLE_CHALLENGE_PORT = "$challengePort"
	$full = (go test -count=1 -v -run "^$test`$" ./controller/internal/servercert | Out-String)
	$code = $LASTEXITCODE
	Write-Host $full
} finally {
	if (-not $server.HasExited) { Stop-Process -Id $server.Id -Force }
	Write-Host '--- pebble-controller.log ---'
	Get-Content -LiteralPath $pebbleLog -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
	Get-Content -LiteralPath (Join-Path $out 'pebble-controller.err') -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
}

$plain = ($full -cmatch "(?m)^\s+--- PASS: $test/answered_by_the_plain_HTTP_port_of_the_Controller ")
$own = ($full -cmatch "(?m)^\s+--- PASS: $test/answered_by_a_port_of_its_own ")
$whole = ($full -cmatch "(?m)^--- PASS: $test ")
$skipped = ($full -cmatch '--- SKIP')
if ($code -ne 0 -or -not $plain -or -not $own -or -not $whole -or $skipped) {
	throw "go test of $test failed (exit code $code, plain HTTP port $plain, port of its own $own, whole test $whole, skipped $skipped)"
}
Write-Host 'Controller certificate with ACME: ok'
