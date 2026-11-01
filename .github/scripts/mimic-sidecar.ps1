param([string] $BuildDir = 'build')

$ErrorActionPreference = 'Stop'
# A failing test must not stop the script before its output is printed
$PSNativeCommandUseErrorActionPreference = $false

# The mimic transport of a node over its mimicry sidecar (ADR-0023; CORE-P2-6 #406), run by the build job of
# windows.yml on x64 and arm64 after the C build:
#   - ranz (controller/cmd/ranz, Go) is built for this machine next to vpntest.exe, where the node looks for it and
#     starts it as `ranz mimic`, the sidecar of each role of the transport;
#   - vpntest mimic runs a server node and a client node over the transport on 127.0.0.1 (src/vpntest/mimictest.c) and
#     must print "MIMIC TEST OK" and "NO MEMORY LEAKS". It also runs `ranz doctor -bundle` and unpacks the bundle with the
#     tar of Windows, to look for the REALITY private key in it.

$build = (Resolve-Path -LiteralPath $BuildDir).Path

# ranz is pure Go; the gcc of the arm64 runner builds x64 code only
$env:CGO_ENABLED = '0'

go build -trimpath -o (Join-Path $build 'ranz.exe') ./controller/cmd/ranz
if ($LASTEXITCODE -ne 0) { throw "go build of ranz exited with $LASTEXITCODE" }
& (Join-Path $build 'ranz.exe') version

$full = (Write-Output "q\n" | & (Join-Path $build 'vpntest.exe') mimic | Out-String)
$code = $LASTEXITCODE
Write-Host $full

# The logs of the sidecars stay in the data directories of the test, which it deletes; the job log has the checks
$ok = ($full -cmatch '(?m)^MIMIC TEST OK\r?$')
$leak = ($full -cmatch 'NO MEMORY LEAKS')
if (-not $ok -or -not $leak) {
	throw "vpntest mimic failed (exit code $code, MIMIC TEST OK $ok, NO MEMORY LEAKS $leak)"
}
Write-Host 'Mimic transport: ok'

# vpntest hysteria: the Hysteria mode of the mimic transport (CORE-P2-4 #95) between two nodes, each with its sidecar ranz
# mimic, on a lossy link that the test makes on 127.0.0.1 (10% loss each way, 150 ms round trip, 20 Mbit/s), against the QUIC
# transport of the core, msquic with BBR, on the same link (src/vpntest/hysteriatest.c). It must print "HYSTERIA TEST OK" and
# "NO MEMORY LEAKS"; its goodput lines go into the job log.
$full = (Write-Output "q\n" | & (Join-Path $build 'vpntest.exe') hysteria | Out-String)
$code = $LASTEXITCODE
Write-Host $full

$ok = ($full -cmatch '(?m)^HYSTERIA TEST OK\r?$')
$leak = ($full -cmatch 'NO MEMORY LEAKS')
if (-not $ok -or -not $leak) {
	throw "vpntest hysteria failed (exit code $code, HYSTERIA TEST OK $ok, NO MEMORY LEAKS $leak)"
}
Write-Host 'Hysteria mode: ok'
