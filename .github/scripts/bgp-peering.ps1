param([string] $BuildDir = 'build')

$ErrorActionPreference = 'Stop'
# A failing test must not stop the script before its output is printed
$PSNativeCommandUseErrorActionPreference = $false

# The BGP peering of the standard mode between three nodes (SDN-77 #357), run by the build job of windows.yml on x64 and
# arm64 after the C build:
#   - ranz (controller/cmd/ranz, Go) is built for this machine next to vpntest.exe, where each node looks for it and starts
#     its own sidecar as `ranz bgp`, as for the BGP sidecar spike (.github/scripts/bgp-spike.ps1);
#   - vpntest peering runs three nodes whose sidecars peer on TCP 179 of 127.0.0.2, 127.0.0.3 and 127.0.0.4 in a full mesh
#     of two VRFs (src/vpntest/peeringtest.c) and must print "PEERING TEST OK" and "NO MEMORY LEAKS". On a failure it prints
#     the log of each node and of its sidecar.

$build = (Resolve-Path -LiteralPath $BuildDir).Path

# ranz is pure Go; the gcc of the arm64 runner builds x64 code only
$env:CGO_ENABLED = '0'

go build -trimpath -o (Join-Path $build 'ranz.exe') ./controller/cmd/ranz
if ($LASTEXITCODE -ne 0) { throw "go build of ranz exited with $LASTEXITCODE" }
& (Join-Path $build 'ranz.exe') version

$full = (Write-Output "q\n" | & (Join-Path $build 'vpntest.exe') peering | Out-String)
$code = $LASTEXITCODE
Write-Host $full

$ok = ($full -cmatch '(?m)^PEERING TEST OK\r?$')
$leak = ($full -cmatch 'NO MEMORY LEAKS')
if (-not $ok -or -not $leak) {
	throw "vpntest peering failed (exit code $code, PEERING TEST OK $ok, NO MEMORY LEAKS $leak)"
}
Write-Host 'BGP peering of the standard mode: ok'
