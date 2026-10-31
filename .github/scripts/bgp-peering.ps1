param([string] $BuildDir = 'build')

$ErrorActionPreference = 'Stop'
# A failing test must not stop the script before its output is printed
$PSNativeCommandUseErrorActionPreference = $false

# The BGP peering of the standard mode between three nodes (SDN-77 #357, SDN-77-R1 #531), run by the build job of windows.yml
# on x64 and arm64 after the C build:
#   - ranz (controller/cmd/ranz, Go) is built for this machine next to vpntest.exe, where each node looks for it and starts
#     its own sidecar as `ranz bgp`, as for the BGP sidecar spike (.github/scripts/bgp-spike.ps1);
#   - vpntest peering runs three nodes whose sidecars peer on TCP 179 of 127.0.0.2, 127.0.0.3 and 127.0.0.4 in a full mesh
#     of two VRFs (src/vpntest/peeringtest.c) and must print "PEERING TEST OK" and "NO MEMORY LEAKS". On a failure it prints
#     the log of each node and of its sidecar.
#   - vpntest bgpboth runs the sidecar of the operator, which listens on TCP 179 of every address (0.0.0.0 and ::), and the
#     sidecar of the peering, which listens on TCP 179 of 127.0.0.2, and then of ::1, on this host in either order of start
#     (src/vpntest/bgpbothtest.c), and must print "BGPBOTH TEST OK" and "NO MEMORY LEAKS". It shows whether the two sidecars
#     of one node bind without a clash, for IPv4 and for IPv6 tunnel endpoints.

$build = (Resolve-Path -LiteralPath $BuildDir).Path

# ranz is pure Go; the gcc of the arm64 runner builds x64 code only
$env:CGO_ENABLED = '0'

go build -trimpath -o (Join-Path $build 'ranz.exe') ./controller/cmd/ranz
if ($LASTEXITCODE -ne 0) { throw "go build of ranz exited with $LASTEXITCODE" }
& (Join-Path $build 'ranz.exe') version

$failed = @()
foreach ($test in @(@{ Name = 'peering'; Ok = 'PEERING TEST OK' }, @{ Name = 'bgpboth'; Ok = 'BGPBOTH TEST OK' })) {
	$full = (Write-Output "q\n" | & (Join-Path $build 'vpntest.exe') $test.Name | Out-String)
	$code = $LASTEXITCODE
	Write-Host $full

	$ok = ($full -cmatch ('(?m)^' + [regex]::Escape($test.Ok) + '\r?$'))
	$leak = ($full -cmatch 'NO MEMORY LEAKS')
	if (-not $ok -or -not $leak) {
		$failed += "vpntest $($test.Name) (exit code $code, $($test.Ok) $ok, NO MEMORY LEAKS $leak)"
	}
}
if ($failed.Count -ne 0) {
	throw ('failed: ' + ($failed -join '; '))
}
Write-Host 'BGP peering of the standard mode and the two sidecars of one host: ok'
