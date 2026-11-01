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

# TEMPORARY, for SDN-77-R3 (#570), and taken out before the pull request is ready: vpntest peering once more, with the ranz.exe of
# origin/integration, whose sidecar has none of the filters of the pull request, in place of the one of this head. It has to fail at
# the hostile peer of Generation 9, whose path hides the LAN of node-c at node-a, and at the flood, which no sidecar of integration
# ends; the lines of the cases and of the failed checks are printed.
$integration = Join-Path $env:RUNNER_TEMP 'ranz-of-integration'
$thisRanz = Join-Path $build 'ranz.exe'
$keptRanz = Join-Path $build 'ranz-of-this-head.exe'
git fetch --no-tags --depth=1 origin integration
if ($LASTEXITCODE -ne 0) { throw "git fetch of integration exited with $LASTEXITCODE" }
git worktree add --detach $integration FETCH_HEAD
if ($LASTEXITCODE -ne 0) { throw "git worktree add exited with $LASTEXITCODE" }
Move-Item -LiteralPath $thisRanz -Destination $keptRanz
try {
	go -C $integration build -trimpath -o $thisRanz ./controller/cmd/ranz
	if ($LASTEXITCODE -ne 0) { throw "go build of the ranz of integration exited with $LASTEXITCODE" }
	& $thisRanz version
	$old = (Write-Output "q\n" | & (Join-Path $build 'vpntest.exe') peering | Out-String)
	Write-Host ((($old -split '\r?\n') | Where-Object { $_ -match '^\[' -or $_ -match '\[FAIL\]' }) -join "`n")
	# What the node log and the sidecar log of each node, which the test prints after a failed check, say of the LAN of node-c
	Write-Host ((($old -split '\r?\n') | Where-Object { $_ -match '192\.168\.3\.0/24' -and $_ -match 'BGP peering: route|not taken' } | Select-Object -First 40) -join "`n")
	$hostile = ($old -cmatch '\[FAIL\]\s+Node-a keeps the LAN 192\.168\.3\.0/24 of node-c')
	$flood = ($old -cmatch '\[FAIL\]\s+The sidecar of node-a ends its session with node-b')
	Write-Host "vpntest peering with the ranz.exe of integration: the hostile peer failed $hostile, the flood failed $flood"
	if (-not $hostile -or -not $flood) {
		$failed += 'vpntest peering with the ranz.exe of integration did not fail at the hostile peer and at the flood'
	}
} finally {
	Remove-Item -LiteralPath $thisRanz -ErrorAction SilentlyContinue
	Move-Item -LiteralPath $keptRanz -Destination $thisRanz
	git worktree remove --force $integration
}

if ($failed.Count -ne 0) {
	throw ('failed: ' + ($failed -join '; '))
}
Write-Host 'BGP peering of the standard mode and the two sidecars of one host: ok'
