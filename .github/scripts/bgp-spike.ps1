param([string] $BuildDir = 'build')

$ErrorActionPreference = 'Stop'
# A failing test must not stop the script before its output is printed
$PSNativeCommandUseErrorActionPreference = $false

# The Windows spike of the BGP sidecar (ADR-0010, CORE-S7-1 #82; ONE-1 #310), run by the build job of
# windows.yml on x64 and arm64 after the C build:
#   - ranz (controller/cmd/ranz, Go) is built for this machine next to vpntest.exe, where the node looks for
#     it and starts it as `ranz bgp`: the sidecar is a subcommand of the one executable, not a file of its own;
#   - the router of the operator is GoBGP's own daemon gobgpd, of the GoBGP version that go.mod pins,
#     with its CLI gobgp: AS 65002, no listener of its own, dialling the sidecar on 127.0.0.1:179;
#   - vpntest bgp runs the node with its sidecar against that router (src/vpntest/bgptest.c) and must print
#     "BGP TEST OK" and "NO MEMORY LEAKS". It also reads the command line of the sidecar from its log: the
#     node started ranz.exe bgp.
#   - vpntest evpn runs the EVPN of a gateway (SDN-25 #201, src/vpntest/evpntest.c): two nodes whose sidecars
#     peer EVPN type-5 with each other on 127.0.0.1, the one the gateway and the other the BGP speaker of a
#     fabric, and a harness VTEP of the fabric on 127.0.0.2. It needs no gobgpd, runs after vpntest bgp also
#     when that failed, and must print "EVPN TEST OK" and "NO MEMORY LEAKS".
#   - vpntest stretch runs the L2 stretch of a gateway (SDN-64 #291, src/vpntest/stretchtest.c): the sidecar of
#     the gateway dials the sidecars of two leaves on 127.0.0.2 and 127.0.0.3, which carry the L2 VNI of the
#     stretched Network with EVPN type-2 and type-3 routes, and a harness VTEP on each address. It needs no
#     gobgpd, runs after vpntest evpn also when that failed, and must print "STRETCH TEST OK" and "NO MEMORY
#     LEAKS".
# The log of gobgpd goes to build/harness-out/gobgpd.log and into the job log.

$build = (Resolve-Path -LiteralPath $BuildDir).Path
$out = Join-Path $build 'harness-out'
$bin = Join-Path $build 'gobgp'
New-Item -ItemType Directory -Force -Path $out, $bin | Out-Null

# ranz and GoBGP are pure Go; the gcc of the arm64 runner builds x64 code only
$env:CGO_ENABLED = '0'

go build -trimpath -o (Join-Path $build 'ranz.exe') ./controller/cmd/ranz
if ($LASTEXITCODE -ne 0) { throw "go build of ranz exited with $LASTEXITCODE" }
$gobgpVersion = (go list -m -f '{{.Version}}' github.com/osrg/gobgp/v4 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not $gobgpVersion) { throw 'the GoBGP version of go.mod is unknown' }
& (Join-Path $build 'ranz.exe') version

$env:GOBIN = $bin
foreach ($cmd in @('gobgpd', 'gobgp')) {
	go install "github.com/osrg/gobgp/v4/cmd/${cmd}@${gobgpVersion}"
	if ($LASTEXITCODE -ne 0) { throw "go install of $cmd $gobgpVersion exited with $LASTEXITCODE" }
}
Remove-Item Env:\GOBIN
$gobgpd = Join-Path $bin 'gobgpd.exe'
$gobgp = Join-Path $bin 'gobgp.exe'

# The router: AS 65002, which dials the sidecar (AS 65001) on 127.0.0.1:179, IPv4 and IPv6 unicast
$conf = Join-Path $out 'gobgpd.toml'
@'
[global.config]
  as = 65002
  router-id = "192.0.2.2"
  port = -1

[[neighbors]]
  [neighbors.config]
    neighbor-address = "127.0.0.1"
    peer-as = 65001
  [neighbors.timers.config]
    connect-retry = 2
  [neighbors.transport.config]
    remote-port = 179
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv4-unicast"
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv6-unicast"
'@ | Set-Content -LiteralPath $conf -Encoding ascii

$routerLog = Join-Path $out 'gobgpd.log'
$router = Start-Process -FilePath $gobgpd -PassThru -NoNewWindow `
	-ArgumentList @('-f', "`"$conf`"", '-t', 'toml', '-p', '--api-hosts=127.0.0.1:50051', '--pprof-disable', '--metrics-path=') `
	-RedirectStandardOutput (Join-Path $out 'gobgpd.out') -RedirectStandardError $routerLog

$code = 1
$full = ''
try {
	$deadline = (Get-Date).AddSeconds(30)
	while ($true) {
		& $gobgp -u 127.0.0.1 -p 50051 global | Out-Null
		if ($LASTEXITCODE -eq 0) { break }
		if ($router.HasExited) { throw "gobgpd exited with $($router.ExitCode)" }
		if ((Get-Date) -gt $deadline) { throw 'gobgpd does not answer on 127.0.0.1:50051' }
		Start-Sleep -Milliseconds 500
	}
	& $gobgp -u 127.0.0.1 -p 50051 global

	$env:RANZ_GOBGP = $gobgp
	$full = (Write-Output "q\n" | & (Join-Path $build 'vpntest.exe') bgp | Out-String)
	$code = $LASTEXITCODE
	Write-Host $full
} finally {
	& $gobgp -u 127.0.0.1 -p 50051 neighbor
	if (-not $router.HasExited) { Stop-Process -Id $router.Id -Force }
	Write-Host '--- gobgpd.log ---'
	Get-Content -LiteralPath $routerLog -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
}

$ok = ($full -cmatch '(?m)^BGP TEST OK\r?$')
$leak = ($full -cmatch 'NO MEMORY LEAKS')

# The EVPN of a gateway, with the sidecars of two nodes and no gobgpd
$evpn = (Write-Output "q\n" | & (Join-Path $build 'vpntest.exe') evpn | Out-String)
$evpnCode = $LASTEXITCODE
Write-Host $evpn
$evpnOk = ($evpn -cmatch '(?m)^EVPN TEST OK\r?$')
$evpnLeak = ($evpn -cmatch 'NO MEMORY LEAKS')

# The L2 stretch of a gateway, with the sidecars of three nodes and no gobgpd
$stretch = (Write-Output "q\n" | & (Join-Path $build 'vpntest.exe') stretch | Out-String)
$stretchCode = $LASTEXITCODE
Write-Host $stretch
$stretchOk = ($stretch -cmatch '(?m)^STRETCH TEST OK\r?$')
$stretchLeak = ($stretch -cmatch 'NO MEMORY LEAKS')

if (-not $ok -or -not $leak) {
	throw "vpntest bgp failed (exit code $code, BGP TEST OK $ok, NO MEMORY LEAKS $leak)"
}
if (-not $evpnOk -or -not $evpnLeak) {
	throw "vpntest evpn failed (exit code $evpnCode, EVPN TEST OK $evpnOk, NO MEMORY LEAKS $evpnLeak)"
}
if (-not $stretchOk -or -not $stretchLeak) {
	throw "vpntest stretch failed (exit code $stretchCode, STRETCH TEST OK $stretchOk, NO MEMORY LEAKS $stretchLeak)"
}
Write-Host 'BGP sidecar spike, EVPN gateway and L2 stretch: ok'
