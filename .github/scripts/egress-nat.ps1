# The Egress tiers on the NAT of Windows of the internet exit of a VRF (SDN-12, #188; ADR-0025 decision 13), each in a step of
# its own because it changes the NAT of Windows of the runner:
# - without -Rras, vpntest egressnat on the runner as it is (build_and_test of windows.yml): the tier that the runner gives,
#   WinNAT where Hyper-V and WinNAT are present, and the proxy once a NAT network of WinNAT of another program exists;
# - with -Rras, vpntest egressrras after this script installs Routing and Remote Access as a LAN router, as an operator sets it
#   up (the egress-rras job of windows.yml, on Windows Server): the node configures RRAS NAT through MprConfig and MprAdmin.
# Before and after the test, the script prints the NAT networks of WinNAT and the NAT interfaces of RRAS of the runner, as the
# tools of Windows show them, so a run shows what the node changed and that it took it back.
param(
	[string] $BuildDir = 'build',
	[switch] $Rras
)

$ErrorActionPreference = 'Stop'

# The NAT of Windows of the runner, as Get-NetNat and netsh routing ip nat show it
function Show-Nat([string] $when) {
	$nats = @(Get-CimInstance -Namespace 'root/StandardCimv2' -ClassName 'MSFT_NetNat' -ErrorAction SilentlyContinue)
	Write-Host "$($when): $($nats.Count) NAT networks of WinNAT"
	foreach ($n in $nats) { Write-Host "  NetNat '$($n.Name)': internal prefix $($n.InternalIPInterfaceAddressPrefix)" }
	if ($Rras) {
		try {
			$out = & netsh routing ip nat show interface 2>&1 | Out-String
			Write-Host "$($when): netsh routing ip nat show interface"
			Write-Host $out
		} catch {
			Write-Host "$($when): netsh routing ip nat show interface failed: $_"
		}
	}
}

if ($Rras) {
	# Routing and Remote Access as an IPv4 router of LAN interfaces: the role service Routing of Remote Access with its tools, then
	# RRAS configured for routing only, which starts its service. The node adds the NAT routing protocol itself.
	$feature = Install-WindowsFeature -Name Routing -IncludeManagementTools
	Write-Host "Install-WindowsFeature Routing: success $($feature.Success), restart needed $($feature.RestartNeeded), exit code $($feature.ExitCode)"
	if (-not $feature.Success) { throw 'the role service Routing of Remote Access could not be installed' }
	Install-RemoteAccess -VpnType RoutingOnly
	$service = Get-Service -Name 'RemoteAccess'
	$type = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters' -Name 'RouterType' -ErrorAction SilentlyContinue).RouterType
	Write-Host "Routing and Remote Access: $($service.Status), router type $type"
	if ($service.Status -ne 'Running') { throw 'Routing and Remote Access does not run after Install-RemoteAccess -VpnType RoutingOnly' }
}

$test = if ($Rras) { 'egressrras' } else { 'egressnat' }
$vpntest = Join-Path $BuildDir 'vpntest.exe'
Show-Nat 'before the test'
$output = & $vpntest $test 2>&1 | Out-String
Write-Host $output
Show-Nat 'after the test'
if ($output -cnotmatch "$($test.ToUpper()) TEST OK") { throw "vpntest $test failed" }
Write-Host "vpntest $test passed"
