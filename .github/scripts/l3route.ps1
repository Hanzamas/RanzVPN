# The step of the routed networks in the XDP job (CORE-S6-1, #80; ADR-0010 decision 1), on Windows Server 2022 and 2025 x64,
# after the QTIP step, with the drivers that the signed ranz.exe installs, never a script (ONE-3, #312). Every criterion is
# proven on this one runner with KM-TEST adapters (ADR-0002 amendment of 2026-10-21):
# 1. ranz install, which gives the ports of the routed networks XDP.
# 2. vpntest l3route xdp, as a process of its own with a time limit, with the golden files of the repository (RANZ_GOLDEN_DIR
#    names the directory of the harness family, whose sibling is the family l3route): the routed networks of the server role,
#    each on a KM-TEST adapter of its own, the routing of the kernel between them against the golden file
#    l3route_routing.txt, the forwarding of the kernel, and the NAT of a routed network to an uplink of the test through
#    WinNAT against l3route_nat.txt. The run passes when it prints L3ROUTE TEST OK, no leak and L3ROUTE GOLDEN MODE compare:
#    a run that recorded golden files in place of comparing them fails, as vpntest.ps1 fails one.
# 3. The NAT networks of WinNAT and the KM-TEST adapters of the runner before and after, as the tools of Windows show them: the
#    test leaves neither behind. Then ranz uninstall.
param(
	[Parameter(Mandatory = $true)]
	[string] $Ranz,
	[Parameter(Mandatory = $true)]
	[string] $Vpntest,
	[string] $Runner = ''
)

$ErrorActionPreference = 'Stop'
# Native exit codes are checked by hand below
$PSNativeCommandUseErrorActionPreference = $false

$ranzExe = (Resolve-Path -LiteralPath $Ranz).Path
$vpntestExe = (Resolve-Path -LiteralPath $Vpntest).Path
$script:failures = @()
# Minutes that the run is given: its own watchdog (L3ROUTE_BUDGET of src/vpntest/l3routetest.c, about seven minutes) and two more
$minutes = 9

# A step that failed: the script goes on with the next one and fails at the end
function Add-Failure([string] $step) {
	$script:failures += $step
	Write-Host "::error::$step"
}

# Run ranz.exe with arguments: its exit code and its output, standard error included
function Invoke-Ranz([string[]] $argv) {
	$out = (& $ranzExe @argv 2>&1 | Out-String)
	$code = $LASTEXITCODE
	Write-Host "ranz $($argv -join ' '): exit $code`n$out"
	return [pscustomobject]@{ Code = $code; Out = $out }
}

# The text of a file that a process may still write to
function Read-Shared([string] $path) {
	if (-not (Test-Path -LiteralPath $path)) { return '' }
	$fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
	try {
		return (New-Object System.IO.StreamReader($fs)).ReadToEnd()
	} finally {
		$fs.Dispose()
	}
}

# The NAT networks of WinNAT and the KM-TEST adapters of the runner, printed; returns the number of KM-TEST adapters
function Show-Runner([string] $when) {
	$nats = @(Get-CimInstance -Namespace 'root/StandardCimv2' -ClassName 'MSFT_NetNat' -ErrorAction SilentlyContinue)
	Write-Host "$($when): $($nats.Count) NAT networks of WinNAT"
	foreach ($n in $nats) { Write-Host "  NetNat '$($n.Name)': internal prefix $($n.InternalIPInterfaceAddressPrefix)" }
	$loops = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -like '*KM-TEST*' })
	Write-Host "$($when): $($loops.Count) KM-TEST adapters"
	foreach ($a in $loops) { Write-Host "  $($a.Name) (interface $($a.ifIndex)): MAC $($a.MacAddress), $($a.Status)" }
	return $loops.Count
}

$os = Get-CimInstance Win32_OperatingSystem
Write-Host "$($os.Caption), build $($os.BuildNumber), on the runner $Runner, $([Environment]::ProcessorCount) processors"
foreach ($name in @('vmms', 'winnat')) {
	$service = Get-Service -Name $name -ErrorAction SilentlyContinue
	Write-Host "the service ${name}: $(if ($service) { $service.Status } else { 'not there' })"
}
$before = Show-Runner 'before the test'

# 1. The drivers: the XDP runtime for the ports, and SeLow
$r = Invoke-Ranz @('install')
if ($r.Code -ne 0) { Add-Failure "ranz install exited with code $($r.Code)" }

# 2. The test, with the golden files of the repository and its output under the temp directory of the runner
$env:RANZ_GOLDEN_DIR = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\tests\golden\harness'))
$env:RANZ_HARNESS_OUT = Join-Path $env:RUNNER_TEMP 'l3route-out'
$out = Join-Path $env:RUNNER_TEMP 'l3route.out'
$err = Join-Path $env:RUNNER_TEMP 'l3route.err'
Write-Host "vpntest l3route xdp, $minutes minutes at most, the golden files of $env:RANZ_GOLDEN_DIR\..\l3route"
$p = Start-Process -FilePath $vpntestExe -ArgumentList @('l3route', 'xdp') -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError $err
# The handle keeps the exit code of the process
$null = $p.Handle
$ended = $p.WaitForExit($minutes * 60000)
if (-not $ended) {
	Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
	$ended = $p.WaitForExit(30000)
	Add-Failure "vpntest l3route did not end within $minutes minutes: stopped$(if (-not $ended) { ', and it does not end' })"
}
$text = (Read-Shared $out) + (Read-Shared $err)
Write-Host $text
if ($text -notmatch '(?m)^L3ROUTE TEST OK') { Add-Failure 'vpntest l3route xdp: the routed networks on KM-TEST adapters' }
if ($text -notmatch 'NO MEMORY LEAKS') { Add-Failure 'vpntest l3route xdp: no NO MEMORY LEAKS line' }
if ($text -cnotmatch '(?m)^L3ROUTE GOLDEN MODE compare\s*$') {
	Add-Failure 'vpntest l3route recorded its golden files in place of comparing them (L3ROUTE GOLDEN MODE update); a deliberate update runs with RANZ_UPDATE_GOLDEN=1'
}

# 3. Nothing of the test is left on the runner, then the drivers go
$after = Show-Runner 'after the test'
if ($after -gt $before) { Add-Failure "the test left $($after - $before) KM-TEST adapters on the runner" }
$r = Invoke-Ranz @('uninstall')
if ($r.Code -ne 0 -and $r.Code -ne 3010) { Add-Failure "ranz uninstall exited with code $($r.Code)" }

if ($env:GITHUB_STEP_SUMMARY) {
	$lines = @($text -split "`r?`n" | Where-Object { $_ -match '^\s+\[(PASS|FAIL)\]' })
	"Routed networks on the Windows IP stack on $($Runner): $(@($lines | Where-Object { $_ -match '\[PASS\]' }).Count) checks passed, $(@($lines | Where-Object { $_ -match '\[FAIL\]' }).Count) failed" | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Encoding utf8 -Append
}

if ($script:failures.Count -gt 0) {
	throw "l3route: $($script:failures.Count) step(s) failed: $($script:failures -join '; ')"
}
Write-Host 'l3route: every step passed'
