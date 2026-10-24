# The XDP job of the L2 adapter (CORE-S3-2, #72; seam 3 of #45), on Windows Server 2022 and 2025 x64: the vpntest test
# kmtest on a real Microsoft KM-TEST Loopback Adapter, with the drivers that the signed ranz.exe installs, never a script
# (ONE-3, #312; ADR-0018 amendment of 2026-10-22).
# 1. ranz install --no-xdp puts SeLow on the machine and no XDP runtime. vpntest kmtest selow: the node finds at run time
#    that XDP cannot bind and falls back to SeLow, which carries TX capture, RX inject and LAN discovery (ADR-0002
#    amendment of 2026-10-21).
# 2. ranz install adds the XDP runtime. The xdp.sys that it put into System32 passes signtool verify /kp, the policy of
#    Windows for kernel-mode drivers, which takes production signatures only, and is signed by Microsoft (ADR-0018
#    amendment of 2026-10-13). vpntest kmtest xdp: TX inspect, RX inject, LAN discovery with per-VLAN broadcast limits,
#    the paused consumer, the benchmark of the batch sizes, recovery and shutdown. Each recovery is in the Application
#    event log under the source ranzvpnserver.
# 3. The soak: two minutes of TX and RX at full rate (#72, risk R2), and on the nightly run of a Sunday an hour of it, the
#    weekly soak of risk R3.
# 4. ranz uninstall after the traffic, timed: it removes the drivers within its timeouts. ranz install again, and the
#    adapter comes back with XDP (vpntest kmtest xdp quick). ranz uninstall last.
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
$xdpSys = Join-Path $env:SystemRoot 'System32\drivers\xdp.sys'
$firewallRule = 'ranz-kmtest'
$script:failures = @()

# A step that failed: the job goes on with the next one and fails at the end
function Add-Failure([string] $step) {
	$script:failures += $step
	Write-Host "::error::$step"
}

# Run ranz.exe with arguments: its exit code and its output, standard error included
function Invoke-Ranz([string[]] $argv) {
	$t0 = Get-Date
	$out = (& $ranzExe @argv 2>&1 | Out-String)
	$code = $LASTEXITCODE
	$took = [int]((Get-Date) - $t0).TotalSeconds
	Write-Host "ranz $($argv -join ' '): exit $code after $took s`n$out"
	return [pscustomobject]@{ Code = $code; Out = $out; Seconds = $took }
}

# Run vpntest kmtest with arguments: true when it printed its OK marker and no leak
function Invoke-KmTest([string[]] $argv) {
	$out = @(Write-Output "q\n" | & $vpntestExe kmtest @argv)
	$out | ForEach-Object { Write-Host $_ }
	$ok = @($out | Select-String -CaseSensitive -Pattern '^KMTEST TEST OK').Count -eq 1
	$leak = @($out | Select-String -CaseSensitive -Pattern 'NO MEMORY LEAKS').Count -eq 1
	return ($ok -and $leak)
}

# signtool.exe of the Windows SDK: the highest version under the Windows Kits, x64 build
function Get-SignTool {
	$roots = @("${env:ProgramFiles(x86)}\Windows Kits\10\bin", "${env:ProgramFiles}\Windows Kits\10\bin")
	$found = foreach ($r in $roots) {
		if (Test-Path -LiteralPath $r) {
			Get-ChildItem -LiteralPath $r -Recurse -Filter 'signtool.exe' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' }
		}
	}
	$tool = $found | Sort-Object FullName -Descending | Select-Object -First 1
	if (-not $tool) { throw 'signtool.exe was not found under the Windows Kits' }
	return $tool.FullName
}

$os = Get-CimInstance Win32_OperatingSystem
Write-Host "$($os.Caption), build $($os.BuildNumber), on the runner $Runner"
try { Write-Host "Secure Boot: $(Confirm-SecureBootUEFI)" } catch { Write-Host "Secure Boot: not readable ($($_.Exception.Message))" }

# The sockets of the test take the frames that the node injects into the host: an inbound rule for vpntest, as a product
# that listens has its own
New-NetFirewallRule -DisplayName $firewallRule -Direction Inbound -Program $vpntestExe -Action Allow -Profile Any | Out-Null

# 1. SeLow alone: XDP cannot bind, and the node falls back to SeLow at run time
$r = Invoke-Ranz @('install', '--no-xdp')
if ($r.Code -ne 0) { Add-Failure "ranz install --no-xdp exited with code $($r.Code)" }
if (Test-Path -LiteralPath $xdpSys) { Add-Failure "$xdpSys is there after ranz install --no-xdp" }
if (-not (Invoke-KmTest @('selow', 'quick'))) { Add-Failure 'vpntest kmtest selow: the fallback to SeLow' }

# 2. The XDP runtime, production-signed
$r = Invoke-Ranz @('install')
if ($r.Code -ne 0) { Add-Failure "ranz install exited with code $($r.Code)" }
if (-not (Test-Path -LiteralPath $xdpSys)) {
	Add-Failure "ranz install put no $xdpSys on the machine"
} else {
	$signtool = Get-SignTool
	$verify = (& $signtool verify /kp /v $xdpSys 2>&1 | Out-String)
	$code = $LASTEXITCODE
	Write-Host $verify
	if ($code -ne 0) { Add-Failure "signtool verify /kp does not pass for $xdpSys (exit code $code)" } else { Write-Host "signtool verify /kp passes for $xdpSys" }
	$signer = (Get-AuthenticodeSignature -LiteralPath $xdpSys).SignerCertificate.Subject
	Write-Host "xdp.sys: signed by $signer"
	if ($signer -notmatch 'O=Microsoft Corporation') { Add-Failure "$xdpSys is not signed by Microsoft: $signer" }
	Write-Host "the xdp service: $((& sc.exe query xdp | Out-String).Trim())"
}

$t0 = Get-Date
if (-not (Invoke-KmTest @('xdp'))) { Add-Failure 'vpntest kmtest xdp' }

# The recoveries of the test are in the Application event log
$events = @(Get-WinEvent -LogName Application -MaxEvents 2000 -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -eq 'ranzvpnserver' -and $_.Id -eq 10 -and $_.TimeCreated -ge $t0 })
Write-Host "$($events.Count) recoveries of an L2 adapter in the Application event log"
$events | Select-Object -First 3 | ForEach-Object { Write-Host "  $($_.TimeCreated): $($_.Message)" }
if ($events.Count -lt 1) { Add-Failure 'no recovery of an L2 adapter in the Application event log' }

# 3. The soak: an hour on the nightly run of a Sunday, two minutes otherwise
$soak = 120
if ($env:GITHUB_EVENT_NAME -eq 'schedule' -and (Get-Date).ToUniversalTime().DayOfWeek -eq [DayOfWeek]::Sunday) { $soak = 3600 }
if (-not (Invoke-KmTest @('xdp', 'soak', "$soak"))) { Add-Failure "vpntest kmtest xdp soak $soak" }

# 4. ranz uninstall after the traffic, then ranz install again, and the adapter comes back with XDP
$r = Invoke-Ranz @('uninstall')
if ($r.Code -ne 0 -and $r.Code -ne 3010) { Add-Failure "ranz uninstall after the traffic exited with code $($r.Code)" }
Write-Host "ranz uninstall after $soak s of traffic took $($r.Seconds) s (exit code $($r.Code))"
$r = Invoke-Ranz @('install')
if ($r.Code -ne 0) { Add-Failure "ranz install after the uninstall exited with code $($r.Code)" }
if (-not (Invoke-KmTest @('xdp', 'quick'))) { Add-Failure 'vpntest kmtest xdp quick after the reinstall' }
$r = Invoke-Ranz @('uninstall')
if ($r.Code -ne 0 -and $r.Code -ne 3010) { Add-Failure "ranz uninstall exited with code $($r.Code)" }

Remove-NetFirewallRule -DisplayName $firewallRule -ErrorAction SilentlyContinue

if ($script:failures.Count -gt 0) {
	throw "kmtest: $($script:failures.Count) step(s) failed: $($script:failures -join '; ')"
}
Write-Host 'kmtest: every step passed'
