# The XDP job of the L2 adapter (CORE-S3-2, #72; seam 3 of #45), on Windows Server 2022 and 2025 x64: the vpntest test
# kmtest on a real Microsoft KM-TEST Loopback Adapter, with the drivers that the signed ranz.exe installs, never a script
# (ONE-3, #312; ADR-0018 amendment of 2026-10-22).
# 1. ranz install --no-xdp puts SeLow on the machine and no XDP runtime. vpntest kmtest selow quick: the node finds at run
#    time that XDP cannot bind and falls back to SeLow, which carries TX capture, RX inject and LAN discovery (ADR-0002
#    amendment of 2026-10-21).
# 2. ranz install adds the XDP runtime. The xdp.sys that it put into System32 passes signtool verify /kp, the policy of
#    Windows for kernel-mode drivers, which takes production signatures only, and is signed by Microsoft (ADR-0018
#    amendment of 2026-10-13), and its receive ring is set up (XdpRxRingSize, so that a send() with USO goes through
#    TX inspect; #72, risk R1). vpntest kmtest xdp quick: TX inspect, RX inject, LAN discovery with per-VLAN broadcast
#    limits, recovery and shutdown. The recovery that the test asks for is in the Application event log under the source
#    ranzvpnserver, and in an ETW trace session on the provider of Debug() (#72, risk R3).
# 3. The soak: two minutes of TX and RX at full rate (#72, risk R2), and on the nightly run of a Sunday an hour of it, the
#    weekly soak of risk R3.
# 4. ranz uninstall after the traffic, timed: it removes the drivers within its timeouts. ranz install again, and the
#    adapter comes back with XDP: vpntest kmtest xdp, which also runs the long parts, the paused consumer with senders
#    with USO and plain ones (#72, risk R1) and the benchmark of the batch sizes.
# 5. The measurement of senders with USO on a KM-TEST adapter without an L2 adapter and on adapters with one, without a
#    pause of the owner (vpntest kmtest xdp bare), printed for the record, then ranz uninstall.
# Each run of vpntest is a process of its own with a time limit: a run that a driver keeps from ending fails its step,
# and the job goes on with the next one.
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
$script:runs = 0
# The provider of Debug() (TRACELOGGING_DEFINE_PROVIDER of src/Mayaqua/Trace.c: the EventSource hash of "Ranz.VPN"), a
# trace session on it, and the words of the recovery that vpntest kmtest asks for (NodeL2Recover of src/Cedar/NodeL2.c)
$providerGuid = '{75b1770a-b78d-5167-6ab6-c837a52a76a2}'
$traceSession = 'RanzKmTest'
$recoveryText = 'a recovery was asked for'
# Minutes that a run of vpntest kmtest is given: its own watchdog (KMTEST_BUDGET of src/vpntest/kmtesttest.c, ten minutes
# and the soak on top) and two more
$kmtestMinutes = 12

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

# Run vpntest kmtest with arguments as a process of its own, for $minutes at most: true when it printed its OK marker and
# no leak, and ended. A run that does not end in time is stopped; a process whose I/O a driver keeps may not end even
# then, and the job goes on without it.
function Invoke-KmTest([string[]] $argv, [int] $minutes = $kmtestMinutes) {
	$script:runs++
	$out = Join-Path $env:RUNNER_TEMP "kmtest-$($script:runs).out"
	$err = Join-Path $env:RUNNER_TEMP "kmtest-$($script:runs).err"
	Write-Host "vpntest kmtest $($argv -join ' '), $minutes minutes at most"
	$p = Start-Process -FilePath $vpntestExe -ArgumentList (@('kmtest') + $argv) -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError $err
	# The handle keeps the exit code of the process
	$null = $p.Handle
	$ended = $p.WaitForExit($minutes * 60000)
	if (-not $ended) {
		Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
		$ended = $p.WaitForExit(30000)
		Write-Host "::error::vpntest kmtest $($argv -join ' ') did not end within $minutes minutes: stopped$(if (-not $ended) { ', and it does not end' })"
	}
	$text = (Read-Shared $out) + (Read-Shared $err)
	Write-Host $text
	$ok = $text -match '(?m)^KMTEST TEST OK' -and $text -match 'NO MEMORY LEAKS'
	return ($ok -and $ended)
}

# Stop a trace session: logman stop now and then fails with the WMI GUID error, HRESULT 0x80071068, while the session is
# there, and the next stop finds it, so it stops up to 3 times, 2 seconds apart, while that error comes back (as
# etw-trace.ps1 does). Returns the exit code of the last stop.
function Stop-TraceSession([string] $name) {
	$wmiGuidError = -2147020696
	for ($attempt = 1; $attempt -le 3; $attempt++) {
		& logman stop $name -ets | Out-Host
		$code = $LASTEXITCODE
		if ($code -ne $wmiGuidError) { return $code }
		if ($attempt -lt 3) { Start-Sleep -Seconds 2 }
	}
	return $code
}

# The receive ring that ranz install gives the XDP runtime (XdpRxRingSize of controller/internal/install/drivers.go):
# XDP inspects what the host sends through it, and a ring smaller than the segments of a send() with USO left the
# sender blocked (#72, risk R1)
function Test-XdpRing([string] $when) {
	$ring = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\xdp' -Name 'XdpRxRingSize' -ErrorAction SilentlyContinue).XdpRxRingSize
	Write-Host "the XDP runtime $when has XdpRxRingSize '$ring'"
	if (-not $ring -or $ring -lt 64) { Add-Failure "ranz install did not set up the receive ring of the XDP runtime $when (XdpRxRingSize '$ring')" }
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
Write-Host "$($os.Caption), build $($os.BuildNumber), on the runner $Runner, $([Environment]::ProcessorCount) processors"
try { Write-Host "Secure Boot: $(Confirm-SecureBootUEFI)" } catch { Write-Host "Secure Boot: not readable ($($_.Exception.Message))" }

# The sockets of the test take the frames that the node injects into the host: an inbound rule for vpntest, as a product
# that listens has its own
New-NetFirewallRule -DisplayName $firewallRule -Direction Inbound -Program $vpntestExe -Action Allow -Profile Any | Out-Null

# 1. SeLow alone: XDP cannot bind, and the node falls back to SeLow at run time
$r = Invoke-Ranz @('install', '--no-xdp')
if ($r.Code -ne 0) { Add-Failure "ranz install --no-xdp exited with code $($r.Code)" }
if (Test-Path -LiteralPath $xdpSys) { Add-Failure "$xdpSys is there after ranz install --no-xdp" }
if (-not (Invoke-KmTest @('selow', 'quick'))) { Add-Failure 'vpntest kmtest selow quick: the fallback to SeLow' }

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
	Test-XdpRing 'after ranz install'
}

# The run of vpntest kmtest xdp quick inside an ETW trace session on the provider of Debug() (src/Mayaqua/Trace.c), which
# receives the recovery that the test asks for, as the Application event log does
$t0 = Get-Date
$etl = Join-Path $env:RUNNER_TEMP 'kmtest.etl'
& logman start $traceSession -p $providerGuid '0xffffffffffffffff' '0xff' -o $etl -ets
if ($LASTEXITCODE -ne 0) { Add-Failure "logman could not start the trace session (exit code $LASTEXITCODE)" }
try {
	if (-not (Invoke-KmTest @('xdp', 'quick'))) { Add-Failure 'vpntest kmtest xdp quick' }
} finally {
	$stopCode = Stop-TraceSession $traceSession
}
if ($stopCode -ne 0) { Add-Failure "logman could not stop the trace session (exit code $stopCode)" }

# The recoveries of the test are in the Application event log
$events = @(Get-WinEvent -LogName Application -MaxEvents 2000 -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -eq 'ranzvpnserver' -and $_.Id -eq 10 -and $_.TimeCreated -ge $t0 })
Write-Host "$($events.Count) recoveries of an L2 adapter in the Application event log"
$events | Select-Object -First 3 | ForEach-Object { Write-Host "  $($_.TimeCreated): $($_.Message)" }
if ($events.Count -lt 1) { Add-Failure 'no recovery of an L2 adapter in the Application event log' }

# ... and in the trace session: the message is a UTF-16LE string in the payload of an event, which need not start at an
# even offset of the file, so the file is decoded from both offsets (as etw-trace.ps1 reads it)
if (-not (Test-Path -LiteralPath $etl)) {
	$written = Get-ChildItem -Path $env:RUNNER_TEMP -Filter 'kmtest*.etl' | Sort-Object LastWriteTime | Select-Object -Last 1
	if ($written) { $etl = $written.FullName }
}
if (-not (Test-Path -LiteralPath $etl)) {
	Add-Failure 'the trace session wrote no .etl file'
} else {
	$bytes = [System.IO.File]::ReadAllBytes($etl)
	$found = @(@(0, 1) | Where-Object {
			$n = $bytes.Length - $_
			[System.Text.Encoding]::Unicode.GetString($bytes, $_, $n - ($n % 2)).Contains($recoveryText)
		}).Count -gt 0
	Write-Host "trace session file: $etl ($($bytes.Length) bytes), a recovery in it: $found"
	if (-not $found) { Add-Failure "the trace session received no event with '$recoveryText'" }
}

# 3. The soak: an hour on the nightly run of a Sunday, two minutes otherwise
$soak = 120
if ($env:GITHUB_EVENT_NAME -eq 'schedule' -and (Get-Date).ToUniversalTime().DayOfWeek -eq [DayOfWeek]::Sunday) { $soak = 3600 }
if (-not (Invoke-KmTest @('xdp', 'soak', "$soak") ($kmtestMinutes + [int][Math]::Ceiling($soak / 60)))) { Add-Failure "vpntest kmtest xdp soak $soak" }

# 4. ranz uninstall after the traffic, then ranz install again, and the adapter comes back with XDP, in the run of the
# long parts
$r = Invoke-Ranz @('uninstall')
if ($r.Code -ne 0 -and $r.Code -ne 3010) { Add-Failure "ranz uninstall after the traffic exited with code $($r.Code)" }
Write-Host "ranz uninstall after $soak s of traffic took $($r.Seconds) s (exit code $($r.Code))"
$r = Invoke-Ranz @('install')
if ($r.Code -ne 0) { Add-Failure "ranz install after the uninstall exited with code $($r.Code)" }
Test-XdpRing 'after the reinstall'
if (-not (Invoke-KmTest @('xdp'))) { Add-Failure 'vpntest kmtest xdp after the reinstall' }

# 5. Senders with USO on an adapter without an L2 adapter and on adapters with one, for the record: the run checks
# nothing of the L2 adapter
if (-not (Invoke-KmTest @('xdp', 'bare') 5)) { Write-Host 'vpntest kmtest xdp bare did not end well: see its KMTEST DIAG lines' }
$r = Invoke-Ranz @('uninstall')
if ($r.Code -ne 0 -and $r.Code -ne 3010) { Add-Failure "ranz uninstall exited with code $($r.Code)" }

Remove-NetFirewallRule -DisplayName $firewallRule -ErrorAction SilentlyContinue

if ($script:failures.Count -gt 0) {
	throw "kmtest: $($script:failures.Count) step(s) failed: $($script:failures -join '; ')"
}
Write-Host 'kmtest: every step passed'
