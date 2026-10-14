# SeLow vs XDP benchmark runner for a GitHub-hosted Windows runner (admin,
# disposable VM). Spike only.
#
#   1. One KM-TEST Loopback Adapter, 10.99.0.1/24, permanent neighbor 10.99.0.2.
#   2. SeLow phase: install the SeLow NDIS protocol driver with netcfg (the
#      same INetCfg install as InstallNdisProtocolDriver in
#      src/Cedar/Win32Com.cpp) and benchmark it. XDP is not installed yet.
#   3. XDP phase: unbind SeLow from the adapter, install XDP, benchmark it.
#
# A health probe (plain send() for 0.5 s, no backend) runs after every test,
# so a test that breaks the adapter's TX path is named in the log. Every
# external command has a timeout, so a hung NDIS unbind cannot eat the job.
param(
    [Parameter(Mandatory)] [string]$Bin,
    [Parameter(Mandatory)] [string]$XdpRuntime,
    [Parameter(Mandatory)] [string]$SeLowDir,
    [Parameter(Mandatory)] [string]$LogDir,
    [int]$Seconds = 5,
    [int]$Runs = 5,
    [int[]]$Sizes = @(64, 512, 1500),
    [int]$Receivers = 2,
    [string[]]$Backends = @('selow', 'xdp'),
    [switch]$Diag
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force $LogDir | Out-Null
$LogDir = (Resolve-Path $LogDir).Path
Start-Transcript -Path (Join-Path $LogDir 'run.txt') | Out-Null
$Bin = (Resolve-Path $Bin).Path
$spbench = Join-Path $Bin 'spbench.exe'
$benchLog = Join-Path $LogDir 'spbench.txt'
$csv = Join-Path $LogDir 'results.csv'
$tmp = Join-Path $LogDir 'tmp'
New-Item -ItemType Directory -Force $tmp | Out-Null
$osTag = $env:ImageOS
if (-not $osTag) { $osTag = (Get-CimInstance Win32_OperatingSystem).BuildNumber }
$tStart = Get-Date

function Section($t) { Write-Host "`n===== $t =====" }

# Runs an executable with a timeout. Returns @{ Code; Out; TimedOut }.
$script:execN = 0
function Invoke-Exe([string]$exe, [string[]]$argv, [int]$timeoutSec) {
    $script:execN++
    $o = Join-Path $tmp "out$($script:execN).txt"
    $e = Join-Path $tmp "err$($script:execN).txt"
    $quoted = $argv | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }
    $p = Start-Process -FilePath $exe -ArgumentList $quoted -PassThru -NoNewWindow -RedirectStandardOutput $o -RedirectStandardError $e
    $null = $p.Handle # caches the handle, so ExitCode is readable after exit
    $done = $p.WaitForExit($timeoutSec * 1000)
    if ($done) { $p.WaitForExit() }
    $lines = @()
    foreach ($f in $o, $e) { if (Test-Path $f) { $lines += @(Get-Content $f) } }
    $code = if ($done) { $p.ExitCode } else { -1 }
    return @{ Code = $code; Out = $lines; TimedOut = (-not $done) }
}

# Runs a PowerShell command line in a child pwsh with a timeout.
function Invoke-Ps([string]$cmd, [int]$timeoutSec) {
    $r = Invoke-Exe 'pwsh' @('-NoProfile', '-NonInteractive', '-Command', $cmd) $timeoutSec
    $r.Out | ForEach-Object { Write-Host "  $_" }
    if ($r.TimedOut) { Write-Host "TIMEOUT after ${timeoutSec}s: $cmd" }
    return $r
}

Section 'OS and CPU'
Get-CimInstance Win32_OperatingSystem | Format-List Caption, Version, BuildNumber, OSArchitecture
Get-CimInstance Win32_Processor | Format-List Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed
Get-CimInstance Win32_ComputerSystem | Format-List Model, TotalPhysicalMemory
try { "SecureBoot: $(Confirm-SecureBootUEFI)" } catch { "SecureBoot: n/a ($($_.Exception.Message))" }
bcdedit /enum '{current}' | Select-String -Pattern 'testsigning|nointegritychecks|hypervisor'
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue |
    Format-List VirtualizationBasedSecurityStatus, SecurityServicesConfigured, SecurityServicesRunning, CodeIntegrityPolicyEnforcementStatus
$ncpu = [Environment]::ProcessorCount
"logical CPUs: $ncpu"

Section 'KM-TEST Loopback install'
& (Join-Path $Bin 'mkloop.exe')
"mkloop exit=$LASTEXITCODE"
$a = $null
for ($i = 0; $i -lt 30 -and -not $a; $i++) {
    $a = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object InterfaceDescription -like '*KM-TEST*' | Select-Object -First 1
    if (-not $a) { Start-Sleep 1 }
}
if (-not $a) {
    'RESULT LOOPBACK FAIL reason=adapter-not-created'
    Stop-Transcript | Out-Null
    exit 3
}
$idx = $a.ifIndex
$name = $a.Name
$a | Format-List Name, InterfaceDescription, InterfaceGuid, ifIndex, Status, MacAddress, LinkSpeed, DriverFileName, MtuSize
'RESULT LOOPBACK PASS'

Section 'Address, neighbor, firewall'
New-NetIPAddress -InterfaceIndex $idx -IPAddress 10.99.0.1 -PrefixLength 24 | Out-Null
New-NetNeighbor -InterfaceIndex $idx -IPAddress 10.99.0.2 -LinkLayerAddress '02-00-00-00-00-02' -State Permanent | Out-Null
Set-NetFirewallProfile -All -Enabled False
Get-NetNeighbor -InterfaceIndex $idx -AddressFamily IPv4 | Format-Table -AutoSize IPAddress, LinkLayerAddress, State

Section 'Adapter offloads (USO is done in software by TCPIP when the adapter has none)'
foreach ($c in 'Get-NetAdapterUso', 'Get-NetAdapterLso', 'Get-NetAdapterChecksumOffload', 'Get-NetAdapterRss') {
    if (Get-Command $c -ErrorAction SilentlyContinue) {
        "--- $c"
        & $c -Name $name -ErrorAction SilentlyContinue | Format-List * | Out-String -Width 200 | ForEach-Object { $_.Trim() }
    } else { "--- $c : cmdlet not present" }
}
netsh int udp show global
Get-NetAdapterAdvancedProperty -Name $name -ErrorAction SilentlyContinue | Format-Table -AutoSize DisplayName, DisplayValue, RegistryKeyword

function Wait-Ready {
    for ($i = 0; $i -lt 40; $i++) {
        $ad = Get-NetAdapter -InterfaceIndex $idx -ErrorAction SilentlyContinue
        $ip = Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -IPAddress 10.99.0.1 -ErrorAction SilentlyContinue
        if ($ad.Status -eq 'Up' -and $ip.AddressState -eq 'Preferred') { return }
        Start-Sleep -Milliseconds 500
    }
    Write-Host "WARN adapter not ready: status=$($ad.Status) ip=$($ip.AddressState)"
}

$cols = 'os', 'run', 'backend', 'dir', 'len', 'gen', 'threads', 'pin', 'secs', 'gen_calls_ps', 'gen_pps', 'pps', 'mbps',
    'loss_pct', 'other_ps', 'dups', 'gen_errors', 'cpu_sys', 'cpu_sys_pct', 'cpu_sys_ticks', 'cpu_gen', 'cpu_cap', 'cpu_proc',
    'cores_per_mpps', 'ncpu', 'tsc_mhz', 'cap_sleep_ms', 'segs', 'gen_err', 'cap_calls', 'cap_errors', 'xdp_rx_dropped',
    'receivers', 'status', 'health_after'
$rows = New-Object System.Collections.Generic.List[object]
$script:broken = 0

function Invoke-Probe([string]$after) {
    $r = Invoke-Exe $spbench @('-d', 'probe', '-i', $idx, '-s', '1', '-w', '0') 60
    $line = $r.Out | Where-Object { $_ -like 'PROBE *' } | Select-Object -Last 1
    if (-not $line) { $line = "PROBE status=none exit=$($r.Code) timedout=$($r.TimedOut)" }
    Add-Content -Path $benchLog -Value "### probe after $after : $line"
    $st = if ($line -match 'status=(\w+)') { $Matches[1] } else { 'none' }
    if ($st -ne 'ok') {
        $script:broken++
        Write-Host "HEALTH BROKEN after $after : $line"
    } else { $script:broken = 0 }
    return $st
}

function Invoke-Bench([int]$run, [string]$b, [string]$dir, [int]$len, [string]$gen, [int]$threads, [bool]$pin, [int]$k) {
    $argv = @('-b', $b, '-d', $dir, '-i', $idx, '-l', $len, '-s', $Seconds, '-t', $threads, '-r', $Receivers)
    if ($dir -eq 'tx') { $argv += @('-g', $gen) }
    if ($pin) { $argv += '-p' }
    if ($k -gt 0) { $argv += @('-k', $k) }
    $r = Invoke-Exe $spbench $argv ($Seconds + 60)
    $out = $r.Out
    Add-Content -Path $benchLog -Value (@("### run=$run spbench $($argv -join ' ') exit=$($r.Code) timedout=$($r.TimedOut)") + $out)
    $kv = [ordered]@{}
    foreach ($c in $cols) { $kv[$c] = '' }
    $kv.os = $osTag; $kv.run = $run; $kv.backend = $b; $kv.dir = $dir; $kv.len = $len; $kv.gen = $gen; $kv.threads = $threads
    $line = $out | Where-Object { $_ -like 'BENCH *' } | Select-Object -Last 1
    if ($line) {
        foreach ($p in ($line.Substring(6) -split ' ')) {
            $q = $p -split '=', 2
            if ($q.Count -eq 2 -and $kv.Contains($q[0])) { $kv[$q[0]] = $q[1] }
        }
        $kv.status = 'ok'
    } else {
        $f = $out | Where-Object { $_ -like 'BENCH_FAIL *' } | Select-Object -Last 1
        $kv.status = if ($f) { ($f -replace '.*reason=', 'fail:') } elseif ($r.TimedOut) { 'fail:timeout' } else { "fail:exit$($r.Code)" }
    }
    $label = "$b $dir $len $gen x$threads$(if ($k) { " k=$k" })"
    $kv.health_after = Invoke-Probe $label
    if ($k -gt 0) { $kv.gen = "$($kv.gen)-capsleep$k" }
    $rows.Add([pscustomobject]$kv)
    Write-Host ("run={0} {1,-5} {2} len={3,-4} gen={4,-16} t={5} gen_pps={6,9} pps={7,9} mbps={8,8} loss={9}% sys={10} gen={11} cap={12} c/Mpps={13} {14} health={15}" -f
        $run, $b, $dir, $len, $kv.gen, $kv.threads, $kv.gen_pps, $kv.pps, $kv.mbps, $kv.loss_pct, $kv.cpu_sys, $kv.cpu_gen,
        $kv.cpu_cap, $kv.cores_per_mpps, $kv.status, $kv.health_after)
}

# rx first, then the tx generators from lightest to heaviest.
$tests = @(
    @{ dir = 'rx'; gen = 'inject'; t = 1; pin = $false; k = 0 },
    @{ dir = 'tx'; gen = 'sendto'; t = 1; pin = $false; k = 0 },     # baseline: the first XDP spike's generator
    @{ dir = 'tx'; gen = 'sendto'; t = $ncpu; pin = $true; k = 0 },
    @{ dir = 'tx'; gen = 'uso'; t = $ncpu; pin = $true; k = 0 }
)

function Invoke-Phase([string]$b) {
    Section "Benchmark $b : $Runs runs x $($Sizes -join '/') B x $($tests.Count) tests, $Seconds s each"
    Wait-Ready
    $h = Invoke-Probe "start of $b phase"
    Write-Host "health at start of ${b}: $h"
    for ($run = 1; $run -le $Runs; $run++) {
        foreach ($t in $tests) {
            if ($Diag -and $b -eq 'xdp' -and $t.gen -eq 'uso' -and $run -eq 1) {
                # Does a slow consumer (XSK ring full, drops) alone break the TX path?
                Invoke-Bench $run $b 'tx' 64 'sendto' $ncpu $true 5
            }
            foreach ($len in $Sizes) {
                if ($script:broken -ge 3) { Write-Host "SKIP $b run=$run $($t.dir) $($t.gen) len=$len (TX path broken)"; continue }
                Invoke-Bench $run $b $t.dir $len $t.gen $t.t $t.pin $t.k
            }
        }
        $rows | Export-Csv -Path $csv -NoTypeInformation
    }
}

# ---------------------------------------------------------------- SeLow
$selowOk = $false
$selowCid = $null
if ($Backends -contains 'selow') {
    Section 'SeLow package and signature'
    $sl = Join-Path $env:RUNNER_TEMP 'selow'
    if (-not $env:RUNNER_TEMP) { $sl = Join-Path $env:TEMP 'selow' }
    New-Item -ItemType Directory -Force $sl | Out-Null
    Copy-Item (Join-Path $SeLowDir '*') $sl -Force
    Get-ChildItem $sl | Format-Table -AutoSize Name, Length, @{ n = 'SHA256'; e = { (Get-FileHash $_.FullName).Hash } }
    "SeLow_x64.sys FileVersion: $((Get-Item (Join-Path $sl 'SeLow_x64.sys')).VersionInfo.FileVersion)"
    Select-String -Path (Join-Path $sl 'SeLow_x64.inf') -Pattern 'DriverVer|Class|LowerRange|UpperRange|Characteristics|CatalogFile|NTamd64' | ForEach-Object { $_.Line.Trim() }
    foreach ($f in 'SeLow_x64.sys', 'SeLow_Win10_x64.cat') {
        $s = Get-AuthenticodeSignature (Join-Path $sl $f)
        "$f : Status=$($s.Status) Signer=$($s.SignerCertificate.Subject) Issuer=$($s.SignerCertificate.Issuer) Alg=$($s.SignerCertificate.SignatureAlgorithm.FriendlyName) NotAfter=$($s.SignerCertificate.NotAfter) Timestamp=$($s.TimeStamperCertificate.Subject)"
    }
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Where-Object FullName -match '\\x64\\' | Sort-Object FullName | Select-Object -Last 1
    if ($signtool) {
        & $signtool.FullName verify /kp /v /c (Join-Path $sl 'SeLow_Win10_x64.cat') (Join-Path $sl 'SeLow_x64.sys') 2>&1 |
            Select-String -Pattern 'Issued to|Successfully verified|Number of|Error|SignTool' |
            ForEach-Object { "signtool: $($_.Line.Trim())" }
        "signtool /kp exit=$LASTEXITCODE"
    }
    certutil -dump (Join-Path $sl 'SeLow_Win10_x64.cat') 2>&1 | Select-String -Pattern 'OSAttr' -Context 0, 2 | Select-Object -First 2 |
        ForEach-Object { $_.ToString().Trim() }

    Section 'SeLow install (netcfg -l SeLow_x64.inf -c p -i SeLow)'
    $t0 = Get-Date
    $r = Invoke-Exe 'netcfg.exe' @('-v', '-l', (Join-Path $sl 'SeLow_x64.inf'), '-c', 'p', '-i', 'SeLow') 180
    $r.Out | Where-Object { $_.Trim() } | ForEach-Object { "netcfg: $_" }
    "netcfg exit=$($r.Code) timedout=$($r.TimedOut) took=$([int]((Get-Date) - $t0).TotalSeconds)s"
    sc.exe query SeLow
    if (-not (Get-Service SeLow -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running')) {
        'SeLow service not running, starting it'
        sc.exe start SeLow
    }
    Get-Service SeLow -ErrorAction SilentlyContinue | Format-Table -AutoSize Name, Status, StartType
    $selowCid = (Get-NetAdapterBinding -Name $name -ErrorAction SilentlyContinue | Where-Object ComponentID -match '^selow$' | Select-Object -First 1).ComponentID
    "SeLow binding component id on loopback: $selowCid"
    Get-NetAdapterBinding -ErrorAction SilentlyContinue | Where-Object ComponentID -match 'selow' | Format-Table -AutoSize Name, ComponentID, Enabled
    $r = Invoke-Exe $spbench @('-b', 'selow', '-d', 'list', '-i', $idx) 60
    $r.Out | Set-Content (Join-Path $LogDir 'selow-list.txt')
    $r.Out
    $selowOk = ($r.Code -eq 0)
    if ($selowOk) { 'RESULT SELOW_INSTALL PASS' } else {
        'RESULT SELOW_INSTALL FAIL'
        $sdl = "$env:WINDIR\INF\setupapi.dev.log"
        if (Test-Path $sdl) {
            '--- setupapi.dev.log (SeLow sections)'
            Select-String -Path $sdl -Pattern 'selow' -Context 2, 12 | Select-Object -Last 6 | ForEach-Object { $_.ToString() }
        }
    }
    if ($selowOk) { Invoke-Phase 'selow' }
}

# ---------------------------------------------------------------- XDP
$xdpOk = $false
if ($Backends -contains 'xdp') {
    if ($selowCid) {
        Section 'Unbind SeLow from the loopback adapter'
        $r = Invoke-Ps "Disable-NetAdapterBinding -Name '$name' -ComponentID $selowCid" 120
        "disable SeLow binding: exit=$($r.Code) timedout=$($r.TimedOut)"
        Get-NetAdapterBinding -Name $name -ComponentID $selowCid -ErrorAction SilentlyContinue | Format-Table -AutoSize Name, ComponentID, Enabled
    }
    Section 'XDP install (xdp-setup.ps1 -Install xdp)'
    $native = Join-Path $XdpRuntime 'runtime\native'
    $t1 = Get-Date
    $r = Invoke-Exe 'pwsh' @('-NoProfile', '-File', (Join-Path $native 'xdp-setup.ps1'), '-Install', 'xdp') 300
    $r.Out | ForEach-Object { "xdp-setup: $_" }
    "xdp-setup exit=$($r.Code) timedout=$($r.TimedOut) took=$([int]((Get-Date) - $t1).TotalSeconds)s"
    sc.exe query xdp
    $xdpOk = [bool](Get-NetAdapterBinding -Name $name -ComponentID ms_xdp -ErrorAction SilentlyContinue | Where-Object Enabled)
    if ($xdpOk) { 'RESULT XDP_INSTALL PASS' } else { 'RESULT XDP_INSTALL FAIL' }
    'bindings on loopback:'
    Get-NetAdapterBinding -Name $name | Format-Table -AutoSize DisplayName, ComponentID, Enabled
    if ($xdpOk) {
        Start-Sleep 2
        Invoke-Phase 'xdp'
    }
}
$rows | Export-Csv -Path $csv -NoTypeInformation

Section 'Summary'
& (Join-Path $PSScriptRoot 'summarize.ps1') -Csv $csv -Out (Join-Path $LogDir 'summary.md')
Get-Content (Join-Path $LogDir 'summary.md')

Section 'Post'
Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $tStart } -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match 'xdp|selow|ndis|netcfg|Service Control|CodeIntegrity|BugCheck|Tcpip' -or $_.Level -le 2 } |
    Select-Object -First 60 | Format-Table -AutoSize -Wrap TimeCreated, ProviderName, Id, LevelDisplayName, Message
Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 30 -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -ge $tStart } | Format-Table -AutoSize -Wrap TimeCreated, Id, Message
"elapsed: $([int]((Get-Date) - $tStart).TotalMinutes) min"

Stop-Transcript | Out-Null
if (-not ($selowOk -or $xdpOk)) { exit 4 }
exit 0
