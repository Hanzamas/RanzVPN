# SeLow vs XDP benchmark runner for a GitHub-hosted Windows runner (admin,
# disposable VM). Installs one KM-TEST Loopback Adapter (10.99.0.1/24), the
# SeLow NDIS protocol driver (netcfg, same as InstallNdisProtocolDriver in
# src/Cedar/Win32Com.cpp) and XDP for Windows, then runs spbench.exe for both
# backends on that one adapter. Before each backend run, the other backend's
# binding on the adapter is disabled, so only one of them is in the data path.
# Spike only.
param(
    [Parameter(Mandatory)] [string]$Bin,
    [Parameter(Mandatory)] [string]$XdpRuntime,
    [Parameter(Mandatory)] [string]$SeLowDir,
    [Parameter(Mandatory)] [string]$LogDir,
    [int]$Seconds = 5,
    [int]$Runs = 5,
    [int[]]$Sizes = @(64, 512, 1500),
    [int]$Receivers = 2,
    [switch]$NoToggle
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force $LogDir | Out-Null
$LogDir = (Resolve-Path $LogDir).Path
Start-Transcript -Path (Join-Path $LogDir 'run.txt') | Out-Null
$spbench = Join-Path (Resolve-Path $Bin).Path 'spbench.exe'
$benchLog = Join-Path $LogDir 'spbench.txt'
$csv = Join-Path $LogDir 'results.csv'
$osTag = $env:ImageOS
if (-not $osTag) { $osTag = (Get-CimInstance Win32_OperatingSystem).BuildNumber }

function Section($t) { Write-Host "`n===== $t =====" }

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
        Select-String -Pattern 'Signing Certificate Chain|Issued to|Issued by|Expires|Successfully verified|Number of|Error|SignTool|Hash of file' |
        ForEach-Object { "signtool: $($_.Line.Trim())" }
    "signtool /kp exit=$LASTEXITCODE"
}
certutil -dump (Join-Path $sl 'SeLow_Win10_x64.cat') 2>&1 | Select-String -Pattern 'OSAttr|HWID' -Context 0, 2 | Select-Object -First 6 |
    ForEach-Object { $_.ToString().Trim() }

Section 'SeLow install (netcfg -l SeLow_x64.inf -c p -i SeLow)'
$t0 = Get-Date
netcfg.exe -v -l (Join-Path $sl 'SeLow_x64.inf') -c p -i SeLow 2>&1 | ForEach-Object { "netcfg: $_" }
"netcfg exit=$LASTEXITCODE took=$([int]((Get-Date) - $t0).TotalSeconds)s"
sc.exe query SeLow
sc.exe qc SeLow
if (-not (Get-Service SeLow -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running')) {
    'SeLow service not running, starting it'
    sc.exe start SeLow
}
Get-Service SeLow -ErrorAction SilentlyContinue | Format-Table -AutoSize Name, Status, StartType
$selowCid = (Get-NetAdapterBinding -Name $name -ErrorAction SilentlyContinue | Where-Object ComponentID -match '^selow$' | Select-Object -First 1).ComponentID
"SeLow binding component id on loopback: $selowCid"
Get-NetAdapterBinding -ErrorAction SilentlyContinue | Where-Object ComponentID -match 'selow' | Format-Table -AutoSize Name, ComponentID, Enabled
& $spbench -b selow -d list -i $idx 2>&1 | Tee-Object -FilePath (Join-Path $LogDir 'selow-list.txt')
$selowOk = ($LASTEXITCODE -eq 0)
if ($selowOk) { 'RESULT SELOW_INSTALL PASS' } else {
    'RESULT SELOW_INSTALL FAIL'
    $sdl = "$env:WINDIR\INF\setupapi.dev.log"
    if (Test-Path $sdl) {
        '--- setupapi.dev.log (SeLow sections)'
        Select-String -Path $sdl -Pattern 'selow' -Context 2, 12 | Select-Object -Last 6 | ForEach-Object { $_.ToString() }
    }
}

Section 'XDP install (xdp-setup.ps1 -Install xdp)'
$native = Join-Path $XdpRuntime 'runtime\native'
$t1 = Get-Date
pwsh -NoProfile -File (Join-Path $native 'xdp-setup.ps1') -Install xdp
"xdp-setup exit=$LASTEXITCODE took=$([int]((Get-Date) - $t1).TotalSeconds)s"
sc.exe query xdp
$xdpOk = [bool](Get-NetAdapterBinding -Name $name -ComponentID ms_xdp -ErrorAction SilentlyContinue)
$xdpCid = if ($xdpOk) { 'ms_xdp' } else { $null }
if ($xdpOk) { 'RESULT XDP_INSTALL PASS' } else { 'RESULT XDP_INSTALL FAIL' }
"bindings on loopback:"
Get-NetAdapterBinding -Name $name | Format-Table -AutoSize DisplayName, ComponentID, Enabled

function Wait-Ready {
    for ($i = 0; $i -lt 40; $i++) {
        $ad = Get-NetAdapter -InterfaceIndex $idx -ErrorAction SilentlyContinue
        $ip = Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -IPAddress 10.99.0.1 -ErrorAction SilentlyContinue
        if ($ad.Status -eq 'Up' -and $ip.AddressState -eq 'Preferred') { return }
        Start-Sleep -Milliseconds 500
    }
    Write-Host "WARN adapter not ready: status=$($ad.Status) ip=$($ip.AddressState)"
}

function Use-Backend([string]$b) {
    if (-not $NoToggle) {
        if ($xdpCid) {
            if ($b -eq 'xdp') { Enable-NetAdapterBinding -Name $name -ComponentID $xdpCid } else { Disable-NetAdapterBinding -Name $name -ComponentID $xdpCid }
        }
        if ($selowCid) {
            if ($b -eq 'selow') { Enable-NetAdapterBinding -Name $name -ComponentID $selowCid } else { Disable-NetAdapterBinding -Name $name -ComponentID $selowCid }
        }
        Start-Sleep 2
    }
    Wait-Ready
    $st = Get-NetAdapterBinding -Name $name | Where-Object { $_.ComponentID -eq $xdpCid -or $_.ComponentID -eq $selowCid } |
        ForEach-Object { "$($_.ComponentID)=$($_.Enabled)" }
    $nb = Get-NetNeighbor -InterfaceIndex $idx -IPAddress 10.99.0.2 -ErrorAction SilentlyContinue
    Write-Host "backend=$b bindings: $($st -join ' ') neighbor=$($nb.LinkLayerAddress)/$($nb.State)"
}

$cols = 'os', 'run', 'backend', 'dir', 'len', 'gen', 'threads', 'pin', 'secs', 'gen_calls_ps', 'gen_pps', 'pps', 'mbps',
    'loss_pct', 'other_ps', 'dups', 'gen_errors', 'cpu_sys', 'cpu_sys_pct', 'cpu_gen', 'cpu_cap', 'cpu_proc',
    'cores_per_mpps', 'ncpu', 'segs', 'gen_err', 'cap_calls', 'cap_errors', 'xdp_rx_dropped', 'receivers', 'status'
$rows = New-Object System.Collections.Generic.List[object]

function Invoke-Bench([int]$run, [string]$b, [string]$dir, [int]$len, [string]$gen, [int]$threads, [bool]$pin) {
    $argv = @('-b', $b, '-d', $dir, '-i', $idx, '-l', $len, '-s', $Seconds, '-t', $threads, '-r', $Receivers)
    if ($dir -eq 'tx') { $argv += @('-g', $gen) }
    if ($pin) { $argv += '-p' }
    $out = & $spbench @argv 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
    Add-Content -Path $benchLog -Value (@("### run=$run spbench $($argv -join ' ') exit=$code") + $out)
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
        $kv.status = if ($f) { ($f -replace '.*reason=', 'fail:') } else { "fail:exit$code" }
    }
    $r = [pscustomobject]$kv
    $rows.Add($r)
    Write-Host ("run={0} {1,-5} {2} len={3,-4} gen={4,-15} t={5} gen_pps={6,9} pps={7,9} mbps={8,8} loss={9}% cpu_sys={10} c/Mpps={11} {12}" -f
        $run, $b, $dir, $len, $kv.gen, $kv.threads, $kv.gen_pps, $kv.pps, $kv.mbps, $kv.loss_pct, $kv.cpu_sys, $kv.cores_per_mpps, $kv.status)
}

$backends = @()
if ($xdpOk) { $backends += 'xdp' }
if ($selowOk) { $backends += 'selow' }
"backends to measure: $($backends -join ', ')"
$tests = @(
    @{ dir = 'tx'; gen = 'sendto'; t = 1; pin = $false },      # baseline: the first XDP spike's generator
    @{ dir = 'tx'; gen = 'sendto'; t = $ncpu; pin = $true },
    @{ dir = 'tx'; gen = 'uso'; t = $ncpu; pin = $true },
    @{ dir = 'rx'; gen = 'inject'; t = 1; pin = $false }
)

Section "Benchmark: $Runs runs x $($Sizes -join '/') B x $($tests.Count) tests, $Seconds s each"
for ($run = 1; $run -le $Runs; $run++) {
    # Alternate the order so neither backend always runs first.
    $order = if ($run % 2 -eq 1) { $backends } else { $backends[($backends.Count - 1)..0] }
    foreach ($b in $order) {
        Use-Backend $b
        foreach ($len in $Sizes) {
            foreach ($t in $tests) {
                Invoke-Bench $run $b $t.dir $len $t.gen $t.t $t.pin
            }
        }
        $rows | Export-Csv -Path $csv -NoTypeInformation
    }
}
$rows | Export-Csv -Path $csv -NoTypeInformation

Section 'Summary'
& (Join-Path $PSScriptRoot 'summarize.ps1') -Csv $csv -Out (Join-Path $LogDir 'summary.md')
Get-Content (Join-Path $LogDir 'summary.md')

Section 'Post'
Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $t0 } -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match 'xdp|selow|ndis|netcfg|Service Control|CodeIntegrity|PnP|BugCheck' -or $_.Level -le 2 } |
    Select-Object -First 60 | Format-Table -AutoSize -Wrap TimeCreated, ProviderName, Id, LevelDisplayName, Message
Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 30 -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -ge $t0 } | Format-Table -AutoSize -Wrap TimeCreated, Id, Message

Stop-Transcript | Out-Null
if ($backends.Count -eq 0) { exit 4 }
exit 0
