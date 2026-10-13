<#
.SYNOPSIS
Ranz VPN Windows 10 XDP test kit: does XDP for Windows work on a KM-TEST Loopback
Adapter on this machine (TX inspect + RX inject)? Installs, tests, then removes everything.

.DESCRIPTION
Run from an elevated 64-bit Windows PowerShell (5.1 is fine) on Windows 10 x64.
It will:
  1. download the pinned XDP for Windows runtime (nuget.org, SHA-256 checked) and get the
     spike binaries (xdpspike.exe, mkloop.exe) from the latest spike-xdp CI artifact;
  2. create a Microsoft KM-TEST Loopback Adapter (10.99.0.1/24);
  3. install XDP (xdp-setup.ps1 -Install xdp) and check it bound to the loopback adapter;
  4. add a temporary firewall rule (UDP 5556 in), then run xdpspike.exe (TX inspect, RX inject);
  5. remove everything again and verify the machine is clean.

Exit code: 0 = PASS and clean, 1 = test FAIL, 2 = could not run (prerequisite, download,
consent), 3 = cleanup incomplete (read the CLEANUP lines; a reboot may be needed).
Logs go to .\logs\<timestamp>\ (kit.txt is the full transcript).

.PARAMETER BinDir
Folder with xdpspike.exe + mkloop.exe (+ SHA256SUMS.txt), or a .zip of it. Default: .\bin if
present, else the latest 'xdpspike-bin-x64' artifact of the spike-xdp workflow via the gh CLI.

.PARAMETER NoCleanup
Leave everything installed (for debugging). Undo later with -CleanupOnly.

.PARAMETER CleanupOnly
Only undo what an earlier run left behind (reads kit-state.json next to this script).

.PARAMETER DisableFirewall
Turn Windows Defender Firewall off for the test (all profiles, restored afterwards) instead of
adding the narrow allow rule. Use only if the RX inject step fails because of the firewall.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$BinDir = '',
    [string]$Repo = 'Hanzamas/RanzVPN',
    [string]$ArtifactName = 'xdpspike-bin-x64',
    [string]$RunId = '',
    [string]$XdpVersion = '1.4.0',
    [string]$XdpSha256 = '',
    [string]$LocalIp = '10.99.0.1',
    [string]$PeerIp = '10.99.0.2',
    [int]$Seconds = 5,
    [string]$WorkDir = '',
    [string]$LogDir = '',
    [switch]$Yes,
    [switch]$NoCleanup,
    [switch]$CleanupOnly,
    [switch]$KeepWork,
    [switch]$DisableFirewall
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

# SHA-256 of Microsoft.XDP-for-Windows.Runtime.x64.<version>.nupkg as downloaded from nuget.org
# (identical on the windows-2022 and windows-2025 CI runners, spike run 38351393612).
$Pinned = @{ '1.4.0' = 'F78F091C3EDA1D17D2BF4F7E0DDC593FBEA1DAAC6A53CA69DE2F1854E8070D23' }
$FwPort = 5556   # xdpspike.exe receives its injected datagrams on UDP 5556
$PsExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

function Full([string]$p) { return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p) }

$Root = $PSScriptRoot
if (-not $Root) { $Root = (Get-Location).Path }
if (-not $WorkDir) { $WorkDir = Join-Path $Root 'work' }
if (-not $LogDir) { $LogDir = Join-Path (Join-Path $Root 'logs') (Get-Date -Format 'yyyyMMdd-HHmmss') }
$WorkDir = Full $WorkDir
$LogDir = Full $LogDir
if ($BinDir) { $BinDir = Full $BinDir }
$StateFile = Join-Path $Root 'kit-state.json'

# What this run changed. Saved to kit-state.json after every change so -CleanupOnly can undo it.
$script:St = @{ LoopId = ''; XdpByUs = $false; FwRule = ''; FwSaved = @(); NativeDir = ''; BinDir = ''; WorkDir = $WorkDir }
$script:ExitCode = 0
$script:Verdict = 'FAIL'
$script:Reason = 'did not finish'
$script:LastExit = 0
$script:Tx = $null
$script:Rx = $null
$script:Flags = @()

function Say([string]$m) { Write-Host $m }
function Section([string]$t) { Write-Host ''; Write-Host "===== $t =====" }
function Warn([string]$m) { Write-Host "WARN: $m" -ForegroundColor Yellow }
function Show($obj) { $t = ($obj | Format-Table -AutoSize | Out-String -Width 200).TrimEnd(); if ($t) { Write-Host $t } }
function Fail([string]$m, [int]$code = 2) { $script:ExitCode = $code; throw $m }
function Save-State { try { $script:St | ConvertTo-Json -Depth 4 | Set-Content -Path $StateFile -Encoding UTF8 } catch { Warn "could not write $StateFile : $($_.Exception.Message)" } }

# Run a native command, merge stderr, return its output lines. Exit code lands in $script:LastExit.
function Invoke-Capture([string]$Exe, [string[]]$ArgList) {
    $out = & $Exe @ArgList 2>&1
    $script:LastExit = $LASTEXITCODE
    return @($out | ForEach-Object { "$_" })
}

function Find-Loop {
    # 'Not Present' rows are ghosts of removed adapters (Device Manager > Show hidden devices); ignore them.
    $all = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'Not Present' })
    $m = @()
    if ($script:St.LoopId) { $m = @($all | Where-Object { $_.PnPDeviceID -and ($_.PnPDeviceID -ieq $script:St.LoopId) }) }
    if ($m.Count -eq 0) { $m = @($all | Where-Object { $_.InterfaceDescription -like '*KM-TEST*' }) }
    if ($m.Count -gt 0) { return $m[0] }
    return $null
}

function Bin-Help {
    return "Get the spike binaries by hand: open https://github.com/$Repo/actions/workflows/spike-xdp.yml , open the newest green run on branch spike/xdp-loopback, download the artifact '$ArtifactName', unzip it into '$(Join-Path $Root 'bin')' (xdpspike.exe, mkloop.exe), then run this script again. Or install the GitHub CLI (winget install GitHub.cli), run 'gh auth login', and run the script again."
}

# ---------------------------------------------------------------- environment

function Show-Environment {
    $os = Get-CimInstance Win32_OperatingSystem
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    Say "Host        : $env:COMPUTERNAME  (user $env:USERNAME)"
    Say "OS          : $($os.Caption) $($cv.DisplayVersion) build $($os.BuildNumber).$($cv.UBR) $($os.OSArchitecture)"
    Say "PowerShell  : $($PSVersionTable.PSVersion), $(if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' })"
    $sb = 'n/a'
    try { $sb = [string](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $sb = "n/a (legacy BIOS or unsupported)" }
    Say "Secure Boot : $sb"
    $bc = ''
    try { $bc = (& bcdedit.exe /enum '{current}' 2>&1 | Out-String) } catch { }
    $script:TestSigning = [regex]::IsMatch($bc, '(?im)^\s*testsigning\s+Yes')
    Say "Test signing: $(if ($script:TestSigning) { 'ON' } else { 'off' })"
    $dg = $null
    try { $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop } catch { }
    $svc = @()
    if ($dg) { $svc = @($dg.SecurityServicesRunning) }
    $script:Hvci = ($svc -contains 2)
    Say "VBS / HVCI  : VBS status=$(if ($dg) { $dg.VirtualizationBasedSecurityStatus } else { 'n/a' }) (2 = running); services running=$($svc -join ',') (2 = memory integrity / HVCI)"
    Say "Session     : $(if ($env:SESSIONNAME) { $env:SESSIONNAME } else { 'n/a' })"
    try { Say ('Firewall    : ' + ((Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { "$($_.Name)=$($_.Enabled)/in:$($_.DefaultInboundAction)" }) -join '  ')) } catch { Say 'Firewall    : n/a' }
    Say ''
    Say 'Network adapters now:'
    Show (Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name, InterfaceDescription, ifIndex, Status, MacAddress, LinkSpeed)
}

function Test-Preflight {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { Fail 'Not elevated. Open PowerShell with "Run as administrator" and run the script again.' }
    if (-not [Environment]::Is64BitOperatingSystem) { Fail 'This kit needs 64-bit Windows (x64).' }
    if (-not [Environment]::Is64BitProcess) { Fail 'This is a 32-bit PowerShell on 64-bit Windows. Start the 64-bit "Windows PowerShell" and run the script again.' }
    $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    if ($arch -ne 'AMD64') { Fail "CPU architecture is $arch. Only x64 (AMD64) has a production-signed XDP runtime." }
    $os = Get-CimInstance Win32_OperatingSystem
    $build = [int]$os.BuildNumber
    if ($build -lt 17763) { Fail "Windows build $build is older than 17763 (Windows 10 1809). The XDP driver INF does not install here." }
    if ($build -ge 22000 -or $os.ProductType -ne 1) { Warn "This is not Windows 10 (build $build, product type $($os.ProductType)). The kit runs anyway, but the Windows 10 question is not answered by this machine." }
    if ($script:TestSigning) { Warn 'Test signing is ON. A pass here does not prove that production-signed xdp.sys loads. Turn test signing off (bcdedit /set testsigning off, reboot) and run again.' }
    if ($env:SESSIONNAME -like 'RDP-*') { Warn 'This is a Remote Desktop session. XDP binds to every Ethernet adapter and briefly resets them: the session can freeze for a few seconds. Prefer the console.' }

    $existing = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -like '*KM-TEST*' -and $_.Status -ne 'Not Present' })
    if ($existing.Count -gt 0) { Fail "A KM-TEST Loopback Adapter already exists ('$($existing[0].Name)'). All instances share one MAC, so this kit refuses to add a second one. Remove it (Device Manager > Network adapters > Uninstall device) or run the kit on another machine." }
    $ipHit = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $LocalIp -or $_.IPAddress -eq $PeerIp })
    $net = ($LocalIp -replace '\.\d+$', '.0') + '/24'
    $rtHit = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -eq $net })
    if ($ipHit.Count -gt 0 -or $rtHit.Count -gt 0) { Fail "$net is already in use on this machine. Pass other addresses with -LocalIp and -PeerIp (same /24)." }

    $prior = $false
    if (Get-Service -Name xdp -ErrorAction SilentlyContinue) { $prior = $true }
    if (@(Get-NetAdapterBinding -ComponentID ms_xdp -ErrorAction SilentlyContinue).Count -gt 0) { $prior = $true }
    $script:XdpPrior = $prior
    if ($prior) {
        $f = Join-Path $env:WINDIR 'System32\drivers\xdp.sys'
        $v = if (Test-Path $f) { (Get-Item $f).VersionInfo.FileVersion } else { 'n/a' }
        Warn "XDP is already installed on this machine (xdp.sys $v). The kit will use it and will NOT uninstall it."
    }
}

function Confirm-Plan {
    Section 'Plan'
    Say 'This kit changes this machine, then undoes every change:'
    if ($script:XdpPrior) { Say '  1. (XDP already present: left alone)' }
    else { Say "  1. install XDP for Windows $XdpVersion (binds to every Ethernet adapter: a short network blip)" }
    Say "  2. add a Microsoft KM-TEST Loopback Adapter (virtual NIC) with $LocalIp/24"
    if ($DisableFirewall) { Say '  3. turn Windows Defender Firewall OFF for all profiles (restored at the end)' }
    else { Say "  3. add a temporary firewall rule: UDP $FwPort inbound to $LocalIp" }
    Say "  4. run xdpspike.exe for about $($Seconds * 2 + 8) seconds (TX inspect, RX inject)"
    Say '  5. remove all of it and verify'
    Say 'Tip: run this in a VM, or take a snapshot / restore point first.'
    if (-not $Yes) {
        $a = Read-Host 'Type YES to continue'
        if ($a -cne 'YES') { Fail 'Aborted by the user. Nothing was changed.' }
    }
}

# ---------------------------------------------------------------- downloads

function Ensure-Runtime {
    $dir = Join-Path $WorkDir "xdp-runtime-$XdpVersion"
    $setup = $null
    if (Test-Path $dir) { $setup = Get-ChildItem -Path $dir -Recurse -Filter xdp-setup.ps1 -ErrorAction SilentlyContinue | Select-Object -First 1 }
    if (-not $setup) {
        New-Item -ItemType Directory -Force $WorkDir | Out-Null
        $zip = Join-Path $WorkDir "Microsoft.XDP-for-Windows.Runtime.x64.$XdpVersion.zip"
        $url = "https://www.nuget.org/api/v2/package/Microsoft.XDP-for-Windows.Runtime.x64/$XdpVersion"
        Say "download : $url"
        try { Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing -ErrorAction Stop }
        catch { Fail "Could not download the XDP runtime from nuget.org: $($_.Exception.Message)" }
        $h = (Get-FileHash $zip -Algorithm SHA256).Hash
        Say "sha256   : $h  ($((Get-Item $zip).Length) bytes)"
        $want = $XdpSha256
        if (-not $want -and $Pinned.ContainsKey($XdpVersion)) { $want = $Pinned[$XdpVersion] }
        if ($want -and ($h -ne $want)) { Fail "SHA-256 mismatch for the XDP runtime. Expected $want. The download was not used." }
        if (-not $want) { Warn "No pinned SHA-256 for XDP $XdpVersion; hash not verified." }
        if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [IO.Compression.ZipFile]::ExtractToDirectory($zip, $dir)
        } catch {
            Say "  ZipFile extract failed ($($_.Exception.Message)), trying Expand-Archive"
            if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
            Expand-Archive -Path $zip -DestinationPath $dir -Force -ErrorAction Stop
        }
        $setup = Get-ChildItem -Path $dir -Recurse -Filter xdp-setup.ps1 -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    if (-not $setup) { Fail 'xdp-setup.ps1 not found in the XDP runtime package.' }
    $native = $setup.DirectoryName
    foreach ($f in 'xdp.sys', 'xdp.inf', 'xdp.cat', 'xdppcw.man') {
        if (-not (Test-Path (Join-Path $native $f))) { Fail "$f missing in $native" }
    }
    Get-ChildItem -Path $native -Recurse -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue
    $script:St.NativeDir = $native
    Save-State
    return $native
}

function Show-Signatures([string]$native) {
    foreach ($f in 'xdp.sys', 'xdp.cat') {
        $sig = Get-AuthenticodeSignature (Join-Path $native $f)
        Say "$f : Status=$($sig.Status) Type=$($sig.SignatureType) Signer=$($sig.SignerCertificate.Subject)"
        try { foreach ($e in $sig.SignerCertificate.EnhancedKeyUsageList) { Say "      EKU $($e.ObjectId) $($e.FriendlyName)" } } catch { }
    }
}

function Resolve-Bins {
    $dir = ''
    if ($BinDir) {
        if (Test-Path $BinDir -PathType Leaf) {
            $dir = Join-Path $WorkDir 'bin'
            if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
            New-Item -ItemType Directory -Force $dir | Out-Null
            try { Expand-Archive -Path $BinDir -DestinationPath $dir -Force -ErrorAction Stop } catch { Fail "Could not unzip ${BinDir}: $($_.Exception.Message)" }
        } else { $dir = $BinDir }
    } elseif (Test-Path (Join-Path $Root 'bin\xdpspike.exe')) {
        $dir = Join-Path $Root 'bin'
    } else {
        $gh = Get-Command gh -ErrorAction SilentlyContinue
        if (-not $gh) { Fail ('The GitHub CLI (gh) is not installed and there is no .\bin folder. ' + (Bin-Help)) }
        $dir = Join-Path $WorkDir 'bin'
        if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
        New-Item -ItemType Directory -Force $dir | Out-Null
        $a = @('run', 'download')
        if ($RunId) { $a += $RunId }
        $a += @('-R', $Repo, '-n', $ArtifactName, '-D', $dir)
        Say "gh $($a -join ' ')"
        $o = Invoke-Capture $gh.Source $a
        $o | ForEach-Object { Say "  $_" }
        if ($script:LastExit -ne 0) { Fail ("gh could not download the artifact '$ArtifactName' (exit $($script:LastExit); is 'gh auth login' done and is there a green spike-xdp run with that artifact?). " + (Bin-Help)) }
    }
    foreach ($f in 'xdpspike.exe', 'mkloop.exe') {
        if (-not (Test-Path (Join-Path $dir $f))) { Fail ("$f not found in $dir. " + (Bin-Help)) }
    }
    Get-ChildItem -Path $dir -Recurse -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue
    $sums = Join-Path $dir 'SHA256SUMS.txt'
    if (Test-Path $sums) {
        foreach ($l in (Get-Content $sums)) {
            if ($l -match '^([0-9A-Fa-f]{64})\s+\*?(\S+)\s*$') {
                $want = $Matches[1]; $name = $Matches[2]
                $f = Join-Path $dir $name
                if (Test-Path $f) {
                    if ((Get-FileHash $f -Algorithm SHA256).Hash -ne $want) { Fail "SHA-256 mismatch for $name (does not match SHA256SUMS.txt)." }
                    Say "sha256 ok : $name"
                }
            }
        }
    } else { Warn 'No SHA256SUMS.txt next to the binaries; not verified.' }
    $bt = Join-Path $dir 'BUILD.txt'
    if (Test-Path $bt) { Get-Content $bt | ForEach-Object { Say "  build: $_" } }
    $script:St.BinDir = $dir
    Save-State
}

# ---------------------------------------------------------------- cleanup

function Invoke-Cleanup {
    Section 'Cleanup'
    $problems = New-Object System.Collections.ArrayList
    $St = $script:St

    Get-Process -Name xdpspike -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    if ($St.FwRule) {
        Remove-NetFirewallRule -Name $St.FwRule -ErrorAction SilentlyContinue
        if (Get-NetFirewallRule -Name $St.FwRule -ErrorAction SilentlyContinue) { [void]$problems.Add("firewall rule $($St.FwRule) is still there") }
        else { Say "firewall rule $($St.FwRule): removed" }
    }
    foreach ($s in @($St.FwSaved)) {
        if ($s -match '^(\w+)=(\w+)$') {
            $n = $Matches[1]; $v = $Matches[2]
            Set-NetFirewallProfile -Name $n -Enabled $v -ErrorAction SilentlyContinue
            $now = [string](Get-NetFirewallProfile -Name $n -ErrorAction SilentlyContinue).Enabled
            if ($now -ne $v) { [void]$problems.Add("firewall profile $n is '$now', was '$v'") } else { Say "firewall profile ${n}: restored to ${v}" }
        }
    }

    if ($St.LoopId) {
        $mk = ''
        if ($St.BinDir) { $mk = Join-Path $St.BinDir 'mkloop.exe' }
        if ($mk -and (Test-Path $mk)) {
            $o = Invoke-Capture $mk @('remove', $St.LoopId)
        } else {
            Say '  mkloop.exe not available, using pnputil /remove-device'
            $o = Invoke-Capture 'pnputil.exe' @('/remove-device', $St.LoopId)
        }
        $o | ForEach-Object { Say "  $_" }
        $gone = $false
        for ($i = 0; $i -lt 30; $i++) { if (-not (Find-Loop)) { $gone = $true; break }; Start-Sleep -Seconds 1 }
        if ($gone) { Say "KM-TEST loopback $($St.LoopId): removed" }
        else { [void]$problems.Add("KM-TEST loopback $($St.LoopId) is still present (Device Manager > Network adapters > Uninstall device)") }
    }

    if ($St.XdpByUs) {
        $native = $St.NativeDir
        if (-not $native -or -not (Test-Path (Join-Path $native 'xdp-setup.ps1'))) {
            try { $native = Ensure-Runtime } catch { $native = ''; [void]$problems.Add("XDP runtime for uninstall is not available: $($_.Exception.Message)") }
        }
        if ($native) {
            $o = Invoke-Capture $PsExe @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $native 'xdp-setup.ps1'), '-Uninstall', 'xdp', '-Verbose')
            $o | ForEach-Object { Say "  $_" }
            Say "xdp-setup.ps1 -Uninstall xdp: exit $($script:LastExit)"
        }
        Start-Sleep -Seconds 2
        if (Get-Service -Name xdp -ErrorAction SilentlyContinue) { [void]$problems.Add('service xdp still exists (reboot, then run: sc.exe delete xdp)') }
        if (@(Get-NetAdapterBinding -ComponentID ms_xdp -ErrorAction SilentlyContinue).Count -gt 0) { [void]$problems.Add('ms_xdp is still bound to an adapter') }
        if (Test-Path (Join-Path $env:WINDIR 'System32\drivers\xdp.sys')) { [void]$problems.Add('drivers\xdp.sys is still on disk (it may go away after a reboot)') }
        if (@($problems | Where-Object { $_ -match 'xdp' }).Count -eq 0) { Say 'XDP: uninstalled' }
    }

    $touched = ($St.LoopId -or $St.XdpByUs -or $St.FwRule -or (@($St.FwSaved) | Where-Object { $_ }))
    if ($problems.Count -eq 0) {
        if (Test-Path $StateFile) { Remove-Item $StateFile -Force -ErrorAction SilentlyContinue }
        if (-not $KeepWork -and $St.WorkDir -and (Test-Path $St.WorkDir)) {
            Remove-Item -Recurse -Force $St.WorkDir -ErrorAction SilentlyContinue
            if (Test-Path $St.WorkDir) { Say "work folder $($St.WorkDir): could not be fully removed (delete it by hand)" } else { Say 'work folder: removed' }
        }
        if ($touched) { Say 'CLEANUP: OK, this machine is back to how it was.' } else { Say 'CLEANUP: nothing had been changed.' }
    } else {
        $problems | ForEach-Object { Write-Host "CLEANUP PROBLEM: $_" -ForegroundColor Red }
        Say "CLEANUP: INCOMPLETE. Fix the items above (or reboot), then run: .\run-win10.ps1 -CleanupOnly"
    }
    $script:CleanupProblems = $problems.Count
}

# ---------------------------------------------------------------- the test

function Invoke-Kit {
    Section 'Environment'
    Show-Environment
    Test-Preflight
    Confirm-Plan

    Section 'XDP runtime (nuget.org)'
    $native = Ensure-Runtime
    Show-Signatures $native

    Section 'Spike binaries'
    Resolve-Bins
    $St = $script:St

    Section 'KM-TEST Loopback Adapter'
    $o = Invoke-Capture (Join-Path $St.BinDir 'mkloop.exe') @()
    $mkExit = $script:LastExit
    $o | ForEach-Object { Say "  $_" }
    $m = [regex]::Match(($o -join "`n"), 'instance=(\S+)')
    if ($m.Success) { $St.LoopId = $m.Groups[1].Value; Save-State }
    if ($mkExit -ne 0) { Fail "mkloop.exe failed (exit $mkExit): the KM-TEST Loopback Adapter could not be created." 1 }
    $loop = $null
    for ($i = 0; $i -lt 30 -and -not $loop; $i++) { $loop = Find-Loop; if (-not $loop) { Start-Sleep -Seconds 1 } }
    if (-not $loop) { Fail 'The KM-TEST Loopback Adapter did not show up within 30 s.' 1 }
    Show ($loop | Select-Object Name, InterfaceDescription, ifIndex, Status, MediaConnectionState, MacAddress, LinkSpeed)
    $idx = $loop.ifIndex

    Section 'Address, neighbor, firewall'
    try {
        New-NetIPAddress -InterfaceIndex $idx -IPAddress $LocalIp -PrefixLength 24 -ErrorAction Stop | Out-Null
        New-NetNeighbor -InterfaceIndex $idx -IPAddress $PeerIp -LinkLayerAddress '02-00-00-00-00-02' -State Permanent -ErrorAction Stop | Out-Null
    } catch { Fail "Could not set the IP address or neighbor on the loopback adapter: $($_.Exception.Message)" 1 }
    Show (Get-NetNeighbor -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object IPAddress, LinkLayerAddress, State)
    if ($DisableFirewall) {
        $saved = @()
        foreach ($p in (Get-NetFirewallProfile)) { $saved += "$($p.Name)=$($p.Enabled)" }
        $St.FwSaved = $saved
        Save-State
        Set-NetFirewallProfile -All -Enabled False
        Say "firewall OFF for the test (was: $($saved -join ', '))"
    } else {
        $rule = 'RanzXdpKit-udp5556'
        Remove-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue
        try {
            New-NetFirewallRule -Name $rule -DisplayName "Ranz XDP kit (temporary): UDP $FwPort in" -Direction Inbound -Action Allow -Protocol UDP -LocalPort $FwPort -LocalAddress $LocalIp -Profile Any -ErrorAction Stop | Out-Null
            $St.FwRule = $rule
            Save-State
            Say "firewall rule added: $rule (UDP $FwPort in to $LocalIp)"
        } catch { Warn "Could not add the firewall rule: $($_.Exception.Message)" }
    }

    Section 'XDP install (xdp-setup.ps1 -Install xdp)'
    $t0 = Get-Date
    if ($script:XdpPrior) {
        Say 'XDP was already installed: skipped.'
    } else {
        $St.XdpByUs = $true
        Save-State
        $o = Invoke-Capture $PsExe @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $native 'xdp-setup.ps1'), '-Install', 'xdp', '-Verbose')
        $xe = $script:LastExit
        $o | ForEach-Object { Say "  $_" }
        Say "xdp-setup.ps1 exit=$xe took=$([int]((Get-Date) - $t0).TotalSeconds)s"
        if ($xe -ne 0) { Fail "xdp-setup.ps1 -Install xdp failed (exit $xe). This is the Windows 10 answer: XDP does not install here. See the lines above and the CodeIntegrity events in the log." 1 }
    }
    (& sc.exe query xdp 2>&1) | ForEach-Object { Say "  $_" }
    $bind = @(Get-NetAdapterBinding -ComponentID ms_xdp -ErrorAction SilentlyContinue)
    Show ($bind | Select-Object Name, InterfaceDescription, Enabled)
    $lb = @($bind | Where-Object { $_.InterfaceDescription -eq $loop.InterfaceDescription })
    if ($lb.Count -eq 0 -or -not $lb[0].Enabled) { Fail 'The XDP filter (ms_xdp) is not bound to the KM-TEST Loopback Adapter.' 1 }
    Say 'ms_xdp is bound to the loopback adapter.'
    $ip = $null
    for ($i = 0; $i -lt 20; $i++) {
        $ip = Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -IPAddress $LocalIp -ErrorAction SilentlyContinue
        if ($ip -and $ip.AddressState -eq 'Preferred') { break }
        Start-Sleep -Seconds 1
    }
    Say "$LocalIp state: $(if ($ip) { $ip.AddressState } else { 'missing' })"
    Show (Get-NetAdapter -InterfaceIndex $idx -ErrorAction SilentlyContinue | Select-Object Name, Status, MediaConnectionState)

    Section 'xdpspike: TX inspect + RX inject'
    $spike = Join-Path $St.BinDir 'xdpspike.exe'
    $lines = New-Object System.Collections.ArrayList
    & $spike $idx $LocalIp $PeerIp $Seconds all 2>&1 | ForEach-Object { $l = "$_"; Write-Host $l; [void]$lines.Add($l) }
    $spikeExit = $LASTEXITCODE
    $lines | Set-Content -Path (Join-Path $LogDir 'xdpspike.txt') -Encoding UTF8
    Say "xdpspike exit=$spikeExit"
    $all = $lines -join "`n"
    $txm = [regex]::Match($all, '(?m)^PPS TX_INSPECT udp_seen=(\d+) sendto=(\d+)')
    $rxm = [regex]::Match($all, '(?m)^PPS RX_INJECT injected=(\d+) delivered_to_socket=(\d+)')
    $script:Tx = @{ Pass = [regex]::IsMatch($all, '(?m)^RESULT TX_INSPECT PASS(\s|$)'); Pps = $(if ($txm.Success) { [double]$txm.Groups[1].Value } else { 0 }); Sent = $(if ($txm.Success) { [double]$txm.Groups[2].Value } else { 0 }) }
    $script:Rx = @{ Pass = [regex]::IsMatch($all, '(?m)^RESULT RX_INJECT PASS(\s|$)'); Pps = $(if ($rxm.Success) { [double]$rxm.Groups[2].Value } else { 0 }); Injected = $(if ($rxm.Success) { [double]$rxm.Groups[1].Value } else { 0 }) }
    if ($script:Tx.Pass -and $script:Rx.Pass) {
        $script:Verdict = 'PASS'; $script:Reason = ''
    } else {
        $script:Verdict = 'FAIL'
        $script:ExitCode = 1
        $r = @()
        if (-not $script:Tx.Pass) { $r += 'TX inspect did not pass' }
        if (-not $script:Rx.Pass) { $r += 'RX inject did not pass' + $(if (-not $DisableFirewall) { ' (if the XSK took the frames but no UDP arrived, retry with -DisableFirewall)' } else { '' }) }
        $script:Reason = $r -join '; '
    }

    Section 'Diagnostics: events since XDP install'
    $n = 0
    try {
        Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $t0 } -ErrorAction Stop |
            Where-Object { $_.ProviderName -match 'xdp|ndis|netcfg|Service Control Manager|Kernel-PnP|CodeIntegrity|DriverFrameworks' -or $_.Level -le 2 } |
            Select-Object -First 30 | ForEach-Object {
                $msg = ("$($_.Message)" -replace '\s+', ' ')
                if ($msg.Length -gt 200) { $msg = $msg.Substring(0, 200) }
                Say ("{0:HH:mm:ss} {1} id={2} {3}" -f $_.TimeCreated, $_.ProviderName, $_.Id, $msg)
                $n++
            }
    } catch { }
    try {
        Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 30 -ErrorAction Stop |
            Where-Object { $_.TimeCreated -ge $t0 } | ForEach-Object {
                $msg = ("$($_.Message)" -replace '\s+', ' ')
                if ($msg.Length -gt 200) { $msg = $msg.Substring(0, 200) }
                Say ("{0:HH:mm:ss} CodeIntegrity id={1} {2}" -f $_.TimeCreated, $_.Id, $msg)
                $n++
            }
    } catch { }
    if ($n -eq 0) { Say '(no relevant events)' }
}

# ---------------------------------------------------------------- main

New-Item -ItemType Directory -Force $LogDir | Out-Null
$transcript = $false
try { Start-Transcript -Path (Join-Path $LogDir 'kit.txt') | Out-Null; $transcript = $true } catch { }
Say "Ranz VPN Windows 10 XDP test kit   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Say "XDP runtime $XdpVersion, logs in $LogDir"

$script:XdpPrior = $false
$script:TestSigning = $false
$script:Hvci = $false
$script:CleanupProblems = 0
$ranCleanup = $false

try {
    if ($CleanupOnly) {
        if (-not (Test-Path $StateFile)) { Say "No $StateFile : nothing to undo."; $script:Verdict = 'N/A' }
        else {
            $j = Get-Content $StateFile -Raw | ConvertFrom-Json
            $script:St.LoopId = [string]$j.LoopId
            $script:St.XdpByUs = [bool]$j.XdpByUs
            $script:St.FwRule = [string]$j.FwRule
            $script:St.FwSaved = @($j.FwSaved)
            $script:St.NativeDir = [string]$j.NativeDir
            $script:St.BinDir = [string]$j.BinDir
            if ($j.WorkDir) { $script:St.WorkDir = [string]$j.WorkDir }
            Say "state: loopback=$($script:St.LoopId) xdpByKit=$($script:St.XdpByUs) fwRule=$($script:St.FwRule)"
        }
    } else {
        Invoke-Kit
    }
} catch {
    $msg = $_.Exception.Message
    Write-Host "ERROR: $msg" -ForegroundColor Red
    if ($script:ExitCode -eq 0) { $script:ExitCode = 2 }
    $script:Verdict = 'FAIL'
    $script:Reason = $msg
} finally {
    if ($CleanupOnly -or -not $NoCleanup) { Invoke-Cleanup; $ranCleanup = $true }
}

Section 'Result'
if ($CleanupOnly) {
    Say "CLEANUP-ONLY: $(if ($script:CleanupProblems -eq 0) { 'OK' } else { 'INCOMPLETE' })"
} else {
    $f = {
        param($r, $unit)
        if ($null -eq $r) { return 'not run' }
        if ($r.Pass) { return ('PASS  {0:N0} {1}' -f $r.Pps, $unit) } else { return 'FAIL' }
    }
    Say ('TX inspect : ' + (& $f $script:Tx 'pps seen by the XDP socket (sender-bound)'))
    Say ('RX inject  : ' + (& $f $script:Rx 'pps delivered to a UDP socket'))
    Say "Signing     : test signing $(if ($script:TestSigning) { 'ON (result is not conclusive for production signing)' } else { 'off' }), Secure Boot see Environment above, HVCI $(if ($script:Hvci) { 'ON' } else { 'off' })"
    if ($NoCleanup) { Say 'CLEANUP    : skipped (-NoCleanup). Undo later with: .\run-win10.ps1 -CleanupOnly' }
    else { Say "CLEANUP    : $(if ($script:CleanupProblems -eq 0) { 'OK' } else { 'INCOMPLETE (see CLEANUP PROBLEM lines above)' })" }
    Say ''
    if ($script:Verdict -eq 'PASS') { Write-Host 'RESULT: PASS' -ForegroundColor Green }
    else { Write-Host "RESULT: FAIL  $($script:Reason)" -ForegroundColor Red }
    try { "RESULT: $($script:Verdict) $($script:Reason)`r`nTX: $($script:Tx | Out-String)`r`nRX: $($script:Rx | Out-String)" | Set-Content -Path (Join-Path $LogDir 'summary.txt') -Encoding UTF8 } catch { }
}
Say "Logs: $LogDir"

$final = 0
if ($script:CleanupProblems -gt 0) { $final = 3 }
elseif ($CleanupOnly) { $final = 0 }
elseif ($script:Verdict -eq 'PASS') { $final = 0 }
elseif ($script:ExitCode -ne 0) { $final = $script:ExitCode }
else { $final = 1 }
if ($transcript) { try { Stop-Transcript | Out-Null } catch { } }
exit $final
