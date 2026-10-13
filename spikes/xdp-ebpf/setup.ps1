# XDP eBPF spike setup for a GitHub-hosted Windows runner (admin, disposable VM).
# Installs eBPF for Windows (MSI), a KM-TEST Loopback Adapter with 10.99.0.1/24,
# XDP from the runtime nupkg and the XDP eBPF feature. Spike only.
param(
    [Parameter(Mandatory)] [string]$Bin,
    [Parameter(Mandatory)] [string]$Runtime,
    [Parameter(Mandatory)] [string]$EbpfMsi,
    [Parameter(Mandatory)] [string]$LogDir,
    [string]$EbpfDir = 'C:\ebpf'
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force $LogDir | Out-Null
Start-Transcript -Path (Join-Path $LogDir 'setup.txt') | Out-Null

function Section($t) { Write-Host "`n===== $t =====" }

$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Where-Object FullName -match '\\x64\\' | Sort-Object FullName | Select-Object -Last 1
function Check-Signature($path) {
    $s = Get-AuthenticodeSignature $path
    "$(Split-Path $path -Leaf) : Status=$($s.Status) Signer=$($s.SignerCertificate.Subject) Issuer=$($s.SignerCertificate.Issuer)"
    if ($signtool) {
        # /kp = kernel-mode driver signing policy (production). Test-signed files fail it.
        $out = & $signtool.FullName verify /kp $path 2>&1
        "  signtool /kp exit=$LASTEXITCODE : $(($out | Select-String -Pattern 'Successfully verified|SignTool Error' | Select-Object -First 1).Line)"
    }
}

Section 'OS'
Get-CimInstance Win32_OperatingSystem | Format-List Caption, Version, BuildNumber, OSArchitecture
try { "SecureBoot: $(Confirm-SecureBootUEFI)" } catch { "SecureBoot: n/a ($($_.Exception.Message))" }
bcdedit /enum '{current}' | Select-String -Pattern 'testsigning|nointegritychecks|hypervisor'
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue |
    Format-List VirtualizationBasedSecurityStatus, SecurityServicesRunning, CodeIntegrityPolicyEnforcementStatus

Section 'eBPF inbox check (before install)'
foreach ($svc in 'ebpfcore', 'netebpfext', 'ebpfsvc') {
    $s = Get-Service $svc -ErrorAction SilentlyContinue
    "$svc service: $(if ($s) { "$($s.Status) $($s.StartType)" } else { 'absent' })"
}
foreach ($f in "$env:WINDIR\System32\drivers\ebpfcore.sys", "$env:WINDIR\System32\drivers\netebpfext.sys", "$env:WINDIR\System32\ebpfapi.dll") {
    "$f exists=$(Test-Path $f)"
}
Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue | Where-Object FeatureName -match 'ebpf|bpf' |
    Format-Table -AutoSize FeatureName, State

Section 'eBPF for Windows install (MSI, runtime components only)'
Check-Signature $EbpfMsi
$t0 = Get-Date
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @(
    '/i', "`"$EbpfMsi`"", "INSTALLFOLDER=`"$EbpfDir`"", 'ADDLOCAL=eBPF_Runtime_Components', '/qn',
    '/l*v', "`"$(Join-Path $LogDir 'ebpf-msi.log')`"")
"msiexec exit=$($p.ExitCode) took=$([int]((Get-Date) - $t0).TotalSeconds)s"
foreach ($svc in 'ebpfcore', 'netebpfext', 'ebpfsvc') {
    sc.exe query $svc | Select-String -Pattern 'SERVICE_NAME|STATE|1060'
}
Get-ChildItem $EbpfDir -Recurse -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } |
    Format-Table -AutoSize @{ n = 'Path'; e = { $_.FullName.Substring($EbpfDir.Length) } }, Length
Get-ChildItem $EbpfDir -Recurse -Include *.sys, ebpfapi.dll -ErrorAction SilentlyContinue | ForEach-Object { Check-Signature $_.FullName }
(Get-Item "$EbpfDir\ebpfapi.dll" -ErrorAction SilentlyContinue).VersionInfo | Format-List FileVersion, ProductVersion
'RESULT EBPF_RUNTIME_INSTALL ' + $(if ((Get-Service ebpfcore -ErrorAction SilentlyContinue).Status -eq 'Running') { 'PASS (ebpfcore running)' } else { 'FAIL (ebpfcore not running)' })

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
$a | Format-List Name, InterfaceDescription, ifIndex, Status, MacAddress
'RESULT LOOPBACK PASS'
Set-Content -Path (Join-Path $LogDir 'ifindex.txt') -Value $idx

Section 'Address, neighbor, firewall'
New-NetIPAddress -InterfaceIndex $idx -IPAddress 10.99.0.1 -PrefixLength 24 | Out-Null
New-NetNeighbor -InterfaceIndex $idx -IPAddress 10.99.0.2 -LinkLayerAddress '02-00-00-00-00-02' -State Permanent | Out-Null
Set-NetFirewallProfile -All -Enabled False

Section 'XDP install (xdp-setup.ps1 -Install xdp, then -Install xdpebpf)'
$native = Join-Path $Runtime 'runtime\native'
Check-Signature (Join-Path $native 'xdp.sys')
# xdpbpfexport.exe (run by -Install xdpebpf) needs ebpfapi.dll on PATH. The MSI
# adds $EbpfDir to the machine PATH, but this session predates it.
$env:PATH = "$EbpfDir;$env:PATH"
$t0 = Get-Date
pwsh -NoProfile -File (Join-Path $native 'xdp-setup.ps1') -Install xdp -Verbose
"xdp-setup xdp exit=$LASTEXITCODE took=$([int]((Get-Date) - $t0).TotalSeconds)s"
$t0 = Get-Date
pwsh -NoProfile -File (Join-Path $native 'xdp-setup.ps1') -Install xdpebpf -Verbose
"xdp-setup xdpebpf exit=$LASTEXITCODE took=$([int]((Get-Date) - $t0).TotalSeconds)s"
sc.exe query xdp | Select-String -Pattern 'STATE'
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\xdp\Parameters' -ErrorAction SilentlyContinue |
    Format-List XdpEbpfEnabled, XdpEbpfMode
Get-NetAdapterBinding -ComponentID ms_xdp -ErrorAction SilentlyContinue | Format-Table -AutoSize Name, InterfaceDescription, Enabled
# Program-type registrations the verifier/bpf2c read (eBPF store).
foreach ($k in 'HKLM:\SOFTWARE\eBPF', 'HKCU:\SOFTWARE\eBPF') {
    Get-ChildItem $k -Recurse -Depth 3 -ErrorAction SilentlyContinue | ForEach-Object { "store: $($_.Name)" } | Select-Object -First 60
}

for ($i = 0; $i -lt 20; $i++) {
    $ip = Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -IPAddress 10.99.0.1 -ErrorAction SilentlyContinue
    if ($ip -and $ip.AddressState -eq 'Preferred') { break }
    Start-Sleep 1
}
"10.99.0.1 state: $($ip.AddressState)"
Get-NetAdapter -InterfaceIndex $idx | Format-Table -AutoSize Name, Status, MediaConnectionState

Stop-Transcript | Out-Null
exit 0
