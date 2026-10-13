# XDP spike runner for a GitHub-hosted Windows runner (admin, disposable VM).
# Installs a KM-TEST Loopback Adapter, gives it 10.99.0.1/24, installs XDP
# from the extracted runtime nupkg, then runs xdpspike.exe. Spike only.
param(
    [Parameter(Mandatory)] [string]$Bin,
    [Parameter(Mandatory)] [string]$Runtime,
    [Parameter(Mandatory)] [string]$LogDir,
    [int]$Seconds = 5
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force $LogDir | Out-Null
Start-Transcript -Path (Join-Path $LogDir 'run.txt') | Out-Null

function Section($t) { Write-Host "`n===== $t =====" }

Section 'OS'
Get-CimInstance Win32_OperatingSystem | Format-List Caption, Version, BuildNumber, OSArchitecture
try { "SecureBoot: $(Confirm-SecureBootUEFI)" } catch { "SecureBoot: n/a ($($_.Exception.Message))" }
bcdedit /enum '{current}' | Select-String -Pattern 'testsigning|nointegritychecks|hypervisor'
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue |
    Format-List VirtualizationBasedSecurityStatus, SecurityServicesRunning
Get-NetAdapter | Format-Table -AutoSize Name, InterfaceDescription, ifIndex, Status, MacAddress

Section 'XDP runtime package'
$native = Join-Path $Runtime 'runtime\native'
Get-ChildItem $native | Format-Table -AutoSize Name, Length
foreach ($f in 'xdp.sys', 'xdp.cat') {
    $s = Get-AuthenticodeSignature (Join-Path $native $f)
    "$f : Status=$($s.Status) Signer=$($s.SignerCertificate.Subject) Issuer=$($s.SignerCertificate.Issuer)"
}
Select-String -Path (Join-Path $native 'xdp.inf') -Pattern 'DriverVer|NT\$ARCH|FilterMediaTypes|FilterClass' | ForEach-Object { $_.Line.Trim() }

Section 'KM-TEST Loopback install'
$devcon = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\Tools" -Recurse -Filter devcon.exe -ErrorAction SilentlyContinue |
    Where-Object FullName -match '\\x64\\' | Select-Object -First 1
"devcon from WDK: $(if ($devcon) { $devcon.FullName } else { 'not present' })"
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
$a | Format-List Name, InterfaceDescription, ifIndex, Status, MediaConnectionState, MacAddress, LinkSpeed, DriverFileName, NdisMedium, NdisPhysicalMedium
'RESULT LOOPBACK PASS'

Section 'Address, neighbor, firewall'
New-NetIPAddress -InterfaceIndex $idx -IPAddress 10.99.0.1 -PrefixLength 24 | Out-Null
New-NetNeighbor -InterfaceIndex $idx -IPAddress 10.99.0.2 -LinkLayerAddress '02-00-00-00-00-02' -State Permanent | Out-Null
Set-NetFirewallProfile -All -Enabled False
Get-NetNeighbor -InterfaceIndex $idx -AddressFamily IPv4 | Format-Table -AutoSize IPAddress, LinkLayerAddress, State

Section 'XDP install (xdp-setup.ps1 -Install xdp)'
$t0 = Get-Date
pwsh -NoProfile -File (Join-Path $native 'xdp-setup.ps1') -Install xdp -Verbose
"xdp-setup exit=$LASTEXITCODE took=$([int]((Get-Date) - $t0).TotalSeconds)s"
sc.exe query xdp
Get-NetAdapterBinding -ComponentID ms_xdp -ErrorAction SilentlyContinue | Format-Table -AutoSize Name, InterfaceDescription, Enabled
"bindings on loopback:"
Get-NetAdapterBinding -InterfaceDescription $a.InterfaceDescription | Format-Table -AutoSize DisplayName, ComponentID, Enabled

for ($i = 0; $i -lt 20; $i++) {
    $ip = Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -IPAddress 10.99.0.1 -ErrorAction SilentlyContinue
    if ($ip -and $ip.AddressState -eq 'Preferred') { break }
    Start-Sleep 1
}
"10.99.0.1 state: $($ip.AddressState)"
Get-NetAdapter -InterfaceIndex $idx | Format-Table -AutoSize Name, Status, MediaConnectionState

Section 'Spike'
& (Join-Path $Bin 'xdpspike.exe') $idx 10.99.0.1 10.99.0.2 $Seconds all 2>&1 | Tee-Object -FilePath (Join-Path $LogDir 'xdpspike.txt')
$code = $LASTEXITCODE
"xdpspike exit=$code"

Section 'Post'
Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $t0 } -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match 'xdp|ndis|netcfg|Service Control|CodeIntegrity|PnP' -or $_.Level -le 2 } |
    Select-Object -First 40 | Format-Table -AutoSize -Wrap TimeCreated, ProviderName, Id, LevelDisplayName, Message
Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 20 -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -ge $t0 } | Format-Table -AutoSize -Wrap TimeCreated, Id, Message

Stop-Transcript | Out-Null
exit $code
