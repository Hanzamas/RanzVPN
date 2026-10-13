# Runs xdpebpf.exe against the KM-TEST adapter prepared by setup.ps1 and the
# native program built by build-bpf.ps1, then dumps relevant events. Spike only.
param(
    [Parameter(Mandatory)] [string]$Bin,
    [Parameter(Mandatory)] [string]$Sys,
    [Parameter(Mandatory)] [string]$LogDir,
    [string]$EbpfDir = 'C:\ebpf',
    [int]$Seconds = 5
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force $LogDir | Out-Null
Start-Transcript -Path (Join-Path $LogDir 'run.txt') | Out-Null
function Section($t) { Write-Host "`n===== $t =====" }

$idx = (Get-Content (Join-Path $LogDir 'ifindex.txt') -ErrorAction SilentlyContinue | Select-Object -First 1)
"IfIndex=$idx sys=$Sys exists=$(Test-Path $Sys)"
$env:PATH = "$EbpfDir;$env:PATH"
$t0 = Get-Date

Section 'Spike'
& (Join-Path $Bin 'xdpebpf.exe') $idx 10.99.0.1 10.99.0.2 $Seconds $Sys 2>&1 | Tee-Object -FilePath (Join-Path $LogDir 'xdpebpf.txt')
$code = $LASTEXITCODE
"xdpebpf exit=$code"

Section 'Post'
Get-Service ebpfcore, netebpfext, xdp -ErrorAction SilentlyContinue | Format-Table -AutoSize Name, Status
Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $t0 } -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match 'xdp|ebpf|ndis|Service Control|CodeIntegrity' -or $_.Level -le 2 } |
    Select-Object -First 40 | Format-Table -AutoSize -Wrap TimeCreated, ProviderName, Id, LevelDisplayName, Message
Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 30 -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -ge $t0 } | Format-Table -AutoSize -Wrap TimeCreated, Id, Message

Stop-Transcript | Out-Null
exit $code
