# Spike: install/uninstall test of the Ranz VPN Server MSI (x64 runner, admin).
# Installs silently, checks the service runs and the default listeners (TCP 443, 5555) are up,
# uninstalls silently, checks the service and the MSI-owned files are gone, and reports what is left.
param(
	[Parameter(Mandatory = $true)][string]$Msi,
	[string]$LogDir = 'build/msi-logs'
)

$ErrorActionPreference = 'Stop'
$svc = 'sevpnserverdev'
$dir = Join-Path $env:ProgramFiles 'Ranz VPN'
$msi = (Resolve-Path -LiteralPath $Msi).Path
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$LogDir = (Resolve-Path -LiteralPath $LogDir).Path
$report = New-Object System.Collections.Generic.List[string]
function Note([string]$line) { Write-Host $line; $report.Add($line) }

function Invoke-Msiexec([string[]]$Arguments) {
	$p = Start-Process -FilePath msiexec.exe -ArgumentList $Arguments -Wait -PassThru
	return $p.ExitCode
}

function Get-ListenPorts([int]$ProcessId) {
	# netstat -ano: "  TCP    0.0.0.0:443    0.0.0.0:0    LISTENING    1234"
	$ports = @()
	foreach ($line in (netstat -ano -p TCP) + (netstat -ano -p TCPv6)) {
		$f = ($line.Trim() -split '\s+')
		if ($f.Count -ge 5 -and $f[3] -eq 'LISTENING' -and [int]$f[4] -eq $ProcessId) {
			$ports += [int]($f[1] -replace '^.*:', '')
		}
	}
	return ($ports | Sort-Object -Unique)
}

Note "MSI: $(Split-Path -Leaf $msi), $((Get-Item -LiteralPath $msi).Length) bytes"

# 1. Install
$code = Invoke-Msiexec @('/i', "`"$msi`"", '/qn', '/l*v', "`"$LogDir\install.log`"")
Note "install: msiexec exit code $code"
if ($code -ne 0 -and $code -ne 3010) { throw "msiexec /i failed with exit code $code (see install.log)" }

# 2. Service registered and running
$q = (sc.exe query $svc | Out-String)
Write-Host $q
Write-Host (sc.exe qc $svc | Out-String)
Write-Host (sc.exe qdescription $svc 4096 | Out-String)
Write-Host (sc.exe qfailure $svc | Out-String)
if ($q -notmatch 'RUNNING') { throw "service $svc is not RUNNING after install" }
Note "install: service $svc RUNNING"

# 3. Default listeners
$pid_ = (Get-CimInstance Win32_Service -Filter "Name='$svc'").ProcessId
$want = @(443, 5555)
$ports = @()
for ($i = 0; $i -lt 90; $i++) {
	$ports = @(Get-ListenPorts $pid_)
	if (@($want | Where-Object { $ports -notcontains $_ }).Count -eq 0) { break }
	Start-Sleep -Seconds 1
}
netstat -ano | Select-String -Pattern "LISTENING\s+$pid_\s*$" | ForEach-Object { Write-Host $_.Line }
Note "install: vpnserver (PID $pid_) listens on TCP $($ports -join ', ')"
$missing = @($want | Where-Object { $ports -notcontains $_ })
if ($missing.Count -gt 0) { throw "vpnserver does not listen on TCP $($missing -join ', ')" }

Note "install: files in $dir after the first start:"
Get-ChildItem -LiteralPath $dir -Recurse -Force | ForEach-Object { Note "  $($_.FullName.Substring($dir.Length + 1))$(if ($_.PSIsContainer) { '\' })" }

# 4. Uninstall
$code = Invoke-Msiexec @('/x', "`"$msi`"", '/qn', '/l*v', "`"$LogDir\uninstall.log`"")
Note "uninstall: msiexec exit code $code"
if ($code -ne 0 -and $code -ne 3010) { throw "msiexec /x failed with exit code $code (see uninstall.log)" }

# 5. Service gone, process gone, MSI-owned files gone
sc.exe query $svc | Out-Null
$scCode = $LASTEXITCODE
Note "uninstall: sc query exit code $scCode (1060 = service does not exist)"
if ($scCode -ne 1060) { throw "service $svc still exists after uninstall" }
if (Get-Process -Name vpnserver -ErrorAction SilentlyContinue) { throw 'vpnserver.exe still running after uninstall' }
foreach ($f in @('vpnserver.exe', 'hamcore.se2')) {
	if (Test-Path -LiteralPath (Join-Path $dir $f)) { throw "$f still present after uninstall" }
}
Note 'uninstall: service gone, process gone, vpnserver.exe and hamcore.se2 gone'

# 6. Leftovers (not MSI-owned: written by vpnserver at run time)
if (Test-Path -LiteralPath $dir) {
	Note "uninstall: $dir is KEPT with:"
	Get-ChildItem -LiteralPath $dir -Recurse -Force | ForEach-Object { Note "  $($_.FullName.Substring($dir.Length + 1))$(if ($_.PSIsContainer) { '\' })" }
	if (Test-Path -LiteralPath (Join-Path $dir 'ranz_server.config')) { Note 'uninstall: ranz_server.config is KEPT' }
} else {
	Note "uninstall: $dir is removed (config removed)"
}
$reg = 'HKLM:\SOFTWARE\Hanzcodes\Ranz VPN'
if (Test-Path -LiteralPath $reg) {
	Note "uninstall: registry key $reg is KEPT:"
	Get-ChildItem -LiteralPath $reg -Recurse | ForEach-Object { Note "  $($_.Name)" }
	Get-ItemProperty -LiteralPath "$reg\Update Service Config" -ErrorAction SilentlyContinue | Out-String | ForEach-Object { Write-Host $_ }
} else {
	Note "uninstall: registry key $reg absent"
}

Note 'RESULT: install/uninstall test passed'
$report | Set-Content -LiteralPath "$LogDir\result.txt" -Encoding utf8
if ($env:GITHUB_STEP_SUMMARY) { ("``````" + "`n" + ($report -join "`n") + "`n" + "``````") | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Encoding utf8 -Append }
