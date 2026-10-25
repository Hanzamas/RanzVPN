param(
	[string] $Ranz,         # The signed ranz.exe of this architecture, with the signed ranz-node.exe as its Payload
	[string] $Tampered,     # The same ranz.exe, signed too, with one byte of its Payload changed
	[string] $XdpFail,      # x64 only: the same ranz.exe, signed too, with one byte of the XDP driver of its Payload changed (ONE-3, #312)
	[ValidateSet('x64', 'arm64')]
	[string] $Architecture, # The architecture of this runner
	[string] $NodeSha256,   # The SHA-256 of that signed ranz-node.exe
	[string] $MemberSha256, # The SHA-256 of the signed rqlited.exe that ranz.exe carries as the rqlite member of a Controller (ONE-4, #313)
	[string] $WintunSha256, # The SHA-256 of the wintun.dll of this architecture that ranz.exe carries, as WireGuard LLC signed it (ONE-3, #312)
	[string] $XdpSysSha256, # x64 only: the SHA-256 of the xdp.sys of the XDP runtime that ranz.exe carries, as Microsoft signed it (ONE-3, #312)
	[string] $XdpApiSha256, # ... and of its xdpapi.dll
	[string] $WireGuardSha256 # The SHA-256 of the wireguard.dll of WireGuardNT of this architecture that ranz.exe carries, as WireGuard LLC signed it (SDN-80, #375)
)

$ErrorActionPreference = 'Stop'
# Native exit codes are checked by hand below
$PSNativeCommandUseErrorActionPreference = $false

# ranz install and ranz uninstall (ONE-2, #311; ADR-0011 and ADR-0020 amendments of 2026-10-22), run from
# a folder that holds nothing but one ranz.exe, against the Ranz VPN folder under Program Files and the
# services ranzvpnserver and ranz-controller, and read from outside the process:
# - a ranz.exe whose Payload has one byte changed is refused, with a message that names ranz-node.exe and
#   its Authenticode signature: no service is registered and no Ranz VPN folder is left;
# - ranz install exits 0, ranzvpnserver is Running as its virtual account NT SERVICE\ranzvpnserver with an
#   unrestricted service SID, from ranz-node.exe in the Ranz VPN folder, and is restarted by the Service
#   Control Manager when it fails. The folder grants nothing to Users, Everyone or Authenticated Users:
#   only SYSTEM and the Administrators have full control, and the virtual accounts of the two services may
#   read and run what is in it (a service has no right to its own executable otherwise);
# - the installed ranz-node.exe is byte for byte the signed ranz-node.exe of sign_and_integrity (its
#   SHA-256), with a valid Authenticode signature (the CI self-signed certificate, trusted on this runner,
#   counts), and so is the ranz.exe that sits next to it, where the Node looks for ranz.exe bgp and where
#   the Controller service runs ranz.exe controller from: a copy of the ranz.exe that ran ranz install;
# - no ranz-controller service exists after ranz install, and ranz install --controller registers it, as
#   its virtual account, to run the ranz.exe of the Ranz VPN folder as ranz.exe controller, and starts it;
#   the Controller brings its own rqlite member (ONE-4, #313): it writes the rqlited.exe that ranz.exe
#   carries to payload\rqlited.exe under its data directory, byte for byte the signed rqlited.exe (its
#   SHA-256) with a valid signature, and runs that file, with no rqlited installed or started here;
# - ranz install again leaves one service of each name, both Running, and starts a Node that was stopped;
# - ranz uninstall removes both services and the Ranz VPN folder, and keeps the data directories of the
#   Node and of the Controller; a reinstall opens the Configuration store that the Node left (which names
#   the Node identity key), byte for byte unchanged, and logs to the node log that it kept;
# - ranz uninstall, run from the ranz.exe in the Ranz VPN folder, removes the services and the files too:
#   the running ranz.exe goes at the next restart.
#
# ONE-3 (#312) adds the drivers that the same ranz.exe carries and installs, read from outside as well:
# - ranz install writes wintun.dll of this architecture as WireGuard LLC signed it (its SHA-256, a valid signature
#   of that signer) and the NOTICE beside it, whose words are those of ranz notice. It runs on a runner whose
#   Windows Firewall blocks the outbound network for that ranz.exe, and the processes that it starts are recorded:
#   no PowerShell and no download is involved, which is what a ranz.exe alone in its folder can do;
# - on x64 it also installs SeLow and the XDP runtime: each package under drivers\ in the Ranz VPN folder, each file
#   as it is (the SeLow package of the repository, the XDP files by their SHA-256), the service of each running, the
#   files that the INF of each copies into System32, and an install record. The XDP files keep the production
#   signature of Microsoft: signtool verify /kp passes on xdp.sys, in System32 and in the package, and xdpapi.dll,
#   which carries a signature that no machine trusts for code, is a member of xdp.cat (signtool verify /c);
# - the Node reports what is there as its Capabilities, in the line "Capabilities:" of its node log (the Hello of its
#   control stream carries the same, which the default VRF tracer of windows.yml reads from the API): x64 with SeLow
#   and XDP after ranz install, arm64 with neither;
# - a ranz.exe whose xdp.sys has one byte changed installs the Node and SeLow all the same, warns that the XDP runtime
#   was not installed, leaves no trace of it, and the Node reports XDP as absent and SeLow as the fallback; so does
#   ranz install --no-xdp, which leaves the XDP runtime out on purpose, and a later ranz install adds it;
# - on arm64 only Wintun is installed: no SeLow and no XDP service, no drivers folder, and the Node reports neither;
# - ranz uninstall removes the drivers that ranz install put on the machine, and leaves a SeLow that was there before
#   (this job installs it by hand from the package of the repository first).
#
# SDN-80 (#375) adds the wireguard.dll of WireGuardNT that a gateway of WireGuard Devices loads, on both architectures:
# - ranz install writes it beside the Node as WireGuard LLC signed it (its SHA-256, a valid signature of that signer), and
#   the NOTICE holds its licence;
# - ranz install --no-wireguard leaves it out and says so, and a ranz install after it writes it.

$ranzFile = (Resolve-Path -LiteralPath $Ranz).Path
$tamperedFile = (Resolve-Path -LiteralPath $Tampered).Path
if (-not $Architecture) { throw '-Architecture names no architecture' }
$x64 = ($Architecture -eq 'x64')
if ($NodeSha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw "-NodeSha256 is not a SHA-256: '$NodeSha256'" }
if ($MemberSha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw "-MemberSha256 is not a SHA-256: '$MemberSha256'" }
if ($WintunSha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw "-WintunSha256 is not a SHA-256: '$WintunSha256'" }
if ($WireGuardSha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw "-WireGuardSha256 is not a SHA-256: '$WireGuardSha256'" }
if ($x64) {
	if ($XdpSysSha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw "-XdpSysSha256 is not a SHA-256: '$XdpSysSha256'" }
	if ($XdpApiSha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw "-XdpApiSha256 is not a SHA-256: '$XdpApiSha256'" }
	$xdpFailFile = (Resolve-Path -LiteralPath $XdpFail).Path
}

$nodeService = 'ranzvpnserver'
$controllerService = 'ranz-controller'
$nodeAccount = "NT SERVICE\$nodeService"
$controllerAccount = "NT SERVICE\$controllerService"
# The SID that Windows gives each virtual account: NODE_SERVICE_SID of src/Cedar/Node.h and serviceSID of
# controller/service_windows.go
$nodeSid = 'S-1-5-80-2319880895-1939077415-1550474732-530486738-250906376'
$controllerSid = 'S-1-5-80-3572785604-795126647-2475823641-2319294638-1653438898'
$installDir = Join-Path $env:ProgramFiles 'Ranz VPN'
$dataDir = Join-Path $env:ProgramData 'Hanzcodes\Ranz VPN'
$store = Join-Path $dataDir 'ranz_node.db'
$logDir = Join-Path $dataDir 'node_log'
$controllerData = Join-Path $env:ProgramData 'Ranz\controller'
# Where the Controller writes its rqlite member: payloadDir of controller/ and the name of the Payload
$memberFile = Join-Path $controllerData 'payload\rqlited.exe'

# The drivers (ONE-3, #312). The packages go under drivers\ in the Ranz VPN folder, a folder for each; the INF of each
# copies its files into System32 and registers its service; the install record, one value for each driver that ranz
# install put on the machine, is the key of controller/internal/install/drivers_windows.go
$driversDir = Join-Path $installDir 'drivers'
$system32 = Join-Path $env:SystemRoot 'System32'
$recordKey = 'HKLM:\SOFTWARE\Hanzcodes\Ranz VPN\Drivers'
$selowSys = Join-Path $system32 'drivers\SeLow_x64.sys'
$xdpSys = Join-Path $system32 'drivers\xdp.sys'
$xdpApi = Join-Path $system32 'xdpapi.dll'
# The SeLow package that ranz carries, as the repository holds it: the job runs in a checkout
$selowPackage = Join-Path (Get-Location).Path 'src\bin\hamcore\DriverPackages\SeLow_Win10\x64'
$firewallRule = 'ranz-install-no-network'

# A clean folder that holds only the ranz.exe of $exe, which the job then runs from: nowhere near the
# folders of the artifacts, so that it cannot find a second file next to it
function New-OneFileFolder([string] $exe) {
	$dir = Join-Path $env:RUNNER_TEMP ([IO.Path]::GetRandomFileName())
	New-Item -ItemType Directory -Force -Path $dir | Out-Null
	Copy-Item -LiteralPath $exe -Destination (Join-Path $dir 'ranz.exe')
	$files = @(Get-ChildItem -LiteralPath $dir -Force)
	if ($files.Count -ne 1 -or $files[0].Name -ne 'ranz.exe') { throw "$dir holds more than ranz.exe" }
	return (Join-Path $dir 'ranz.exe')
}

function Get-Sha256([string] $path) {
	return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}

# Run a ranz.exe with arguments: its exit code and its output, standard error included
function Invoke-Ranz([string] $exe, [string[]] $argv) {
	$out = (& $exe @argv 2>&1 | Out-String)
	$code = $LASTEXITCODE
	Write-Host "ranz $($argv -join ' '): exit $code`n$out"
	return [pscustomobject]@{ Code = $code; Out = $out }
}

# The state of a driver or a service as sc.exe names it (RUNNING, STOPPED), $null when it is not registered
function Get-DriverState([string] $name) {
	$out = (& sc.exe query $name 2>&1 | Out-String)
	$global:LASTEXITCODE = 0
	if ($out -match 'STATE\s*:\s*\d+\s+(\w+)') { return $Matches[1] }
	return $null
}

# Neither SeLow nor the XDP runtime is on the machine: no service, no install record, no file of the XDP runtime
function Assert-NoDrivers([string] $when) {
	foreach ($name in @('SeLow', 'xdp')) {
		$state = Get-DriverState $name
		if ($state) { throw "$when the service $name is registered ($state)" }
	}
	foreach ($file in @($xdpSys, $xdpApi)) {
		if (Test-Path -LiteralPath $file) { throw "$when $file is there" }
	}
	if (Test-Path -LiteralPath $recordKey) { throw "$when the install record $recordKey is there" }
	if (Test-Path -LiteralPath $driversDir) { throw "$when $driversDir is there" }
}

# The lines "Capabilities: ..." of the node log of the data directory, one for each time that a Node started
function Get-NodeCapsLines {
	return @(Get-ChildItem -LiteralPath $logDir -File -Recurse -ErrorAction SilentlyContinue | Sort-Object Name |
		Select-String -Pattern 'Capabilities: architecture \S+, SeLow (yes|no), XDP (yes|no)' | ForEach-Object { $_.Line })
}

# The Capabilities that the Node reported to its node log in a line after the first $before ones: the node log is
# written a moment after the Node starts
function Wait-NodeCaps([int] $before, [int] $seconds = 60) {
	$end = (Get-Date).AddSeconds($seconds)
	while ($true) {
		# @(): a function that returns one line gives a string, and [-1] of a string is its last character
		$lines = @(Get-NodeCapsLines)
		if ($lines.Count -gt $before -and $lines[-1] -match 'Capabilities: architecture (\S+), SeLow (yes|no), XDP (yes|no)') {
			return [pscustomobject]@{ Architecture = $Matches[1]; SeLow = ($Matches[2] -eq 'yes'); Xdp = ($Matches[3] -eq 'yes') }
		}
		if ((Get-Date) -ge $end) { throw "the Node wrote no new line of Capabilities to its node log within $seconds s ($($lines.Count) lines, $before before)" }
		Start-Sleep -Milliseconds 500
	}
}

# The Node that started after the first $before lines of Capabilities reports this architecture, SeLow and XDP
function Assert-NodeCaps([int] $before, [bool] $selow, [bool] $xdp) {
	$caps = Wait-NodeCaps $before
	if ($caps.Architecture -ne $Architecture) { throw "the Node reports the architecture $($caps.Architecture) on a $Architecture runner" }
	if ($caps.SeLow -ne $selow) { throw "the Node reports SeLow $($caps.SeLow), not $selow" }
	if ($caps.Xdp -ne $xdp) { throw "the Node reports XDP $($caps.Xdp), not $xdp" }
	Write-Host "the Node reports its Capabilities: architecture $($caps.Architecture), SeLow $($caps.SeLow), XDP $($caps.Xdp)"
}

# Windows Firewall blocks the outbound network of the program $program: what ranz install needs is in the file
function Block-Network([string] $program) {
	New-NetFirewallRule -DisplayName $firewallRule -Direction Outbound -Program $program -Action Block -Profile Any | Out-Null
	Write-Host "the outbound network is blocked for $program"
}

function Unblock-Network {
	Remove-NetFirewallRule -DisplayName $firewallRule -ErrorAction SilentlyContinue
}

# Record the processes that start, with the process that started each (a Windows Management Instrumentation event of
# Windows), until Stop-ProcessWatch gives them
function Start-ProcessWatch {
	try {
		Register-CimIndicationEvent -Query 'SELECT * FROM Win32_ProcessStartTrace' -SourceIdentifier 'ranz-processes' | Out-Null
	} catch {
		Write-Host "the process watch could not start: $($_.Exception.Message)"
	}
}

function Stop-ProcessWatch {
	# An event comes to the queue a moment after the process started
	Start-Sleep -Seconds 3
	$started = @(Get-Event -SourceIdentifier 'ranz-processes' -ErrorAction SilentlyContinue | ForEach-Object { $_.SourceEventArgs.NewEvent })
	Unregister-Event -SourceIdentifier 'ranz-processes' -ErrorAction SilentlyContinue
	Get-Event -SourceIdentifier 'ranz-processes' -ErrorAction SilentlyContinue | Remove-Event -ErrorAction SilentlyContinue
	return $started
}

# What ranz.exe started, from the processes of Start-ProcessWatch (ranz.exe of this script is the child of this
# process): none of it is PowerShell
function Assert-NoPowerShell([object[]] $started) {
	$ranzIds = @($started | Where-Object { $_.ProcessName -eq 'ranz.exe' -and $_.ParentProcessID -eq $PID } | ForEach-Object { $_.ProcessID })
	if ($ranzIds.Count -eq 0) {
		Write-Host "the process watch saw $($started.Count) processes start and no ranz.exe of this job among them: what it started is not read"
		return
	}
	$children = @($started | Where-Object { $ranzIds -contains $_.ParentProcessID })
	Write-Host "ranz.exe started $(@($children | ForEach-Object { $_.ProcessName }) -join ', ')"
	$shells = @($children | Where-Object { $_.ProcessName -match '^(powershell|pwsh)(\.exe)?$' })
	if ($shells.Count -gt 0) { throw "ranz.exe started PowerShell: $(@($shells | ForEach-Object { $_.ProcessName }) -join ', ')" }
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

# $file has a valid Authenticode signature of a signer whose name matches $signer
function Assert-Signer([string] $file, [string] $signer) {
	$sig = Get-AuthenticodeSignature -FilePath $file
	if ($sig.Status -ne 'Valid') { throw "$file has signature status $($sig.Status), not Valid" }
	if ($sig.SignerCertificate.Subject -notmatch $signer) { throw "$file is signed by $($sig.SignerCertificate.Subject), not by $signer" }
}

# signtool verify /kp: the kernel-mode driver signing policy accepts $file, which is what a production-signed driver passes
function Assert-KernelSignature([string] $file) {
	$out = (& $signtool verify /kp /v $file 2>&1 | Out-String)
	if ($LASTEXITCODE -ne 0) { throw "signtool verify /kp does not pass for ${file}:`n$out" }
	Write-Host "signtool verify /kp passes for $file"
}

# $file names $signer as its signer and is a member of the signed catalog $catalog, which signtool verify /c checks as Windows
# does. The xdpapi.dll of the XDP runtime carries a signature of the Azure Public Services of Microsoft that no machine trusts
# for code (its root is no root of Windows), so the catalog of its package is how Windows trusts it
function Assert-CatalogMember([string] $file, [string] $catalog, [string] $signer) {
	$named = (Get-AuthenticodeSignature -FilePath $file).SignerCertificate.Subject
	if ($named -notmatch $signer) { throw "$file is signed by $named, not by $signer" }
	$out = (& $signtool verify /pa /c $catalog /v $file 2>&1 | Out-String)
	if ($LASTEXITCODE -ne 0) { throw "signtool verify /c does not pass for $file against ${catalog}:`n$out" }
	Write-Host "signtool verify /c passes for $file against $catalog"
}

# The install record of ranz install names the INF that Windows published for the driver $name (oemNN.inf), or none
function Get-RecordedInf([string] $name) {
	$record = Get-ItemProperty -LiteralPath $recordKey -ErrorAction SilentlyContinue
	if ($record) { return $record.$name }
	return $null
}

# What ranz install leaves of SeLow on x64: its package under drivers\SeLow, each file byte for byte as the repository
# holds it, the service SeLow running, the driver that the INF copied into System32, and the record
function Assert-SeLowInstalled {
	$pkg = Join-Path $driversDir 'SeLow'
	foreach ($name in @('SeLow_x64.sys', 'SeLow_Win10_x64.cat', 'SeLow_x64.inf')) {
		$file = Join-Path $pkg $name
		if (-not (Test-Path -LiteralPath $file)) { throw "ranz install did not write $file" }
		if ((Get-Sha256 $file) -ne (Get-Sha256 (Join-Path $selowPackage $name))) { throw "$file is not byte for byte the file of the SeLow package of the repository" }
	}
	$state = Get-DriverState 'SeLow'
	if ($state -ne 'RUNNING') { throw "the service SeLow is '$state' after ranz install, not RUNNING" }
	if (-not (Test-Path -LiteralPath $selowSys)) { throw "$selowSys is not there: the INF of the SeLow package did not copy the driver" }
	if ((Get-Sha256 $selowSys) -ne (Get-Sha256 (Join-Path $selowPackage 'SeLow_x64.sys'))) { throw "$selowSys is not the driver of the SeLow package" }
	$inf = Get-RecordedInf 'SeLow'
	if ($inf -notmatch '^oem\d+\.inf$') { throw "the install record does not name the INF that Windows published for SeLow: '$inf'" }
	Write-Host "SeLow is installed by ranz install: the service runs, $selowSys is the driver of the package, and the install record names $inf"
}

# What ranz install leaves of the XDP runtime on x64: its package under drivers\xdp with the files as Microsoft signed
# them, the service xdp running, the driver and the API library that the INF copied into System32, and the record. The
# files keep the production signature of Microsoft, which signtool verify /kp checks on the driver and signtool verify /c
# checks on the API library, a member of the catalog.
function Assert-XdpInstalled {
	$pkg = Join-Path $driversDir 'xdp'
	foreach ($name in @('xdp.sys', 'xdpapi.dll', 'xdp.cat', 'xdp.inf', 'xdppcw.man')) {
		if (-not (Test-Path -LiteralPath (Join-Path $pkg $name))) { throw "ranz install did not write $(Join-Path $pkg $name)" }
	}
	foreach ($pair in @(@($pkg, 'xdp.sys', $XdpSysSha256), @($pkg, 'xdpapi.dll', $XdpApiSha256), @($system32, 'xdpapi.dll', $XdpApiSha256), @((Join-Path $system32 'drivers'), 'xdp.sys', $XdpSysSha256))) {
		$file = Join-Path $pair[0] $pair[1]
		if ((Get-Sha256 $file) -ne $pair[2]) { throw "$file is not byte for byte the file of the pinned XDP runtime (SHA-256 $($pair[2]))" }
	}
	$state = Get-DriverState 'xdp'
	if ($state -ne 'RUNNING') { throw "the service xdp is '$state' after ranz install, not RUNNING" }
	foreach ($file in @((Join-Path $pkg 'xdp.sys'), $xdpSys)) {
		Assert-Signer $file 'Microsoft'
		Assert-KernelSignature $file
	}
	Assert-Signer (Join-Path $pkg 'xdp.cat') 'Microsoft'
	foreach ($file in @((Join-Path $pkg 'xdpapi.dll'), $xdpApi)) { Assert-CatalogMember $file (Join-Path $pkg 'xdp.cat') 'Microsoft' }
	$inf = Get-RecordedInf 'xdp'
	if ($inf -notmatch '^oem\d+\.inf$') { throw "the install record does not name the INF that Windows published for the XDP runtime: '$inf'" }
	Write-Host "the XDP runtime is installed by ranz install: the service runs, its files are the pinned ones with the signature of Microsoft, and the install record names $inf"
}

# The drivers are there as ranz install leaves them on this architecture: on x64 SeLow, and the XDP runtime unless $withXdp is false
function Assert-DriversInstalled([bool] $withXdp) {
	if (-not $x64) {
		Soft 'on arm64 only Wintun is installed' { Assert-NoDrivers 'on arm64 only Wintun is installed, but' }
		return
	}
	Soft 'SeLow is installed' { Assert-SeLowInstalled }
	if ($withXdp) {
		Soft 'the XDP runtime is installed' { Assert-XdpInstalled }
	} else {
		Soft 'the XDP runtime is left out' {
			if (Get-DriverState 'xdp') { throw 'the service xdp is registered, and the XDP runtime was left out' }
			foreach ($file in @($xdpSys, $xdpApi, (Join-Path $driversDir 'xdp'))) {
				if (Test-Path -LiteralPath $file) { throw "$file is there, and the XDP runtime was left out" }
			}
			if (Get-RecordedInf 'xdp') { throw 'the install record names the XDP runtime, which was left out' }
			Write-Host 'the XDP runtime is not installed, and has left no trace'
		}
	}
}

# ranz uninstall took off the drivers that ranz install put on the machine: no service, no record, no folder, and no
# file in System32 but one that a running driver holds, which Windows removes at the next restart and ranz uninstall said so
function Assert-DriversRemoved([string] $output) {
	foreach ($name in @('SeLow', 'xdp')) {
		if (Get-DriverState $name) { throw "ranz uninstall left the service $name" }
	}
	if (Test-Path -LiteralPath $recordKey) { throw "ranz uninstall left the install record $recordKey" }
	if (Test-Path -LiteralPath $driversDir) { throw "ranz uninstall left $driversDir" }
	foreach ($file in @($selowSys, $xdpSys, $xdpApi)) {
		if ((Test-Path -LiteralPath $file) -and $output -notmatch [regex]::Escape("$file is in use")) { throw "ranz uninstall left $file" }
	}
	Write-Host 'ranz uninstall took off the drivers that ranz install put on the machine'
}

function Remove-InstalledState {
	Unblock-Network
	foreach ($name in @($nodeService, $controllerService)) {
		if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
			& sc.exe stop $name | Out-Null
			Start-Sleep -Seconds 2
			& sc.exe delete $name | Out-Null
		}
	}
	if (Test-Path -LiteralPath $installDir) { Remove-Item -LiteralPath $installDir -Recurse -Force -ErrorAction SilentlyContinue }
	# sc.exe fails for a service that is gone, which is no error of this script, and the exit code that
	# it leaves must not become the one of the step
	$global:LASTEXITCODE = 0
}

# No access control entry of $path names Users, Everyone or Authenticated Users
function Assert-NoUsersAccess([string] $path) {
	$denied = @('S-1-5-32-545', 'S-1-1-0', 'S-1-5-11')
	foreach ($ace in (Get-Acl -LiteralPath $path).Access) {
		$ref = $ace.IdentityReference
		if ($ref -is [System.Security.Principal.SecurityIdentifier]) {
			$sid = $ref
		} else {
			try { $sid = $ref.Translate([System.Security.Principal.SecurityIdentifier]) } catch { continue }
		}
		if ($denied -contains $sid.Value) {
			throw "$path grants $($ace.AccessControlType) $($ace.FileSystemRights) to $ref ($($sid.Value))"
		}
	}
	Write-Host "$path grants nothing to Users, Everyone or Authenticated Users"
}

# $path has an Allow entry for $account whose rights include $rights
function Assert-Access([string] $path, [string] $account, [string] $rights) {
	$grant = (Get-Acl -LiteralPath $path).Access | Where-Object {
		$_.IdentityReference.Value -eq $account -and $_.AccessControlType -eq 'Allow' -and "$($_.FileSystemRights)" -match $rights
	}
	if (-not $grant) { throw "$path does not grant $rights to $account" }
}

function Wait-ServiceState([string] $name, [string] $state, [int] $seconds = 60) {
	$end = (Get-Date).AddSeconds($seconds)
	while ($true) {
		$svc = Get-Service -Name $name -ErrorAction SilentlyContinue
		if ($svc -and $svc.Status -eq $state) { return }
		if ((Get-Date) -ge $end) { throw "$name did not reach $state within $seconds s (it is $(if ($svc) { $svc.Status } else { 'not installed' }))" }
		Start-Sleep -Milliseconds 500
	}
}

function Wait-ServiceGone([string] $name, [int] $seconds = 30) {
	$end = (Get-Date).AddSeconds($seconds)
	while (Get-Service -Name $name -ErrorAction SilentlyContinue) {
		if ((Get-Date) -ge $end) { throw "$name is still installed $seconds s after ranz uninstall" }
		Start-Sleep -Milliseconds 500
	}
}

# The lines "Node started" of the node log of the data directory: one for each time the Node ran
function Get-NodeStarts {
	return @(Get-ChildItem -LiteralPath $logDir -File -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern 'Node started' -SimpleMatch).Count
}

# The rqlite member of the Controller (ONE-4, #313): the file that the Controller wrote under its data
# directory is byte for byte the signed rqlited.exe that ranz.exe carries (its SHA-256), has a valid
# Authenticode signature, and is the file that the one rqlited.exe process runs
function Assert-Member {
	if (-not (Test-Path -LiteralPath $memberFile)) { throw "the Controller did not write its rqlite member to $memberFile" }
	if ((Get-Sha256 $memberFile) -ne $MemberSha256) { throw "$memberFile is not byte for byte the signed rqlited.exe (SHA-256 $MemberSha256)" }
	$sig = Get-AuthenticodeSignature -FilePath $memberFile
	if ($sig.Status -ne 'Valid') { throw "$memberFile has signature status $($sig.Status), not Valid" }
	$running = @(Get-CimInstance Win32_Process -Filter "Name='rqlited.exe'" | Where-Object { $_.ExecutablePath -eq $memberFile })
	if ($running.Count -ne 1) { throw "expected one rqlited.exe process that runs $memberFile, found $($running.Count)" }
	Write-Host "the Controller wrote its rqlite member, $memberFile, byte for byte the signed rqlited.exe and with a valid signature, and runs it as process $($running[0].ProcessId)"
}

# What the drivers of the machine are, as ranz install and the Node leave them: the services, the install record, the
# packages under drivers\ and the Capabilities that the Node wrote to its log
function Show-Drivers {
	foreach ($name in @('SeLow', 'xdp')) {
		$state = Get-DriverState $name
		Write-Host "driver ${name}: $(if ($state) { $state } else { 'not registered' })"
	}
	$record = Get-ItemProperty -LiteralPath $recordKey -ErrorAction SilentlyContinue
	if ($record) {
		Write-Host "install record: $(@($record.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ', ')"
	} else {
		Write-Host 'install record: none'
	}
	if (Test-Path -LiteralPath $driversDir) {
		Get-ChildItem -LiteralPath $driversDir -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $($_.FullName) $($_.Length) bytes" }
	}
	foreach ($line in @(Get-NodeCapsLines)) { Write-Host "node log: $line" }
}

# What a failed step needs to be read from the log alone
function Show-Diagnostics {
	foreach ($name in @($nodeService, $controllerService)) {
		$svc = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
		if ($svc) {
			Write-Host "service ${name}: $($svc.State), exit code $($svc.ExitCode), start name '$($svc.StartName)', path $($svc.PathName)"
		} else {
			Write-Host "service ${name}: not installed"
		}
	}
	if (Test-Path -LiteralPath $installDir) {
		Write-Host "${installDir}:"
		Get-ChildItem -LiteralPath $installDir -Force -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $($_.Name) $($_.Length) bytes" }
		& icacls.exe $installDir | ForEach-Object { Write-Host "  $_" }
	} else {
		Write-Host "${installDir}: not there"
	}
	Show-Drivers
	Write-Host 'Service Control Manager events since the start of the job:'
	Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = $since } -ErrorAction SilentlyContinue |
		Sort-Object RecordId | ForEach-Object { Write-Host ("  {0:u} id {1}: {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace '\s+', ' ')) }
	foreach ($log in @(Get-ChildItem -LiteralPath $logDir -File -Recurse -ErrorAction SilentlyContinue)) {
		Write-Host "last lines of $($log.FullName):"
		Get-Content -LiteralPath $log.FullName -Tail 40 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $_" }
	}
	$controllerLog = Join-Path $controllerData 'controller.log'
	if (Test-Path -LiteralPath $controllerLog) {
		Write-Host "last lines of ${controllerLog}:"
		Get-Content -LiteralPath $controllerLog -Tail 40 | ForEach-Object { Write-Host "  $_" }
	}
	if (Test-Path -LiteralPath $memberFile) {
		Write-Host "the rqlite member: $memberFile, $((Get-Item -LiteralPath $memberFile).Length) bytes, signature $((Get-AuthenticodeSignature -FilePath $memberFile).Status)"
	} else {
		Write-Host "the rqlite member: $memberFile is not there"
	}
}

# The steps below run one after the other, each in a try of its own, and a step that fails does not stop the next: it is
# recorded with its message, the state that it left is shown, and the machine is put back as far as it can be, so that
# the next step starts from a runner without a driver of Ranz VPN. The job fails at the end, with every step that failed.
# The drivers are new in this job and one run takes long, so one run tells all that is wrong.
$failures = New-Object System.Collections.Generic.List[string]

function Add-Failure([string] $step, $err) {
	$failures.Add("${step}: $($err.Exception.Message)")
	Write-Host "failed: ${step}: $($err.Exception.Message)"
}

# A check whose failure is recorded and does not stop its step: the checks after it tell more
function Soft([string] $step, [scriptblock] $check) {
	try {
		& $check
	} catch {
		Add-Failure $step $_
		Show-Drivers
	}
}

# ranz uninstall from a ranz.exe of this job takes off what a failed step left, as far as it recorded it
function Reset-Machine {
	foreach ($exe in @($goodExe, $failExe)) {
		if ($exe -and (Test-Path -LiteralPath $exe)) {
			$null = Invoke-Ranz $exe @('uninstall')
			break
		}
	}
	Remove-InstalledState
}

# A step that did not finish
function Fail([string] $step, $err) {
	Add-Failure $step $err
	Show-Diagnostics
	Reset-Machine
}

Remove-InstalledState
$since = Get-Date
if ($x64) { $signtool = Get-SignTool }
try {
	# 0. This runner holds neither SeLow nor the XDP runtime, so what ranz install puts there is its own
	Assert-NoDrivers 'this runner holds drivers before ranz install:'
	Write-Host "this $Architecture runner holds neither SeLow nor the XDP runtime"

	# 1. A ranz.exe whose Payload was changed: refused with a message that names the file and its
	#    signature, nothing registered, nothing left under Program Files, no driver installed.
	$tamperedExe = New-OneFileFolder $tamperedFile
	$r = Invoke-Ranz $tamperedExe @('install')
	if ($r.Code -eq 0) { throw 'ranz install with a changed Payload exited 0' }
	if ($r.Out -notmatch 'ranz-node\.exe' -or $r.Out -notmatch 'Authenticode signature') {
		throw "ranz install refused the changed Payload without naming ranz-node.exe and its Authenticode signature:`n$($r.Out)"
	}
	if (Get-Service -Name $nodeService -ErrorAction SilentlyContinue) { throw "a changed Payload still registered $nodeService" }
	if (Test-Path -LiteralPath $installDir) { throw "a changed Payload still left $installDir" }
	Assert-NoDrivers 'a changed Payload still left a driver:'
	Write-Host "a changed Payload is refused: no service is registered, no driver is installed and $installDir is not left"
} catch {
	Fail 'a runner without drivers, and a changed Payload' $_
}

try {
	# 1b. x64: a ranz.exe whose xdp.sys has one byte changed. The XDP runtime is refused for the signature of its
	#     driver and leaves no trace; the Node and SeLow are installed all the same, and the Node reports the xdp
	#     Capability as absent, with SeLow as the fallback (ADR-0002 amendment of 2026-10-21)
	if ($x64) {
		$failExe = New-OneFileFolder $xdpFailFile
		$before = (Get-NodeCapsLines).Count
		$r = Invoke-Ranz $failExe @('install')
		if ($r.Code -ne 0) { throw "ranz install with a changed XDP driver exited with code $($r.Code): a driver that fails to install leaves the Node installed" }
		if ($r.Out -notmatch 'the XDP runtime was not installed' -or $r.Out -notmatch 'xdp\.sys' -or $r.Out -notmatch 'Authenticode signature') {
			throw "ranz install did not warn that the XDP runtime was refused for the Authenticode signature of xdp.sys:`n$($r.Out)"
		}
		Wait-ServiceState $nodeService 'Running'
		Assert-DriversInstalled $false
		Soft 'the Node reports SeLow and no XDP' { Assert-NodeCaps $before $true $false }
		$r = Invoke-Ranz $failExe @('uninstall')
		if ($r.Code -ne 0) { throw "ranz uninstall after the XDP runtime that was refused exited with code $($r.Code)" }
		Wait-ServiceGone $nodeService
		Soft 'ranz uninstall removes SeLow' { Assert-DriversRemoved $r.Out }
		Write-Host 'a changed XDP driver is refused and leaves no trace: the Node is installed with SeLow, and reports XDP as absent'
	}
} catch {
	Fail 'a changed XDP driver' $_
}

try {
	# 2. ranz install: the Node service, the folder, the files, and the drivers of this architecture. Windows Firewall
	#    blocks the outbound network for this ranz.exe, and the processes that it starts are recorded: it needs no
	#    download and runs no PowerShell
	$goodExe = New-OneFileFolder $ranzFile
	$before = (Get-NodeCapsLines).Count
	Soft 'Windows Firewall blocks the outbound network for ranz.exe' { Block-Network $goodExe }
	Start-ProcessWatch
	try {
		$r = Invoke-Ranz $goodExe @('install')
	} finally {
		$started = Stop-ProcessWatch
		Unblock-Network
	}
	if ($r.Code -ne 0) { throw "ranz install exited with code $($r.Code)" }
	Assert-NoPowerShell $started
	if (-not $x64 -and $r.Out -notmatch 'carries Wintun only') { throw "ranz install on arm64 did not say that Wintun is the only driver:`n$($r.Out)" }

	Wait-ServiceState $nodeService 'Running'
	$svc = Get-CimInstance Win32_Service -Filter "Name='$nodeService'"
	if ($svc.StartName -ne $nodeAccount) { throw "$nodeService runs as '$($svc.StartName)', not its virtual account $nodeAccount" }
	if ($svc.PathName -ne "`"$installDir\ranz-node.exe`" /service") { throw "$nodeService runs '$($svc.PathName)', not ranz-node.exe of $installDir with /service" }
	$sidType = (& sc.exe qsidtype $nodeService | Out-String)
	if ($sidType -notmatch 'UNRESTRICTED') { throw "the service SID type of $nodeService is not unrestricted:`n$sidType" }
	$sid = (& sc.exe showsid $nodeService | Out-String)
	if ($sid -notmatch [regex]::Escape($nodeSid)) { throw "Windows gives $nodeAccount another SID than $nodeSid`:`n$sid" }
	$failure = (& sc.exe qfailure $nodeService | Out-String)
	if ($failure -notmatch 'RESTART') { throw "$nodeService is not restarted when it fails:`n$failure" }
	Write-Host "$nodeService is Running as $nodeAccount ($nodeSid) with an unrestricted service SID, from $($svc.PathName), and is restarted when it fails"

	if (-not (Test-Path -LiteralPath $installDir)) { throw "$installDir was not made" }
	Assert-NoUsersAccess $installDir
	Assert-Access $installDir 'NT AUTHORITY\SYSTEM' 'FullControl'
	Assert-Access $installDir 'BUILTIN\Administrators' 'FullControl'
	Assert-Access $installDir $nodeAccount 'ReadAndExecute'
	$acl = Get-Acl -LiteralPath $installDir
	if (-not $acl.AreAccessRulesProtected) { throw "$installDir inherits its access list from Program Files" }
	if (@($acl.Access).Count -ne 4) { throw "the access list of $installDir has $(@($acl.Access).Count) entries, not SYSTEM, the Administrators and the two service accounts:`n$($acl.AccessToString)" }
	Write-Host "the access list of ${installDir}: $($acl.AccessToString -replace '\s+', ' ')"

	# The files of the Ranz VPN folder: the Node, ranz.exe, the Wintun DLL and the NOTICE that holds its licence, the
	# WireGuardNT DLL, and on x64 the folder of the packages of the drivers; every executable and DLL has a valid
	# Authenticode signature
	$expected = @('NOTICE.txt', 'ranz-node.exe', 'ranz.exe', 'wintun.dll', 'wireguard.dll')
	if ($x64) { $expected += 'drivers' }
	$names = @(Get-ChildItem -LiteralPath $installDir -Force | ForEach-Object { $_.Name })
	if (Compare-Object -ReferenceObject $expected -DifferenceObject $names) { throw "$installDir holds $($names -join ', '), not $($expected -join ', ')" }
	foreach ($name in $names) {
		$file = Join-Path $installDir $name
		Assert-NoUsersAccess $file
		if ($name -match '\.(exe|dll)$') {
			$sig = Get-AuthenticodeSignature -FilePath $file
			if ($sig.Status -ne 'Valid') { throw "$file has signature status $($sig.Status), not Valid" }
		}
	}
	$installedNode = Join-Path $installDir 'ranz-node.exe'
	if ((Get-Sha256 $installedNode) -ne $NodeSha256) { throw "$installedNode is not byte for byte the signed ranz-node.exe (SHA-256 $NodeSha256)" }
	$installedRanz = Join-Path $installDir 'ranz.exe'
	if ((Get-Sha256 $installedRanz) -ne (Get-Sha256 $ranzFile)) { throw "$installedRanz is not byte for byte the ranz.exe that ran ranz install" }
	Write-Host "$installedNode is the signed ranz-node.exe byte for byte, $installedRanz is a copy of the ranz.exe that ran ranz install, and both have a valid Authenticode signature"
	$version = (& $installedRanz version | Out-String).Trim()
	if ($LASTEXITCODE -ne 0 -or $version -notmatch '^ranz \d+\.\d+\.\d+$') { throw "$installedRanz version printed '$version' (exit code $LASTEXITCODE)" }
	Write-Host "the installed ranz.exe runs: $version"

	# The Wintun DLL as WireGuard LLC signed it (its licence lets it be redistributed unmodified only), and the NOTICE
	# beside it, which holds the words of ranz notice and so the licence of Wintun
	$installedWintun = Join-Path $installDir 'wintun.dll'
	if ((Get-Sha256 $installedWintun) -ne $WintunSha256) { throw "$installedWintun is not byte for byte the wintun.dll that ranz.exe carries (SHA-256 $WintunSha256)" }
	Assert-Signer $installedWintun 'WireGuard LLC'
	$noticeFile = Join-Path $installDir 'NOTICE.txt'
	$installedNotice = ((Get-Content -Raw -LiteralPath $noticeFile) -split '\s+' | Where-Object { $_ }) -join ' '
	$printedNotice = ((& $installedRanz notice | Out-String) -split '\s+' | Where-Object { $_ }) -join ' '
	if (-not $printedNotice -or $installedNotice -ne $printedNotice) { throw "$noticeFile does not hold the words of ranz notice" }
	if ($installedNotice -notmatch 'Wintun') { throw "$noticeFile does not hold the licence of Wintun" }
	Write-Host "$installedWintun is the wintun.dll that ranz.exe carries, signed by WireGuard LLC, and $noticeFile holds the NOTICE with its licence"
	# The WireGuardNT DLL as WireGuard LLC signed it, which a gateway of WireGuard Devices loads (SDN-80, #375)
	$installedWireGuard = Join-Path $installDir 'wireguard.dll'
	if ((Get-Sha256 $installedWireGuard) -ne $WireGuardSha256) { throw "$installedWireGuard is not byte for byte the wireguard.dll that ranz.exe carries (SHA-256 $WireGuardSha256)" }
	Assert-Signer $installedWireGuard 'WireGuard LLC'
	if ($installedNotice -notmatch 'WireGuardNT') { throw "$noticeFile does not hold the licence of WireGuardNT" }
	Write-Host "$installedWireGuard is the wireguard.dll that ranz.exe carries, signed by WireGuard LLC, and $noticeFile holds its licence too"

	# The drivers of this architecture, and the Node that started after them reports them as its Capabilities: on x64
	# SeLow and the XDP runtime, on arm64 neither
	Assert-DriversInstalled $true
	Soft 'the Node reports the Capabilities of its host' { Assert-NodeCaps $before $x64 $x64 }

	if (-not (Test-Path -LiteralPath $store)) { throw "$store (the Configuration store of the Node) was not made" }

	# 3. No Controller service without --controller
	if (Get-Service -Name $controllerService -ErrorAction SilentlyContinue) { throw "$controllerService exists although ranz install ran without --controller" }
	Write-Host "no $controllerService without --controller"

	# 4. ranz install --controller also registers and starts the Controller service, which brings its
	#    own rqlite member: nothing else is installed or started for its store
	$r = Invoke-Ranz $goodExe @('install', '--controller')
	if ($r.Code -ne 0) { throw "ranz install --controller exited with code $($r.Code)" }
	Wait-ServiceState $controllerService 'Running'
	$csvc = Get-CimInstance Win32_Service -Filter "Name='$controllerService'"
	if ($csvc.StartName -ne $controllerAccount) { throw "$controllerService runs as '$($csvc.StartName)', not its virtual account $controllerAccount" }
	if ($csvc.PathName -ne "`"$installedRanz`" controller") { throw "$controllerService runs '$($csvc.PathName)', not the ranz.exe of $installDir with controller" }
	$csid = (& sc.exe showsid $controllerService | Out-String)
	if ($csid -notmatch [regex]::Escape($controllerSid)) { throw "Windows gives $controllerAccount another SID than ${controllerSid}:`n$csid" }
	Assert-Access $installDir $controllerAccount 'ReadAndExecute'
	Wait-ServiceState $nodeService 'Running'
	Write-Host "$controllerService is Running as $controllerAccount, from $($csvc.PathName); $nodeService still runs"
	Assert-Member

	# 5. Idempotent: install again leaves one service of each name, both Running, and a Node that was
	#    stopped runs again
	$r = Invoke-Ranz $goodExe @('install', '-controller')
	if ($r.Code -ne 0) { throw "the second ranz install -controller exited with code $($r.Code)" }
	# The drivers that it put there are not installed again, and are still its own, so that uninstall removes them
	if ($x64 -and ($r.Out -notmatch 'the SeLow driver is installed already' -or $r.Out -notmatch 'the XDP runtime is installed already')) {
		throw "the second ranz install did not say that SeLow and the XDP runtime are installed already:`n$($r.Out)"
	}
	Assert-DriversInstalled $true
	foreach ($name in @($nodeService, $controllerService)) {
		$count = @(Get-CimInstance Win32_Service -Filter "Name='$name'").Count
		if ($count -ne 1) { throw "$count services are named $name after ranz install ran twice" }
	}
	Wait-ServiceState $nodeService 'Running'
	Wait-ServiceState $controllerService 'Running'
	Stop-Service -Name $nodeService
	$r = Invoke-Ranz $goodExe @('install')
	if ($r.Code -ne 0) { throw "ranz install over a stopped Node exited with code $($r.Code)" }
	Wait-ServiceState $nodeService 'Running'
	Write-Host 'ranz install again leaves one service of each name, both Running, and starts a Node that was stopped'

	# 6. ranz uninstall: both services and the Ranz VPN folder go, the data directories stay
	$r = Invoke-Ranz $goodExe @('uninstall')
	if ($r.Code -ne 0) { throw "ranz uninstall exited with code $($r.Code)" }
	foreach ($name in @($nodeService, $controllerService)) { Wait-ServiceGone $name }
	if (Test-Path -LiteralPath $installDir) { throw "ranz uninstall left $installDir" }
	Soft 'ranz uninstall removes the drivers it installed' { Assert-DriversRemoved $r.Out }
	if (-not (Test-Path -LiteralPath $store)) { throw "ranz uninstall removed the Configuration store of the Node, $store" }
	$starts = Get-NodeStarts
	if ($starts -lt 1) { throw "ranz uninstall removed the node log in $logDir" }
	if (-not (Test-Path -LiteralPath (Join-Path $controllerData 'admin.token'))) { throw "ranz uninstall removed the data directory of the Controller, $controllerData" }
	# The Node has stopped, so its store is closed: this is the file that a reinstall must find again
	$storeHash = Get-Sha256 $store
	Write-Host "ranz uninstall removed both services and $installDir, and kept $dataDir and $controllerData"
	$r = Invoke-Ranz $goodExe @('uninstall')
	if ($r.Code -ne 0) { throw "ranz uninstall of what is already removed exited with code $($r.Code)" }

	# 7. A reinstall resumes with the Configuration store that the Node left, which names its identity
	#    key (CONTEXT.md, Node): unchanged, and logged to the node log that was kept. Install and
	#    uninstall never touch the key storage provider that holds the key.
	$before = (Get-NodeCapsLines).Count
	$r = Invoke-Ranz $goodExe @('install')
	if ($r.Code -ne 0) { throw "the reinstall exited with code $($r.Code)" }
	Wait-ServiceState $nodeService 'Running'
	Assert-DriversInstalled $true
	Soft 'the reinstalled Node reports the Capabilities of its host' { Assert-NodeCaps $before $x64 $x64 }
	# Stopping the Node closes its store and its log
	Stop-Service -Name $nodeService
	if ((Get-Sha256 $store) -ne $storeHash) { throw "a reinstall changed the Configuration store of the Node, which names its identity key" }
	if ((Get-NodeStarts) -le $starts) { throw "the reinstalled Node did not log to the node log that uninstall kept ($starts starts before, $(Get-NodeStarts) after)" }
	Write-Host 'a reinstall resumes with the same Configuration store, and so the same Node identity key, and the same node log'
	Start-Service -Name $nodeService

	# 8. ranz uninstall from the ranz.exe of the Ranz VPN folder: the services and the other files go,
	#    that ranz.exe, which runs, at the next restart
	$r = Invoke-Ranz $installedRanz @('uninstall')
	if ($r.Code -ne 0) { throw "ranz uninstall from $installedRanz exited with code $($r.Code)" }
	foreach ($name in @($nodeService, $controllerService)) { Wait-ServiceGone $name }
	$left = @(Get-ChildItem -LiteralPath $installDir -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
	if ($left.Count -gt 1 -or ($left.Count -eq 1 -and $left[0] -ne 'ranz.exe')) { throw "ranz uninstall from $installedRanz left $($left -join ', ') in $installDir" }
	Soft 'ranz uninstall from the installed ranz.exe removes the drivers' { Assert-DriversRemoved $r.Out }
	Write-Host "ranz uninstall from $installedRanz removed the services, the drivers and the other files; what is left in ${installDir}: $($left -join ', ')"
} catch {
	Fail 'ranz install and ranz uninstall' $_
}

try {
	# 9. ranz install --no-xdp leaves the XDP runtime out on purpose: the Node reports no xdp Capability and SeLow is
	#    its L2 backend (on arm64 the flag changes nothing, there is no XDP runtime to leave out). A ranz install after
	#    it adds the XDP runtime, and the Node that ran restarts, so that it reports it.
	Remove-InstalledState
	$before = (Get-NodeCapsLines).Count
	$r = Invoke-Ranz $goodExe @('install', '--no-xdp')
	if ($r.Code -ne 0) { throw "ranz install --no-xdp exited with code $($r.Code)" }
	if ($x64 -and $r.Out -notmatch '--no-xdp') { throw "ranz install --no-xdp did not say that it left the XDP runtime out:`n$($r.Out)" }
	Wait-ServiceState $nodeService 'Running'
	Assert-DriversInstalled $false
	Soft 'the Node reports no XDP after --no-xdp' { Assert-NodeCaps $before $x64 $false }
	if ($x64) {
		$before = (Get-NodeCapsLines).Count
		$r = Invoke-Ranz $goodExe @('install')
		if ($r.Code -ne 0) { throw "ranz install after --no-xdp exited with code $($r.Code)" }
		Wait-ServiceState $nodeService 'Running'
		Assert-DriversInstalled $true
		Soft 'the Node that ran reports XDP after the install that added it' { Assert-NodeCaps $before $true $true }
	}
	$r = Invoke-Ranz $goodExe @('uninstall')
	if ($r.Code -ne 0) { throw "ranz uninstall after --no-xdp exited with code $($r.Code)" }
	Wait-ServiceGone $nodeService
	Soft 'ranz uninstall removes the drivers installed after --no-xdp' { Assert-DriversRemoved $r.Out }
	Write-Host 'ranz install --no-xdp leaves the XDP runtime out, and a ranz install after it adds it'
} catch {
	Fail 'ranz install --no-xdp' $_
}

try {
	# 9b. ranz install --no-wireguard leaves wireguard.dll of WireGuardNT out on purpose (SDN-80, #375), on a Node that is the
	#     gateway of no WireGuard Device; a ranz install after it writes the DLL.
	Remove-InstalledState
	$installedWireGuard = Join-Path $installDir 'wireguard.dll'
	$r = Invoke-Ranz $goodExe @('install', '--no-wireguard')
	if ($r.Code -ne 0) { throw "ranz install --no-wireguard exited with code $($r.Code)" }
	if ($r.Out -notmatch 'wireguard\.dll is left out \(--no-wireguard\)') { throw "ranz install --no-wireguard did not say that it left wireguard.dll out:`n$($r.Out)" }
	Wait-ServiceState $nodeService 'Running'
	if (Test-Path -LiteralPath $installedWireGuard) { throw "ranz install --no-wireguard wrote $installedWireGuard" }
	$r = Invoke-Ranz $goodExe @('install')
	if ($r.Code -ne 0) { throw "ranz install after --no-wireguard exited with code $($r.Code)" }
	if (-not (Test-Path -LiteralPath $installedWireGuard) -or (Get-Sha256 $installedWireGuard) -ne $WireGuardSha256) {
		throw "ranz install after --no-wireguard did not write $installedWireGuard byte for byte (SHA-256 $WireGuardSha256)"
	}
	$r = Invoke-Ranz $goodExe @('uninstall')
	if ($r.Code -ne 0) { throw "ranz uninstall after --no-wireguard exited with code $($r.Code)" }
	Wait-ServiceGone $nodeService
	Soft 'ranz uninstall removes the drivers installed after --no-wireguard' { Assert-DriversRemoved $r.Out }
	Write-Host 'ranz install --no-wireguard leaves wireguard.dll out, and a ranz install after it writes it'
} catch {
	Fail 'ranz install --no-wireguard' $_
}

try {
	# 10. x64: a SeLow that was on the machine before ranz install stays at ranz uninstall. This job installs it as the
	#     fork does, by hand from its package; ranz install does not take it for its own, installs the XDP runtime beside
	#     it, and ranz uninstall removes the XDP runtime and leaves SeLow.
	if ($x64) {
		Remove-InstalledState
		$netcfg = Join-Path $system32 'netcfg.exe'
		& $netcfg -v -l (Join-Path $selowPackage 'SeLow_x64.inf') -c p -i SeLow | Out-Host
		if ($LASTEXITCODE -ne 0) { throw "netcfg could not install SeLow by hand: exit code $LASTEXITCODE" }
		if (-not (Get-DriverState 'SeLow')) { throw 'SeLow was installed by hand, and its service is not registered' }
		$r = Invoke-Ranz $goodExe @('install')
		if ($r.Code -ne 0) { throw "ranz install over a SeLow that was there before exited with code $($r.Code)" }
		if ($r.Out -notmatch 'the SeLow driver is on this machine already') { throw "ranz install did not say that SeLow was on the machine already:`n$($r.Out)" }
		if (Get-RecordedInf 'SeLow') { throw 'the install record names the SeLow that was there before ranz install' }
		Wait-ServiceState $nodeService 'Running'
		Soft 'the XDP runtime is installed beside the SeLow that was there before' { Assert-XdpInstalled }
		$r = Invoke-Ranz $goodExe @('uninstall')
		if ($r.Code -ne 0) { throw "ranz uninstall over a SeLow that was there before exited with code $($r.Code)" }
		Wait-ServiceGone $nodeService
		if ($r.Out -notmatch 'the SeLow driver was on this machine before ranz install') { throw "ranz uninstall did not say that SeLow stays:`n$($r.Out)" }
		if (-not (Get-DriverState 'SeLow')) { throw 'ranz uninstall removed the SeLow that was on the machine before ranz install' }
		foreach ($path in @($xdpSys, $xdpApi, $recordKey)) {
			if (Test-Path -LiteralPath $path) { throw "ranz uninstall left $path, which it put there" }
		}
		if (Get-DriverState 'xdp') { throw 'ranz uninstall left the service xdp, which it installed' }
		Write-Host 'ranz uninstall removed the XDP runtime that it installed and left the SeLow that was there before'
	}
} catch {
	Fail 'a SeLow that was there before ranz install' $_
}

# The SeLow that this job installed by hand goes again, whatever the step did
if ($x64 -and (Get-DriverState 'SeLow')) {
	& (Join-Path $system32 'netcfg.exe') -u SeLow | Out-Host
	$global:LASTEXITCODE = 0
}
Remove-InstalledState

if ($failures.Count -gt 0) {
	Write-Host "$($failures.Count) steps failed:"
	foreach ($f in $failures) { Write-Host "  $f" }
	throw "$($failures.Count) steps of the install job failed: $($failures -join '; ')"
}

Write-Host 'ok'
