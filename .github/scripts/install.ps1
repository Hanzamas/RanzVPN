param(
	[string] $Ranz,        # The signed ranz.exe of this architecture, with the signed ranz-node.exe as its Payload
	[string] $Tampered,    # The same ranz.exe, signed too, with one byte of its Payload changed
	[string] $NodeSha256,  # The SHA-256 of that signed ranz-node.exe
	[string] $Rqlited      # rqlited.exe, the store of the Controller service until ONE-4 (#313) puts an rqlite member in ranz.exe
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
#   its virtual account, to run the ranz.exe of the Ranz VPN folder as ranz.exe controller, and starts it
#   (with the rqlite that it stores its intent in, which this script runs);
# - ranz install again leaves one service of each name, both Running, and starts a Node that was stopped;
# - ranz uninstall removes both services and the Ranz VPN folder, and keeps the data directories of the
#   Node and of the Controller; a reinstall opens the Configuration store that the Node left (which names
#   the Node identity key), byte for byte unchanged, and logs to the node log that it kept;
# - ranz uninstall, run from the ranz.exe in the Ranz VPN folder, removes the services and the files too:
#   the running ranz.exe goes at the next restart.

$ranzFile = (Resolve-Path -LiteralPath $Ranz).Path
$tamperedFile = (Resolve-Path -LiteralPath $Tampered).Path
if ($NodeSha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw "-NodeSha256 is not a SHA-256: '$NodeSha256'" }
$rqlitedFile = (Resolve-Path -LiteralPath $Rqlited).Path

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
$rqliteData = Join-Path $env:RUNNER_TEMP 'ranz-install-rqlite'
$rqliteOut = Join-Path $env:RUNNER_TEMP 'ranz-install-rqlited.out'
$rqliteErr = Join-Path $env:RUNNER_TEMP 'ranz-install-rqlited.err'
$script:rqlite = $null

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

function Remove-InstalledState {
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

# The rqlite that the Controller service stores its intent in, at the address that the Controller uses
# when it is given no -rqlited: 127.0.0.1:4001
function Start-Rqlite {
	Remove-Item -LiteralPath $rqliteData -Recurse -Force -ErrorAction SilentlyContinue
	New-Item -ItemType Directory -Force -Path $rqliteData | Out-Null
	$script:rqlite = Start-Process -FilePath $rqlitedFile -PassThru -WindowStyle Hidden -RedirectStandardOutput $rqliteOut -RedirectStandardError $rqliteErr `
		-ArgumentList @('-node-id', '1', '-http-addr', '127.0.0.1:4001', '-raft-addr', '127.0.0.1:4002', $rqliteData)
	$end = (Get-Date).AddSeconds(60)
	while ($true) {
		try {
			$ready = Invoke-WebRequest -Uri 'http://127.0.0.1:4001/readyz' -UseBasicParsing -TimeoutSec 2
			if ($ready.StatusCode -eq 200) { break }
		} catch {
			# not ready yet
		}
		if ($script:rqlite.HasExited) { throw "rqlited exited with code $($script:rqlite.ExitCode) before it was ready" }
		if ((Get-Date) -ge $end) { throw 'rqlited is not ready within 60 s' }
		Start-Sleep -Milliseconds 500
	}
	Write-Host "rqlited is ready (process $($script:rqlite.Id))"
}

function Stop-Rqlite {
	if ($script:rqlite -and -not $script:rqlite.HasExited) { Stop-Process -Id $script:rqlite.Id -Force -ErrorAction SilentlyContinue }
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
	foreach ($log in @($rqliteOut, $rqliteErr)) {
		if (Test-Path -LiteralPath $log) {
			Write-Host "last lines of ${log}:"
			Get-Content -LiteralPath $log -Tail 20 | ForEach-Object { Write-Host "  $_" }
		}
	}
}

Remove-InstalledState
$since = Get-Date
try {
	# 1. A ranz.exe whose Payload was changed: refused with a message that names the file and its
	#    signature, nothing registered, nothing left under Program Files.
	$tamperedExe = New-OneFileFolder $tamperedFile
	$r = Invoke-Ranz $tamperedExe @('install')
	if ($r.Code -eq 0) { throw 'ranz install with a changed Payload exited 0' }
	if ($r.Out -notmatch 'ranz-node\.exe' -or $r.Out -notmatch 'Authenticode signature') {
		throw "ranz install refused the changed Payload without naming ranz-node.exe and its Authenticode signature:`n$($r.Out)"
	}
	if (Get-Service -Name $nodeService -ErrorAction SilentlyContinue) { throw "a changed Payload still registered $nodeService" }
	if (Test-Path -LiteralPath $installDir) { throw "a changed Payload still left $installDir" }
	Write-Host "a changed Payload is refused: no service is registered and $installDir is not left"

	# 2. ranz install: the Node service, the folder, the files
	$goodExe = New-OneFileFolder $ranzFile
	$r = Invoke-Ranz $goodExe @('install')
	if ($r.Code -ne 0) { throw "ranz install exited with code $($r.Code)" }

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

	$names = @(Get-ChildItem -LiteralPath $installDir -Force | ForEach-Object { $_.Name })
	if ($names.Count -ne 2 -or $names -notcontains 'ranz-node.exe' -or $names -notcontains 'ranz.exe') { throw "$installDir holds $($names -join ', '), not ranz-node.exe and ranz.exe" }
	foreach ($name in $names) {
		$file = Join-Path $installDir $name
		Assert-NoUsersAccess $file
		$sig = Get-AuthenticodeSignature -FilePath $file
		if ($sig.Status -ne 'Valid') { throw "$file has signature status $($sig.Status), not Valid" }
	}
	$installedNode = Join-Path $installDir 'ranz-node.exe'
	if ((Get-Sha256 $installedNode) -ne $NodeSha256) { throw "$installedNode is not byte for byte the signed ranz-node.exe (SHA-256 $NodeSha256)" }
	$installedRanz = Join-Path $installDir 'ranz.exe'
	if ((Get-Sha256 $installedRanz) -ne (Get-Sha256 $ranzFile)) { throw "$installedRanz is not byte for byte the ranz.exe that ran ranz install" }
	Write-Host "$installedNode is the signed ranz-node.exe byte for byte, $installedRanz is a copy of the ranz.exe that ran ranz install, and both have a valid Authenticode signature"
	$version = (& $installedRanz version | Out-String).Trim()
	if ($LASTEXITCODE -ne 0 -or $version -notmatch '^ranz \d+\.\d+\.\d+$') { throw "$installedRanz version printed '$version' (exit code $LASTEXITCODE)" }
	Write-Host "the installed ranz.exe runs: $version"

	if (-not (Test-Path -LiteralPath $store)) { throw "$store (the Configuration store of the Node) was not made" }

	# 3. No Controller service without --controller
	if (Get-Service -Name $controllerService -ErrorAction SilentlyContinue) { throw "$controllerService exists although ranz install ran without --controller" }
	Write-Host "no $controllerService without --controller"

	# 4. ranz install --controller also registers and starts the Controller service
	Start-Rqlite
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

	# 5. Idempotent: install again leaves one service of each name, both Running, and a Node that was
	#    stopped runs again
	$r = Invoke-Ranz $goodExe @('install', '-controller')
	if ($r.Code -ne 0) { throw "the second ranz install -controller exited with code $($r.Code)" }
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
	$r = Invoke-Ranz $goodExe @('install')
	if ($r.Code -ne 0) { throw "the reinstall exited with code $($r.Code)" }
	Wait-ServiceState $nodeService 'Running'
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
	Write-Host "ranz uninstall from $installedRanz removed the services and the other files; what is left in ${installDir}: $($left -join ', ')"
} catch {
	Write-Host "failed: $($_.Exception.Message)"
	Show-Diagnostics
	throw
} finally {
	Stop-Rqlite
	Remove-InstalledState
}

Write-Host 'ok'
