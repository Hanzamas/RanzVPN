param(
	[string] $BuildDir,
	[string] $ReferenceNode
)

$ErrorActionPreference = 'Stop'

# ranz install and ranz uninstall (ONE-2, #311; ADR-0011 and ADR-0020 amendments of 2026-10-22), run
# from a folder that holds only ranz.exe (the one-executable product: no second file, no second
# download) against the Ranz VPN folder under Program Files and the ranzvpnserver service:
# - ranz install exits 0, ranzvpnserver reaches the Running state under its virtual account with an
#   unrestricted service SID, and the Ranz VPN folder grants nothing to Users, Everyone or
#   Authenticated Users;
# - the installed ranz-node.exe is byte for byte the payload and its Authenticode signature is
#   Valid (the CI self-signed certificate, trusted on this runner, counts);
# - a build whose embedded payload was altered (ranz-tampered.exe, built from the same folder
#   discipline as ranz.exe) is refused, writes nothing under the Ranz VPN folder and starts no
#   service;
# - ranz install -controller also registers and starts ranz-controller; a plain ranz install does
#   not;
# - running ranz install again leaves one service of each name, both Running;
# - ranz uninstall removes both services and the Ranz VPN folder, and leaves the Node's data
#   directory (and so its Configuration store and identity key) in place, and a reinstall resumes
#   from it unchanged.

$ranz = Join-Path $BuildDir 'ranz.exe'
$tampered = Join-Path $BuildDir 'ranz-tampered.exe'
$reference = (Resolve-Path -LiteralPath $ReferenceNode).Path

$nodeService = 'ranzvpnserver'
$controllerService = 'ranz-controller'
$nodeAccount = "NT SERVICE\$nodeService"
$installDir = Join-Path $env:ProgramFiles 'Ranz VPN'
$dataDir = Join-Path $env:ProgramData 'Hanzcodes\Ranz VPN'
$store = Join-Path $dataDir 'ranz_node.db'

function New-OneFileFolder([string] $exe) {
	# A clean folder that holds only ranz.exe (or the tampered build): the acceptance criterion that
	# the one ranz.exe is the only file the job copies to the runner, proven by running it from
	# nowhere near $BuildDir, which also holds the other build.
	$dir = Join-Path $env:RUNNER_TEMP ([IO.Path]::GetRandomFileName())
	New-Item -ItemType Directory -Force -Path $dir | Out-Null
	Copy-Item -LiteralPath $exe -Destination (Join-Path $dir 'ranz.exe')
	return (Join-Path $dir 'ranz.exe')
}

function Get-Sha256([string] $path) {
	return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}

function Remove-InstalledState {
	foreach ($name in @($nodeService, $controllerService)) {
		if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
			& sc.exe stop $name | Out-Null
			Start-Sleep -Seconds 1
			& sc.exe delete $name | Out-Null
		}
	}
	if (Test-Path -LiteralPath $installDir) { Remove-Item -LiteralPath $installDir -Recurse -Force -ErrorAction SilentlyContinue }
	$global:LASTEXITCODE = 0
}

# The Ranz VPN folder must grant nothing to Users, Everyone or Authenticated Users: no ACE of path
# names one of those principals.
function Assert-NoUsersAccess([string] $path) {
	$denied = @(
		(New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')), # BUILTIN\Users
		(New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')),      # Everyone
		(New-Object System.Security.Principal.SecurityIdentifier('S-1-5-11'))      # Authenticated Users
	)
	$acl = Get-Acl -LiteralPath $path
	foreach ($ace in $acl.Access) {
		$sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
		if ($denied -contains $sid) {
			throw "$path grants $($ace.AccessControlType) $($ace.FileSystemRights) to $($ace.IdentityReference) ($sid)"
		}
	}
	Write-Host "$path grants nothing to Users, Everyone or Authenticated Users"
}

function Assert-FullControl([string] $path, [string] $account) {
	$acl = Get-Acl -LiteralPath $path
	$grant = $acl.Access | Where-Object {
		$_.IdentityReference.Value -eq $account -and $_.AccessControlType -eq 'Allow' -and $_.FileSystemRights -match 'FullControl'
	}
	if (-not $grant) { throw "$path does not grant FullControl to $account" }
}

function Wait-ServiceState([string] $name, [string] $state, [int] $seconds = 30) {
	$end = (Get-Date).AddSeconds($seconds)
	while ($true) {
		$svc = Get-Service -Name $name -ErrorAction SilentlyContinue
		if ($svc -and $svc.Status -eq $state) { return $svc }
		if ((Get-Date) -ge $end) { throw "$name did not reach $state within $seconds s (it is $(if ($svc) { $svc.Status } else { 'not installed' }))" }
		Start-Sleep -Milliseconds 500
	}
}

function Invoke-Ranz([string] $exe, [string[]] $argv) {
	$out = (& $exe @argv 2>&1 | Out-String)
	Write-Host "$(Split-Path -Leaf $exe) $($argv -join ' '): exit $LASTEXITCODE`n$out"
	return $out
}

Remove-InstalledState
try {
	# 1. A build whose embedded ranz-node.exe was altered: refused, nothing registered, nothing
	#    written under the Ranz VPN folder.
	$tamperedExe = New-OneFileFolder $tampered
	Invoke-Ranz $tamperedExe @('install') | Out-Null
	if ($LASTEXITCODE -eq 0) { throw 'ranz install with a tampered embedded payload exited 0' }
	if (Get-Service -Name $nodeService -ErrorAction SilentlyContinue) { throw "a tampered payload still registered $nodeService" }
	if (Test-Path -LiteralPath $installDir) { throw "a tampered payload still created $installDir" }
	Write-Host "a tampered embedded payload is refused: no service registered, $installDir not created"

	# 2. ranz install: the Node service, the folder's access list, the payload itself
	$goodExe = New-OneFileFolder $ranz
	Invoke-Ranz $goodExe @('install') | Out-Null
	if ($LASTEXITCODE -ne 0) { throw "ranz install exited with code $LASTEXITCODE" }

	Wait-ServiceState $nodeService 'Running' | Out-Null
	$svc = Get-CimInstance Win32_Service -Filter "Name='$nodeService'"
	if ($svc.StartName -ne $nodeAccount) { throw "$nodeService runs as '$($svc.StartName)', not its virtual account $nodeAccount" }
	$sidType = (& sc.exe qsidtype $nodeService | Out-String)
	if ($sidType -notmatch 'UNRESTRICTED') { throw "the service SID type of $nodeService is not unrestricted:`n$sidType" }
	Write-Host "$nodeService is Running as $nodeAccount with an unrestricted service SID"

	if (-not (Test-Path -LiteralPath $installDir)) { throw "$installDir was not created" }
	Assert-NoUsersAccess $installDir
	Assert-FullControl $installDir 'NT AUTHORITY\SYSTEM'
	Assert-FullControl $installDir 'BUILTIN\Administrators'

	$installedNode = Join-Path $installDir 'ranz-node.exe'
	if (-not (Test-Path -LiteralPath $installedNode)) { throw "$installedNode was not installed" }
	if ((Get-Sha256 $installedNode) -ne (Get-Sha256 $reference)) { throw "$installedNode is not byte for byte the payload" }
	$sig = Get-AuthenticodeSignature -FilePath $installedNode
	if ($sig.Status -ne 'Valid') { throw "$installedNode has signature status $($sig.Status), not Valid" }
	Write-Host "$installedNode is byte for byte the payload, and its Authenticode signature is Valid"

	if (-not (Test-Path -LiteralPath $store)) { throw "$store (the Node's Configuration store) was not created" }
	$storeHash = Get-Sha256 $store

	# 3. No Controller service without -controller
	if (Get-Service -Name $controllerService -ErrorAction SilentlyContinue) { throw "$controllerService exists although ranz install ran without -controller" }
	Write-Host "no $controllerService without -controller"

	# 4. ranz install -controller also registers and starts the Controller service
	Invoke-Ranz $goodExe @('install', '-controller') | Out-Null
	if ($LASTEXITCODE -ne 0) { throw "ranz install -controller exited with code $LASTEXITCODE" }
	Wait-ServiceState $controllerService 'Running' | Out-Null
	Write-Host "$controllerService is Running"

	# 5. Idempotent: install again leaves one service of each name, both still Running
	Invoke-Ranz $goodExe @('install', '-controller') | Out-Null
	if ($LASTEXITCODE -ne 0) { throw "the second ranz install -controller exited with code $LASTEXITCODE" }
	foreach ($name in @($nodeService, $controllerService)) {
		$count = @(Get-CimInstance Win32_Service -Filter "Name='$name'").Count
		if ($count -ne 1) { throw "$count services are named $name after installing twice" }
	}
	Wait-ServiceState $nodeService 'Running' | Out-Null
	Wait-ServiceState $controllerService 'Running' | Out-Null
	Write-Host 'running ranz install twice leaves one service of each name, both Running'

	# 6. ranz uninstall: removes both services and the folder, keeps the data directory
	Invoke-Ranz $goodExe @('uninstall') | Out-Null
	if ($LASTEXITCODE -ne 0) { throw "ranz uninstall exited with code $LASTEXITCODE" }
	foreach ($name in @($nodeService, $controllerService)) {
		if (Get-Service -Name $name -ErrorAction SilentlyContinue) { throw "ranz uninstall left $name installed" }
	}
	if (Test-Path -LiteralPath $installDir) { throw "ranz uninstall left $installDir" }
	if (-not (Test-Path -LiteralPath $store)) { throw "ranz uninstall removed the Node's data directory" }
	if ((Get-Sha256 $store) -ne $storeHash) { throw "ranz uninstall changed the Node's Configuration store" }
	Write-Host "ranz uninstall removed both services and $installDir, and kept $dataDir"

	# 7. A reinstall resumes with the same Node identity key: install and uninstall never touch the
	#    key storage provider, and the Configuration store that names the key (CONTEXT.md, "Node") is
	#    the same file uninstall kept, unchanged by the fresh install below.
	Invoke-Ranz $goodExe @('install') | Out-Null
	if ($LASTEXITCODE -ne 0) { throw "the reinstall exited with code $LASTEXITCODE" }
	Wait-ServiceState $nodeService 'Running' | Out-Null
	if ((Get-Sha256 $store) -ne $storeHash) { throw "a reinstall changed the Node's Configuration store (and so the IdentityKey setting it names)" }
	Write-Host 'a reinstall resumes with the same Configuration store, and so the same Node identity key'
} catch {
	Write-Host "diagnostics: $nodeService = $((Get-Service -Name $nodeService -ErrorAction SilentlyContinue).Status), $controllerService = $((Get-Service -Name $controllerService -ErrorAction SilentlyContinue).Status)"
	throw
} finally {
	Remove-InstalledState
}

Write-Host 'ok'
