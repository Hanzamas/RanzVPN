param(
	[string] $Architecture, # x64 or arm64: the architecture of this runner
	[string] $Dir,          # The folder of the MSIs of this architecture: ranz-<arch>.msi, ranz-<arch>-previous.msi, ranz-<arch>-tampered.msi, ranz-<arch>.sha256
	[string] $OtherDir,     # The folder that holds ranz-<other>.msi, the package of the other architecture
	[string] $LogDir,       # Where the Windows Installer logs go
	[string] $NodeSha256,   # The SHA-256 of the signed ranz-node.exe that the ranz.exe of the packages carries as its Payload
	[switch] $StandIn,      # The packages carry a stand-in ranz.exe (.github/msi/standin-ranz.go), which a job without the C build runs
	[switch] $SelfTest      # Checks the bound of a msiexec call on a planted hang alone, with no package: no other parameter is read
)

$ErrorActionPreference = 'Stop'
# Native exit codes are checked by hand below
$PSNativeCommandUseErrorActionPreference = $false

# The thin MSI of ranz.exe (ONE-5, #314; ADR-0011 and ADR-0020 amendments of 2026-10-22), installed, upgraded,
# refused and uninstalled with msiexec on a runner of its own architecture, and read from outside the
# process: the msiexec exit code, the Service Control Manager, the files and their access list, the Apps and
# Features entries and the data directory.
#
# - every package has a valid Authenticode signature, the one of the CI certificate that the job trusts as a root;
# - an MSI of the other architecture is refused, and nothing is installed: the arm64 package on an x64 computer
#   with 1633 (Windows Installer refuses its platform), the x64 package on an arm64 computer with 1603 and
#   the launch condition message that names the arm64 package;
# - a package whose ranz install fails rolls back: msiexec exits 1603 and nothing is left (a ranz.exe whose
#   Payload has one byte changed, which ranz install refuses; with -StandIn the stand-in fails on request);
# - the MSI installs ranz.exe, runs ranz install and ends with ranzvpnserver Running as its virtual account
#   from ranz-node.exe in the Ranz VPN folder, whose files are byte for byte the signed ranz.exe of the package
#   and the signed ranz-node.exe, with a valid signature and nothing for Users; Apps and Features lists exactly
#   one entry, at the version of the package;
# - an upgrade from the version N to N+1 (the previous package and the current one, a build apart) exits 0,
#   restarts the Node under a new process id and keeps the data directory, the Configuration store (which names
#   the Node identity key) byte for byte, and one Apps and Features entry, at N+1; its ranz.exe is the one of
#   the new package, and prints the version of the package, which is the counter of the run;
# - a downgrade, N over N+1, exits 1603 with the message of the package, and N+1 stays installed and running;
# - an uninstall exits 0 and leaves nothing but the data directory: no service, no Ranz VPN folder, no Apps
#   and Features entry, no Windows Installer product, nothing for the restart to remove (ranz uninstall
#   -keep-ranz leaves ranz.exe and its folder to Windows Installer); a reinstall resumes with the same
#   Configuration store and node log.
#
# With -StandIn the same steps run against the stand-in ranz.exe, which has no service: the check of each
# step is then the folder, the Apps and Features entry and the calls.log of the stand-in, which names the
# package whose ranz.exe ran each action, in order (an upgrade runs the uninstall of the old package before
# the install of the new one).
#
# Every step runs, and a failed step prints what it needs to be read from the log, then the next independent
# step runs; the job fails at the end with the list of the steps that failed.
#
# Every msiexec call has a bound (Invoke-Msiexec, $msiexecSeconds): Windows Installer has none, and a call that never ended held
# this script for 55 minutes in three runs (CI-FLAKE-6, #593). A call that is not done in time prints what a person needs to see
# the cause, ends its process tree and fails its step with the verb and the package, and the run stops there: the next call would
# hang the same way. -SelfTest plants such a hang and checks all of that on any computer with PowerShell 7: quality-gates-test.py
# runs it on Linux, and the msi job runs it on x64 and arm64.

$nodeService = 'ranzvpnserver'
$controllerService = 'ranz-controller'
$nodeAccount = "NT SERVICE\$nodeService"
$productName = 'Ranz VPN'
$installDir = Join-Path $env:ProgramFiles 'Ranz VPN'
$installedRanz = Join-Path $installDir 'ranz.exe'
$installedNode = Join-Path $installDir 'ranz-node.exe'
$dataDir = Join-Path $env:ProgramData 'Hanzcodes\Ranz VPN'
$store = Join-Path $dataDir 'ranz_node.db'
$nodeLogDir = Join-Path $dataDir 'node_log'
$canary = Join-Path $dataDir 'msi-canary.txt'
$standInDir = Join-Path $env:ProgramData 'Ranz MSI stand-in'
$calls = Join-Path $standInDir 'calls.log'

# The bound of a msiexec call, in seconds. The green runs of 2026-10-31 (five of each architecture, from the pushes to integration)
# took 36 s at the most for the slowest call, the install of the previous package on x64 (23 s on arm64), and 5 s at the most for
# every other call, so 300 s is more than eight times the slowest. The program that a call runs and the arguments before its verb
# are msiexec.exe and none; -SelfTest puts a stand-in there.
$msiexecSeconds = 300
$msiexecFile = 'msiexec.exe'
$msiexecPrefix = @()
# The message of the call that reached its bound, once one did: Step stops the run there, and no other call starts
$script:msiexecHang = $null

function Test-ProcessAlive([int] $id) {
	$process = Get-Process -Id $id -ErrorAction SilentlyContinue
	return ($null -ne $process -and -not $process.HasExited)
}

# What a person needs to see why a msiexec call does not end, one line each: the msiexec processes and the tree of the call with the
# parent, the time and the command line of each, the end of the verbose log of the call, the events of Windows Installer of the last
# 15 minutes and the state of its service. A part that the computer cannot give says why, so that it never hides the others.
function Get-MsiexecEvidence([int] $callId, [string] $log) {
	$lines = [System.Collections.Generic.List[string]]::new()
	$lines.Add("msiexec processes, and the tree of the call (process $callId), each with its parent and its command line:")
	try {
		if (-not (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) { throw 'this computer has no Get-CimInstance' }
		$all = @(Get-CimInstance Win32_Process)
		$shown = [System.Collections.Generic.HashSet[int]]::new()
		$queue = [System.Collections.Generic.Queue[int]]::new()
		foreach ($id in @($callId) + @($all | Where-Object { $_.Name -eq 'msiexec.exe' } | ForEach-Object { [int] $_.ProcessId })) {
			if ($shown.Add($id)) { $queue.Enqueue($id) }
		}
		while ($queue.Count -gt 0) {
			$parentId = $queue.Dequeue()
			foreach ($child in @($all | Where-Object { [int] $_.ParentProcessId -eq $parentId })) {
				if ($shown.Add([int] $child.ProcessId)) { $queue.Enqueue([int] $child.ProcessId) }
			}
		}
		foreach ($process in @($all | Where-Object { $shown.Contains([int] $_.ProcessId) } | Sort-Object ProcessId)) {
			$parent = @($all | Where-Object { $_.ProcessId -eq $process.ParentProcessId })[0]
			$parentName = if ($parent) { $parent.Name } else { 'gone' }
			$cpu = ([double] $process.KernelModeTime + [double] $process.UserModeTime) / 1e7
			$lines.Add(('  process {0} {1}, parent {2} {3}, {4} threads, {5:N1} s of cpu, started {6:u}: {7}' -f $process.ProcessId, $process.Name, $process.ParentProcessId, $parentName, $process.ThreadCount, $cpu, $process.CreationDate, $process.CommandLine))
		}
	} catch {
		$lines.Add("  not read: $($_.Exception.Message)")
	}

	$lines.Add("the verbose log ${log}:")
	try {
		if (Test-Path -LiteralPath $log) {
			$item = Get-Item -LiteralPath $log
			$lines.Add(('  {0} bytes, last written {1:u}, and its last lines:' -f $item.Length, $item.LastWriteTime))
			Get-Content -LiteralPath $log -Tail 40 | ForEach-Object { $lines.Add("  $_") }
		} else {
			$lines.Add('  the log is not there')
		}
	} catch {
		$lines.Add("  not read: $($_.Exception.Message)")
	}

	$lines.Add('events of Windows Installer (provider MsiInstaller, log Application) of the last 15 minutes, the last 60 of them:')
	try {
		$events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'MsiInstaller'; StartTime = (Get-Date).AddMinutes(-15) } -ErrorAction SilentlyContinue)
		if ($events.Count -eq 0) { $lines.Add('  none') }
		foreach ($record in @($events | Sort-Object RecordId | Select-Object -Last 60)) {
			$lines.Add(('  {0:u} id {1}: {2}' -f $record.TimeCreated, $record.Id, ($record.Message -replace '\s+', ' ')))
		}
	} catch {
		$lines.Add("  not read: $($_.Exception.Message)")
	}

	try {
		$service = Get-CimInstance Win32_Service -Filter "Name='msiserver'"
		if ($service) {
			$lines.Add("service msiserver: $($service.State), process $($service.ProcessId), start mode $($service.StartMode), status $($service.Status), exit code $($service.ExitCode)")
		} else {
			$lines.Add('service msiserver: not installed')
		}
	} catch {
		$lines.Add("service msiserver: not read ($($_.Exception.Message))")
	}
	return $lines.ToArray()
}

# Ends the process of a call and every process that it started
function Stop-MsiexecCall([System.Diagnostics.Process] $call) {
	try {
		$call.Kill($true)
	} catch {
		Write-Host "the process $($call.Id) could not be ended: $($_.Exception.Message)"
	}
	if (-not $call.WaitForExit(10000)) { Write-Host "the process $($call.Id) is still there 10 s after it was ended" }
}

# A msiexec run: its exit code and the path of its verbose log
function Invoke-Msiexec([string] $verb, [string] $package, [string] $step) {
	$log = Join-Path $LogDir "$step.log"
	$p = Start-Process -FilePath $msiexecFile -ArgumentList ($msiexecPrefix + @($verb, "`"$package`"", '/qn', '/norestart', '/l*v', "`"$log`"")) -Wait -PassThru
	$script:lastLog = $log
	Write-Host "msiexec $verb $(Split-Path -Leaf $package): exit code $($p.ExitCode) (log $log)"
	return [pscustomobject]@{ Code = $p.ExitCode; Log = $log }
}

# The bound on a planted hang. A bound that no hang has tested proves nothing, so a stand-in for msiexec.exe that never ends, and
# starts a child that never ends either, runs through Invoke-Msiexec with a bound of 20 s. The call must fail within it, with a
# message that names the verb and the package; the evidence must be printed and kept; both processes must be ended. The stand-in
# sleeps for 120 s, so a call with no bound returns after 120 s with no failure, and the check fails on that. A stand-in that exits
# at once checks that a call that ends is left alone, and on Windows a package that is not there checks the real msiexec.exe.
function Invoke-SelfTest {
	$bound = 20
	$work = Join-Path ([System.IO.Path]::GetTempPath()) "msi-install-selftest-$([guid]::NewGuid().ToString('N'))"
	New-Item -ItemType Directory -Force -Path $work | Out-Null
	$standIn = Join-Path $work 'standin-msiexec.ps1'
	Set-Content -LiteralPath $standIn -Value @'
# A stand-in for msiexec.exe (the self-test of msi-install.ps1): refused.msi exits with 23 at once, any other package hangs. The
# stand-in writes its verbose log, starts a child that does not end either, writes both process ids next to the log and sleeps.
$package = $args[1]
$log = $args[[array]::IndexOf($args, '/l*v') + 1]
if ((Split-Path -Leaf $package) -eq 'refused.msi') { exit 23 }
Set-Content -LiteralPath $log -Value @('planted verbose log, line 1', 'planted verbose log, line 2: the last line')
$child = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 120') -PassThru
Set-Content -LiteralPath "$log.pids" -Value "$PID $($child.Id)"
Start-Sleep -Seconds 120
'@
	try {
		$script:LogDir = $work
		$script:msiexecSeconds = $bound
		if ($IsWindows) {
			$real = Invoke-Msiexec '/i' (Join-Path $work 'not-there.msi') 'planted-not-there'
			if ($real.Code -isnot [int] -or $real.Code -eq 0) { throw "the real msiexec.exe gave the exit code '$($real.Code)' for a package that is not there" }
			Write-Host 'ok: the real msiexec.exe gives its exit code for a package that is not there'
		}
		$script:msiexecFile = (Get-Process -Id $PID).Path
		$script:msiexecPrefix = @('-NoProfile', '-NonInteractive', '-File', "`"$standIn`"")

		$refused = Invoke-Msiexec '/i' (Join-Path $work 'refused.msi') 'planted-refused'
		if ($refused.Code -ne 23) { throw "a call that ends gave the exit code $($refused.Code), not 23" }
		if (Test-Path -LiteralPath (Join-Path $work 'planted-refused-evidence.txt')) { throw 'a call that ended left the evidence of a hang' }
		Write-Host 'ok: a call that ends gives its exit code, and leaves no evidence of a hang'

		$thrown = $null
		$watch = [System.Diagnostics.Stopwatch]::StartNew()
		try {
			$hung = Invoke-Msiexec '/i' (Join-Path $work 'hang.msi') 'planted-hang'
		} catch {
			$thrown = $_.Exception.Message
		}
		$seconds = $watch.Elapsed.TotalSeconds
		if (-not $thrown) { throw "a msiexec that never ends was not bounded: the call returned after $([int] $seconds) s with the exit code $($hung.Code) and no failure, and its bound is $bound s" }
		if ($seconds -lt $bound -or $seconds -gt $bound + 60) { throw "the call failed after $([int] $seconds) s, not within its bound of $bound s (and 60 s for the evidence)" }
		if ($thrown -notlike "msiexec /i hang.msi did not end within $bound s*") { throw "the failure does not name the verb and the package: $thrown" }
		if ($thrown -ne $script:msiexecHang) { throw "Step stops the run at the message in msiexecHang, which is '$script:msiexecHang', not '$thrown'" }
		Write-Host "ok: a msiexec that never ends fails within its bound ($bound s, after $([int] $seconds) s), and the failure names the verb and the package"

		$evidenceFile = Join-Path $work 'planted-hang-evidence.txt'
		if (-not (Test-Path -LiteralPath $evidenceFile)) { throw 'the call that did not end kept no evidence in a file' }
		$evidence = Get-Content -LiteralPath $evidenceFile -Raw
		$ids = @((Get-Content -LiteralPath (Join-Path $work 'planted-hang.log.pids')) -split '\s+' | Where-Object { $_ })
		if ($ids.Count -ne 2) { throw "the stand-in wrote $($ids.Count) process ids, not two: its own and its child's" }
		$parts = @('msiexec processes', 'planted verbose log, line 2: the last line', 'events of Windows Installer', 'service msiserver')
		if ($IsWindows) { $parts += @($ids | ForEach-Object { "  process $_ " }) }
		foreach ($part in $parts) {
			if (-not $evidence.Contains($part)) { throw "the evidence of the call that did not end has no '$part':`n$evidence" }
		}
		Write-Host 'ok: the evidence holds the processes, the end of the verbose log, the events of Windows Installer and the state of msiserver, and is kept in a file'

		$deadline = (Get-Date).AddSeconds(15)
		while (@($ids | Where-Object { Test-ProcessAlive ([int] $_) }).Count -gt 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
		$alive = @($ids | Where-Object { Test-ProcessAlive ([int] $_) })
		if ($alive.Count -gt 0) { throw "the process tree of the call is still there after its failure: process $($alive -join ', ')" }
		Write-Host 'ok: the process tree of the call is ended: the stand-in and its child'
	} finally {
		Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
	}
}

if ($SelfTest) {
	Invoke-SelfTest
	exit 0
}

if ($Architecture -notin 'x64', 'arm64') { throw "-Architecture is '$Architecture', not x64 or arm64" }
$other = if ($Architecture -eq 'x64') { 'arm64' } else { 'x64' }
$msiCurrent = (Resolve-Path -LiteralPath (Join-Path $Dir "ranz-$Architecture.msi")).Path
$msiPrevious = (Resolve-Path -LiteralPath (Join-Path $Dir "ranz-$Architecture-previous.msi")).Path
$msiOther = (Resolve-Path -LiteralPath (Join-Path $OtherDir "ranz-$other.msi")).Path
if (-not $StandIn) {
	$msiTampered = (Resolve-Path -LiteralPath (Join-Path $Dir "ranz-$Architecture-tampered.msi")).Path
	$ranzSha256 = (Get-Content -LiteralPath (Join-Path $Dir "ranz-$Architecture.sha256") -Raw).Trim()
	if ($ranzSha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw "ranz-$Architecture.sha256 holds no SHA-256: '$ranzSha256'" }
	if ($NodeSha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw "-NodeSha256 is not a SHA-256: '$NodeSha256'" }
}
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$LogDir = (Resolve-Path -LiteralPath $LogDir).Path

function Get-Sha256([string] $path) {
	return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}

# One property of the Property table of the package at $path
function Get-MsiProperty([string] $path, [string] $name) {
	$installer = New-Object -ComObject WindowsInstaller.Installer
	$db = $installer.OpenDatabase($path, 0)
	$view = $db.OpenView('SELECT `Value` FROM `Property` WHERE `Property`=' + "'$name'")
	try {
		# A void method of a COM object gives $null to the pipeline, and the function would return it
		[void]$view.Execute()
		$record = $view.Fetch()
		if ($null -eq $record) { throw "$path has no property $name" }
		return $record.StringData(1)
	} finally {
		[void]$view.Close()
		[void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($view)
		[void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($db)
		[void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($installer)
		[GC]::Collect()
		[GC]::WaitForPendingFinalizers()
	}
}

$version = Get-MsiProperty $msiCurrent 'ProductVersion'
$previousVersion = Get-MsiProperty $msiPrevious 'ProductVersion'
$upgradeCode = Get-MsiProperty $msiCurrent 'UpgradeCode'
if ([version]$previousVersion -ge [version]$version) { throw "the previous package is at $previousVersion, not below $version" }
if (-not $StandIn) {
	# The one counter that only grows (ADR-0020 consequences): the third part of the version is the run number of
	# this workflow, the build number that ranz version prints
	if (-not ($version -match '^(\d+\.\d+)\.(\d+)$') -or $Matches[2] -ne $env:GITHUB_RUN_NUMBER) {
		throw "the version $version of the package does not end in the run number $env:GITHUB_RUN_NUMBER"
	}
	$expectedPrevious = "$($Matches[1]).$([int]$Matches[2] - 1)"
	if ($previousVersion -ne $expectedPrevious) { throw "the previous package is at $previousVersion, not $expectedPrevious, one build below $version" }
}
Write-Host "package $version ($Architecture), previous package $previousVersion, upgrade code $upgradeCode"

# The text of a Windows Installer log, whatever its encoding
function Read-MsiLog([string] $path) {
	if (-not (Test-Path -LiteralPath $path)) { return '' }
	return [System.IO.File]::ReadAllText($path)
}

# The Apps and Features entries of the product: every Uninstall key of the machine and of the user that names it
function Get-ArpEntries {
	$roots = @(
		'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
		'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
		'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
	)
	foreach ($root in $roots) {
		if (-not (Test-Path -LiteralPath $root)) { continue }
		foreach ($key in Get-ChildItem -LiteralPath $root) {
			$p = Get-ItemProperty -LiteralPath $key.PSPath
			if ($p.DisplayName -like "$productName*") {
				[pscustomobject]@{ Key = $key.PSChildName; Name = $p.DisplayName; Version = $p.DisplayVersion; Root = $root }
			}
		}
	}
}

# The products of Windows Installer that carry the upgrade code of the package
function Get-RelatedProducts {
	$installer = New-Object -ComObject WindowsInstaller.Installer
	try {
		$codes = @()
		foreach ($code in $installer.RelatedProducts($upgradeCode)) { $codes += $code }
		return $codes
	} finally {
		[void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($installer)
	}
}

# The processor architecture that Windows keeps for the whole machine (the launch condition of the x64 package
# reads the same value): x64 is AMD64 here, arm64 is ARM64
function Get-NativeArchitecture {
	return (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name PROCESSOR_ARCHITECTURE -ErrorAction SilentlyContinue).PROCESSOR_ARCHITECTURE
}

# The files that the next restart removes or renames, and the ones of them that name the Ranz VPN folder
function Get-PendingRemovals {
	$value = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
	return @($value | Where-Object { $_ -and $_ -match 'Ranz VPN' })
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

# The process id of the Node service, which a restart changes
function Get-NodeProcessId {
	return [int] (Get-CimInstance Win32_Service -Filter "Name='$nodeService'").ProcessId
}

# The lines "Node started" of the node log of the data directory: one for each time the Node ran
function Get-NodeStarts {
	return @(Get-ChildItem -LiteralPath $nodeLogDir -File -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern 'Node started' -SimpleMatch).Count
}

# The SHA-256 of the Configuration store of the Node, read while the Node is stopped: it closes its store then.
# The Node runs again afterwards.
function Get-ClosedStoreHash {
	Stop-Service -Name $nodeService
	$hash = Get-Sha256 $store
	Start-Service -Name $nodeService
	Wait-ServiceState $nodeService 'Running'
	return $hash
}

# The calls that the stand-in ranz.exe logged, one line each: the build that ran and its arguments
function Get-Calls {
	if (-not (Test-Path -LiteralPath $calls)) { return @() }
	return @(Get-Content -LiteralPath $calls)
}

# The calls after the first $before of them are exactly $expected
function Assert-Calls([int] $before, [string[]] $expected) {
	$all = @(Get-Calls)
	$new = if ($all.Count -gt $before) { @($all[$before..($all.Count - 1)]) } else { @() }
	if (($new -join '|') -ne ($expected -join '|')) {
		throw "the stand-in ranz.exe was called with [$($new -join '; ')], not with [$($expected -join '; ')]"
	}
}

# What the MSI of $version must have installed
function Assert-Installed([string] $expectedVersion, [bool] $current) {
	$entries = @(Get-ArpEntries)
	if ($entries.Count -ne 1) {
		throw "Apps and Features lists $($entries.Count) entries for $productName, not one: $(($entries | ForEach-Object { "$($_.Name) $($_.Version)" }) -join '; ')"
	}
	if ($entries[0].Version -ne $expectedVersion) { throw "Apps and Features lists $productName at $($entries[0].Version), not at $expectedVersion" }
	$related = @(Get-RelatedProducts)
	if ($related.Count -ne 1 -or $related[0] -ne $entries[0].Key) { throw "Windows Installer lists [$($related -join ', ')] for the upgrade code, not the product $($entries[0].Key) alone" }

	foreach ($path in $installedRanz, $installedNode) {
		if (-not (Test-Path -LiteralPath $path)) { throw "$path is not there" }
	}
	if ($StandIn) { return }

	Wait-ServiceState $nodeService 'Running'
	$svc = Get-CimInstance Win32_Service -Filter "Name='$nodeService'"
	if ($svc.StartName -ne $nodeAccount) { throw "$nodeService runs as '$($svc.StartName)', not its virtual account $nodeAccount" }
	if ($svc.PathName -ne "`"$installedNode`" /service") { throw "$nodeService runs '$($svc.PathName)', not ranz-node.exe of $installDir with /service" }
	if (Get-Service -Name $controllerService -ErrorAction SilentlyContinue) { throw "$controllerService exists although the MSI runs ranz install without -controller" }

	Assert-NoUsersAccess $installDir
	foreach ($path in $installedRanz, $installedNode) {
		Assert-NoUsersAccess $path
		$sig = Get-AuthenticodeSignature -FilePath $path
		if ($sig.Status -ne 'Valid') { throw "$path has signature status $($sig.Status), not Valid" }
	}
	if ((Get-Sha256 $installedNode) -ne $NodeSha256) { throw "$installedNode is not byte for byte the signed ranz-node.exe (SHA-256 $NodeSha256)" }
	if ((Get-Sha256 $installedRanz) -ne $ranzSha256) { throw "$installedRanz is not byte for byte the signed ranz.exe of the package (SHA-256 $ranzSha256)" }
	if ($current) {
		$line = (& $installedRanz version | Out-String).Trim()
		if ($LASTEXITCODE -ne 0 -or $line -ne "ranz $expectedVersion") { throw "$installedRanz version printed '$line' (exit code $LASTEXITCODE), not 'ranz $expectedVersion', the version of the package" }
	}
	if (-not (Test-Path -LiteralPath $store)) { throw "$store (the Configuration store of the Node) was not made" }
}

# What an uninstall, a refused package and a rollback leave: nothing of the product but the data directory
function Assert-NothingInstalled([string] $when) {
	foreach ($name in $nodeService, $controllerService) {
		if (Get-Service -Name $name -ErrorAction SilentlyContinue) { throw "$when the service $name is there" }
	}
	if (Test-Path -LiteralPath $installDir) {
		throw "$when $installDir is there, with $((Get-ChildItem -LiteralPath $installDir -Force -Recurse | ForEach-Object { $_.FullName }) -join ', ')"
	}
	$entries = @(Get-ArpEntries)
	if ($entries.Count -ne 0) { throw "$when Apps and Features lists $($entries.Count) entries for ${productName}: $(($entries | ForEach-Object { "$($_.Name) $($_.Version)" }) -join '; ')" }
	$related = @(Get-RelatedProducts)
	if ($related.Count -ne 0) { throw "$when Windows Installer lists the products $($related -join ', ') for the upgrade code" }
	$pending = @(Get-PendingRemovals)
	if ($pending.Count -ne 0) { throw "$when the next restart removes or renames $($pending -join ', ')" }
}

# The data directory of the Node is what an uninstall keeps: the canary that the job put there, and the
# Configuration store, byte for byte. The Node holds its store open while it runs, so the bytes of the store
# are read here only while no Node runs, as after an uninstall; Get-ClosedStoreHash reads them for a Node that runs.
function Assert-DataKept {
	if (-not (Test-Path -LiteralPath $canary)) { throw "$canary, which the job left in the data directory, is gone" }
	if ((Get-Content -LiteralPath $canary -Raw).Trim() -ne $state.Canary) { throw "$canary was changed" }
	if (-not (Test-Path -LiteralPath $store)) { throw "the Configuration store $store is gone" }
	if (-not (Get-Service -Name $nodeService -ErrorAction SilentlyContinue) -and (Get-Sha256 $store) -ne $state.StoreHash) {
		throw "the Configuration store $store was changed (it names the Node identity key)"
	}
}

function Remove-InstalledState {
	# The products of Windows Installer first, then what is left of the services and the folder
	foreach ($entry in @(Get-ArpEntries)) {
		# After a call that did not end, Windows Installer is in a state that nobody knows: no other call starts
		if ($entry.Key -match '^\{[0-9A-Fa-f-]+\}$' -and -not $script:msiexecHang) {
			[void](Invoke-Msiexec '/x' $entry.Key "remove-$($entry.Key.Trim('{', '}'))")
		}
	}
	foreach ($name in @($nodeService, $controllerService)) {
		if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
			& sc.exe stop $name | Out-Null
			Start-Sleep -Seconds 2
			& sc.exe delete $name | Out-Null
		}
	}
	if (Test-Path -LiteralPath $installDir) { Remove-Item -LiteralPath $installDir -Recurse -Force -ErrorAction SilentlyContinue }
	# sc.exe fails for a service that is gone, which is no error of this script
	$global:LASTEXITCODE = 0
}

# What a failed step needs to be read from the log alone
function Show-Diagnostics {
	foreach ($name in @($nodeService, $controllerService)) {
		$svc = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
		if ($svc) {
			Write-Host "service ${name}: $($svc.State), exit code $($svc.ExitCode), process $($svc.ProcessId), start name '$($svc.StartName)', path $($svc.PathName)"
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
	Write-Host "architecture of this computer: $(Get-NativeArchitecture) in the registry, $env:PROCESSOR_ARCHITECTURE and $env:PROCESSOR_ARCHITEW6432 in the environment of this process"
	Write-Host "Apps and Features: $((@(Get-ArpEntries) | ForEach-Object { "$($_.Name) $($_.Version) $($_.Key)" }) -join '; ')"
	Write-Host "Windows Installer products of the upgrade code: $((@(Get-RelatedProducts)) -join ', ')"
	Write-Host "files that the next restart removes or renames and that name $installDir`: $((@(Get-PendingRemovals)) -join '; ')"
	if ($script:lastLog -and (Test-Path -LiteralPath $script:lastLog)) {
		$lines = @((Read-MsiLog $script:lastLog) -split "`r?`n")
		Write-Host "the lines of $script:lastLog that tell what failed:"
		$lines | Where-Object { $_ -match 'Return value 3|Error \d{4}|returned actual error|Product: .* -- |CustomAction .* returned|Action RanzI|Action RanzU|1603|1722|is not supported' } |
			Select-Object -First 30 | ForEach-Object { Write-Host "  $_" }
		Write-Host "the last lines of $script:lastLog`:"
		$lines | Select-Object -Last 25 | ForEach-Object { Write-Host "  $_" }
	}
	if ($StandIn) {
		Write-Host "calls of the stand-in ranz.exe: $((Get-Calls) -join '; ')"
	} else {
		Write-Host 'Service Control Manager events since the start of the job:'
		Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = $since } -ErrorAction SilentlyContinue |
			Sort-Object RecordId | ForEach-Object { Write-Host ("  {0:u} id {1}: {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace '\s+', ' ')) }
		foreach ($log in @(Get-ChildItem -LiteralPath $nodeLogDir -File -Recurse -ErrorAction SilentlyContinue)) {
			Write-Host "last lines of $($log.FullName):"
			Get-Content -LiteralPath $log.FullName -Tail 30 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $_" }
		}
	}
}

# A step: it runs its body and reports what failed, and the steps after it run whatever it did. It returns
# whether it passed, so that the steps that need the one before it can stop.
$failures = [System.Collections.Generic.List[string]]::new()
function Step([string] $name, [scriptblock] $body) {
	Write-Host "::group::$name"
	$passed = $true
	try {
		$null = & $body
		Write-Host "ok: $name"
	} catch {
		$passed = $false
		$message = ($_.Exception.Message -replace '\s+', ' ')
		$failures.Add("${name}: $message")
		Write-Host "::error::$name failed: $message"
		Write-Host "failed: $name`n$($_.Exception.Message)"
		try { Show-Diagnostics } catch { Write-Host "the diagnostics failed: $($_.Exception.Message)" }
	}
	Write-Host '::endgroup::'
	# A call that did not end left Windows Installer in a state that nobody knows, and the next call would hang the same way
	if ($script:msiexecHang) {
		Write-Host "the run stops after '$name': $script:msiexecHang"
		throw $script:msiexecHang
	}
	return $passed
}

# Steps that share state: the process id of the Node, the canary, the Configuration store as it was
$state = @{}
$since = Get-Date
$script:lastLog = $null
Write-Host "this computer is $(Get-NativeArchitecture) by the registry, and the architecture of this runner is $Architecture"
if ($StandIn) { Remove-Item -LiteralPath $standInDir -Recurse -Force -ErrorAction SilentlyContinue }
Remove-InstalledState

try {
	# 0. The packages are signed like the executables (ADR-0020 amendment of 2026-10-22), with the CI certificate
	#    that the job trusts as a root
	if (-not $StandIn) {
		[void](Step 'the packages have a valid Authenticode signature' {
			foreach ($package in $msiCurrent, $msiPrevious, $msiOther, $msiTampered) {
				$sig = Get-AuthenticodeSignature -FilePath $package
				if ($sig.Status -ne 'Valid') { throw "$package has signature status $($sig.Status), not Valid" }
			}
		})
	}

	# 1. A package of the other architecture is refused and installs nothing
	[void](Step "the $other package is refused on $Architecture, and nothing is installed" {
		$r = Invoke-Msiexec '/i' $msiOther 'wrong-architecture'
		# Windows Installer refuses the platform of an arm64 package on x64 (1633); the x64 package on arm64 runs, and its
		# launch condition fails it (1603)
		$want = if ($Architecture -eq 'x64') { 1633 } else { 1603 }
		if ($r.Code -ne $want) { throw "msiexec exited with code $($r.Code), not $want" }
		if ($Architecture -eq 'arm64' -and (Read-MsiLog $r.Log) -notmatch 'arm64 package of Ranz VPN') {
			throw "the log of the refused install has no launch condition message that names the arm64 package"
		}
		Assert-NothingInstalled 'after the refused package'
	})
	Remove-InstalledState

	# 2. An install whose ranz install fails rolls back, and nothing is left
	if ($StandIn) {
		[void](Step 'an install that fails rolls back, and nothing is left' {
			New-Item -ItemType Directory -Force -Path $standInDir | Out-Null
			$flag = Join-Path $standInDir 'fail-install'
			New-Item -ItemType File -Force -Path $flag | Out-Null
			$before = @(Get-Calls).Count
			try { $r = Invoke-Msiexec '/i' $msiCurrent 'failing-install' } finally { Remove-Item -LiteralPath $flag -Force }
			if ($r.Code -ne 1603) { throw "msiexec exited with code $($r.Code), not 1603" }
			Assert-Calls $before @('cur install', 'cur uninstall -keep-ranz')
			Assert-NothingInstalled 'after the rolled back install'
		})
	} else {
		[void](Step 'a Payload that fails its check rolls back, and nothing is left' {
			$r = Invoke-Msiexec '/i' $msiTampered 'tampered-payload'
			if ($r.Code -ne 1603) { throw "msiexec exited with code $($r.Code), not 1603" }
			Assert-NothingInstalled 'after the rolled back install'
		})
	}
	Remove-InstalledState

	# 3. Install N, upgrade to N+1, a downgrade is refused, uninstall, reinstall: each step needs the one before it
	$chain = @(
		@{ Name = "the MSI at $previousVersion installs and starts the Node"; Body = {
			$before = @(Get-Calls).Count
			$r = Invoke-Msiexec '/i' $msiPrevious 'install-previous'
			if ($r.Code -ne 0) { throw "msiexec exited with code $($r.Code), not 0" }
			Assert-Installed $previousVersion $false
			if ($StandIn) {
				Assert-Calls $before @('prev install')
			} else {
				# The data directory is the Node's to make, at its first start: the job puts a file in it, and
				# reads the Configuration store of the Node, closed, to compare with it afterwards
				$state.Canary = [guid]::NewGuid().ToString()
				Set-Content -LiteralPath $canary -Value $state.Canary
				$state.StoreHash = Get-ClosedStoreHash
				$state.ProcessId = Get-NodeProcessId
				$state.Starts = Get-NodeStarts
				if ($state.Starts -lt 1) { throw "the Node did not write 'Node started' to the node log in $nodeLogDir" }
			}
		} },
		@{ Name = "an upgrade to $version keeps the data directory, and Apps and Features shows one entry"; Body = {
			$before = @(Get-Calls).Count
			$r = Invoke-Msiexec '/i' $msiCurrent 'upgrade'
			if ($r.Code -ne 0) { throw "msiexec exited with code $($r.Code), not 0" }
			Assert-Installed $version $true
			if ($StandIn) {
				# The old package is removed before the new one is installed
				Assert-Calls $before @('prev uninstall -keep-ranz', 'cur install')
			} else {
				if ((Get-NodeProcessId) -eq $state.ProcessId) { throw "the Node runs in the process $($state.ProcessId) of before the upgrade: it was not restarted" }
				if ((Get-NodeStarts) -le $state.Starts) { throw 'the Node of the new package did not log to the node log that the upgrade kept' }
				if ((Get-ClosedStoreHash) -ne $state.StoreHash) { throw "the upgrade changed the Configuration store of the Node, which names its identity key" }
				Assert-DataKept
				$state.ProcessId = Get-NodeProcessId
			}
		} },
		@{ Name = "a downgrade to $previousVersion is refused, and $version stays installed"; Body = {
			$before = @(Get-Calls).Count
			if (-not $StandIn) { $processId = Get-NodeProcessId }
			$r = Invoke-Msiexec '/i' $msiPrevious 'downgrade'
			if ($r.Code -ne 1603) { throw "msiexec exited with code $($r.Code), not 1603" }
			if ((Read-MsiLog $r.Log) -notmatch 'A newer version of Ranz VPN is installed') { throw 'the log of the refused downgrade has no message of the package' }
			Assert-Installed $version $true
			if ($StandIn) {
				Assert-Calls $before @()
			} elseif ((Get-NodeProcessId) -ne $processId) {
				throw 'the refused downgrade restarted the Node'
			}
		} },
		@{ Name = 'the uninstall leaves nothing but the data directory'; Body = {
			$before = @(Get-Calls).Count
			$r = Invoke-Msiexec '/x' $msiCurrent 'uninstall'
			if ($r.Code -ne 0) { throw "msiexec exited with code $($r.Code), not 0" }
			Assert-NothingInstalled 'after the uninstall'
			if ($StandIn) {
				Assert-Calls $before @('cur uninstall -keep-ranz')
			} else {
				Assert-DataKept
				$state.Starts = Get-NodeStarts
			}
		} },
		@{ Name = 'a reinstall resumes with the same Configuration store and node log'; Body = {
			$r = Invoke-Msiexec '/i' $msiCurrent 'reinstall'
			if ($r.Code -ne 0) { throw "msiexec exited with code $($r.Code), not 0" }
			Assert-Installed $version $true
			if (-not $StandIn) {
				if ((Get-ClosedStoreHash) -ne $state.StoreHash) { throw 'a reinstall changed the Configuration store of the Node, which names its identity key' }
				if ((Get-NodeStarts) -le $state.Starts) { throw 'the reinstalled Node did not log to the node log that the uninstall kept' }
				Assert-DataKept
			}
		} },
		@{ Name = 'the final uninstall leaves nothing but the data directory'; Body = {
			$r = Invoke-Msiexec '/x' $msiCurrent 'final-uninstall'
			if ($r.Code -ne 0) { throw "msiexec exited with code $($r.Code), not 0" }
			Assert-NothingInstalled 'after the final uninstall'
			if (-not $StandIn) { Assert-DataKept }
		} }
	)
	foreach ($item in $chain) {
		$passed = @(Step $item.Name $item.Body)[-1]
		if (-not $passed) {
			Write-Host "the steps after '$($item.Name)' need it and do not run"
			break
		}
	}
} catch {
	# A call that did not end: the run stopped at the step that made it, and the summary below names the call. Any other
	# error is the script's own.
	if (-not $script:msiexecHang) { throw }
	if (@($failures | Where-Object { $_.EndsWith($script:msiexecHang) }).Count -eq 0) { $failures.Add("clean-up: $script:msiexecHang") }
} finally {
	Remove-InstalledState
}

if ($failures.Count -gt 0) {
	throw "$($failures.Count) steps failed:`n$($failures -join "`n")"
}
Write-Host 'ok'

# The last native command above may have left a code that is no failure here, and the step of the job
# returns the code of the last native command
exit 0
