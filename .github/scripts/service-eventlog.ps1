param(
	[string] $BuildDir = 'build',
	# Runs the source scan alone, on the tree under this folder: the fixtures of quality-gates-test.py
	[string] $ScanRoot = '',
	# Runs the checks on planted faults alone, with no service and no Windows API, so that quality-gates-test.py can run
	# it on Linux
	[switch] $SelfTest
)

$ErrorActionPreference = 'Stop'

# ranz-node installed and started as a Windows service, restarted, stopped and uninstalled, with what it must not do
# while it runs (tickets #92 and #47; CORE-S8-1-R1, #575). Four checks:
#   1. Service events in the Windows Event Log (ticket #92). The service writes "started" (event ID 1) to the
#      Application log under its service name once /install has started it and again once a restart has, and "stopped"
#      (event ID 2) when it is stopped and uninstalled, with no failure entry (event ID 3). The event IDs are
#      MS_EVENT_SERVICE_* in src/Mayaqua/Microsoft.h; the entries are written by MsServiceDispatcher and
#      MsServiceStopProc in src/Mayaqua/Microsoft.c.
#   2. No firewall rule (ticket #47, criterion 2). /install, the start of the service, a restart of it and /uninstall
#      add, delete or change no rule of Windows Firewall, judged by the rules that Windows Firewall reports. ranz-node
#      /install adds none (src/ranz-node/ranz-node.c gives MsServiceEx no rule); the rules of the Node are those that
#      ranz install makes, which install.ps1 checks.
#   3. No script host (ticket #47, criterion 2). An ETW trace session on the Kernel-Process provider records every
#      process start of the whole run, and no process that ranz-node.exe started is cscript.exe or wscript.exe. The
#      registry key of the old VBScript hash guard does not exist either.
#   4. No VBScript firewall path in the sources (ticket #47, criterion 5): src/Mayaqua, src/Cedar, src/Core and
#      src/ranz-node name no cscript, wscript, .vbs file or hash guard of the old path.
# Checks 2 to 4 had a script of their own for vpnserver /install, firewall-rule.ps1, which left with vpnserver (CORE-S8-1,
# #84). ranz-node takes the same start path (MsServiceEx runs InitMayaqua), so they run against it here.
#
# A check that passes everything proves nothing, so each one is run on a planted fault first and must fail on it. The
# faults of Invoke-SelfTest are data (rule lines, a list of process starts); the Windows run adds a real rule and a real
# process start. The source scan has its fixtures in quality-gates-test.py, which runs this script with -ScanRoot on trees
# that it makes, and with -SelfTest.

# The folders of the sources that the scan reads, under the root of the tree: the C code that ranz-node.exe links (Mayaqua,
# Cedar and Core) and its own. The code of third parties under 3rdparty is not ours and is left out.
$scanDirs = @('src/Mayaqua', 'src/Cedar', 'src/Core', 'src/ranz-node')

# What the VBScript firewall path of the old server was made of: the script host, the script file, its name and the registry
# key of its hash guard (ticket #47). Select-String reads each as a regular expression, without regard to case.
$scanPatterns = @('cscript', 'wscript', '\.vbs\b', 'winfire_', 'FW ScriptHash', 'SOFTETHER_FW_SCRIPT_HASH', 'RegistWindowsFirewall')

# The script hosts, by the name of their image
$scriptHosts = @('cscript.exe', 'wscript.exe')

# The rules that Windows makes for the Store apps of a user are named after the package family, then -In- or -Out-
# (Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe-In-Allow-ServerCapability). They come while a step runs, as the apps of the
# runner are provisioned, and nothing of ranz-node adds them: a run of the check of vpnserver /install saw three of them
# between /install and its check of the rules.
$storeRule = '^[A-Za-z0-9][A-Za-z0-9.-]*_[a-z0-9]{13}-(In|Out)-'

# The source files that the scan reads under the root of a tree. A folder that is not there fails the scan: one that read
# nothing would pass whatever the sources held.
function Get-ScanFiles([string] $root) {
	foreach ($dir in $scanDirs) {
		$path = Join-Path $root $dir
		if (-not (Test-Path -LiteralPath $path -PathType Container)) { throw "the source scan has no folder $dir under $root" }
		Get-ChildItem -Path $path -Include '*.c', '*.h' -Recurse -File | Where-Object { $_.FullName -notmatch '[\\/]3rdparty[\\/]' }
	}
}

# Fails with the lines of the sources under root that name the VBScript firewall path
function Assert-NoVbscriptFirewallPath([string] $root) {
	$files = @(Get-ScanFiles $root)
	if ($files.Count -eq 0) { throw "the source scan found no .c or .h file under $root" }
	$hits = @($files | Select-String -Pattern $scanPatterns)
	if ($hits.Count -gt 0) {
		$hits | ForEach-Object { Write-Host "  $($_.Path):$($_.LineNumber): $($_.Line.Trim())" }
		throw "$($hits.Count) lines of the sources of the Node name the VBScript firewall path"
	}
	Write-Host "the sources of the Node name no VBScript firewall path ($($files.Count) files in $($scanDirs -join ', '))"
}

# Every rule of the local store as one line, sorted: a rule added, deleted or changed changes a line. The rules of the Store
# apps are left out.
function Get-RuleLines {
	@(Get-NetFirewallRule | Where-Object { $_.Name -notmatch $storeRule } | ForEach-Object {
			'{0} | {1} | enabled {2} | {3} | {4} | profile {5}' -f $_.Name, $_.DisplayName, $_.Enabled, $_.Direction, $_.Action, $_.Profile
		} | Sort-Object)
}

# Fails with the lines that differ when the rules of what (a step of the run) are not the rules of before
function Assert-SameRules([string[]] $expected, [string[]] $actual, [string] $what) {
	$diff = @(Compare-Object -ReferenceObject $expected -DifferenceObject $actual)
	if ($diff.Count -gt 0) {
		$diff | ForEach-Object { Write-Host ("  {0} {1}" -f $(if ($_.SideIndicator -eq '=>') { 'added:  ' } else { 'removed:' }), $_.InputObject) }
		throw "$what changed $($diff.Count) firewall rule lines"
	}
}

# The name of the file of an image path as the trace names it, a device path such as
# \Device\HarddiskVolume3\Windows\System32\cscript.exe
function Get-ImageLeaf([string] $image) {
	$image -replace '^.*[\\/]', ''
}

# Fails when a process that the program exe started is a script host, and when the trace holds no start of the program at
# all: a trace that recorded nothing would pass every program. processes are the process starts of the trace, each with its
# image (a device path), its process ID and the process ID of its parent. The trace names an image by its device path, so
# the path of exe without its drive letter is the end of it.
function Assert-NoScriptHost($processes, [string] $exe) {
	$tail = $exe.Substring(2)
	$starts = @($processes | Where-Object { $_.Image -and $_.Image.EndsWith($tail, [StringComparison]::OrdinalIgnoreCase) } | ForEach-Object { $_.Id })
	if ($starts.Count -eq 0) { throw "the trace holds $(@($processes).Count) process starts, none of ${exe}: it recorded nothing" }
	$children = @($processes | Where-Object { $starts -contains $_.Parent })
	Write-Host "$(@($processes).Count) process starts traced, $($starts.Count) of $(Get-ImageLeaf $exe), which started $($children.Count) processes"
	$children | ForEach-Object { Write-Host "  $($_.Image)" }
	$hosts = @($children | Where-Object { (Get-ImageLeaf $_.Image) -in $scriptHosts })
	if ($hosts.Count -gt 0) { throw "$(Get-ImageLeaf $exe) started $($hosts.Count) script hosts" }
}

# Runs block, which must fail: the planted fault what is caught. A block that passes fails the run.
function Assert-Fails([scriptblock] $block, [string] $what) {
	try {
		& $block
	} catch {
		Write-Host "ok: the check fails on $what ($($_.Exception.Message))"
		return
	}
	throw "the check did not fail on $what"
}

# The checks of the rules and of the script hosts on planted data, which need no Windows
function Invoke-SelfTest {
	$rules = @(
		'{11111111-1111-1111-1111-111111111111} | Core Networking | enabled True | Inbound | Allow | profile Any',
		'{22222222-2222-2222-2222-222222222222} | File and Printer Sharing | enabled False | Inbound | Allow | profile Private'
	)
	Assert-SameRules $rules $rules 'the same rules'
	Write-Host 'ok: the check passes the same rules'
	$planted = '{33333333-3333-3333-3333-333333333333} | Planted | enabled True | Inbound | Allow | profile Any'
	Assert-Fails { Assert-SameRules $rules ($rules + $planted) 'a planted rule' } 'a rule that was added'
	Assert-Fails { Assert-SameRules $rules @($rules[0]) 'a planted deletion' } 'a rule that was deleted'
	Assert-Fails { Assert-SameRules $rules @($rules[0], ($rules[1] -replace 'enabled False', 'enabled True')) 'a planted change' } 'a rule that was changed'

	$node = 'C:\build\ranz-node.exe'
	$device = '\Device\HarddiskVolume3'
	$trace = @(
		[pscustomobject]@{ Image = "$device\build\ranz-node.exe"; Id = [uint32] 100; Parent = [uint32] 4 },
		[pscustomobject]@{ Image = "$device\Windows\System32\conhost.exe"; Id = [uint32] 101; Parent = [uint32] 100 },
		[pscustomobject]@{ Image = "$device\Windows\System32\cscript.exe"; Id = [uint32] 200; Parent = [uint32] 4 }
	)
	Assert-NoScriptHost $trace $node
	Write-Host 'ok: the check passes a program that started no script host, and a script host that something else started'
	$cscript = [pscustomobject]@{ Image = "$device\Windows\System32\cscript.exe"; Id = [uint32] 102; Parent = [uint32] 100 }
	$wscript = [pscustomobject]@{ Image = "$device\Windows\System32\WScript.EXE"; Id = [uint32] 103; Parent = [uint32] 100 }
	Assert-Fails { Assert-NoScriptHost ($trace + $cscript) $node } 'a cscript.exe that the program started'
	Assert-Fails { Assert-NoScriptHost ($trace + $wscript) $node } 'a WScript.EXE that the program started'
	Assert-Fails { Assert-NoScriptHost @($trace[1], $trace[2]) $node } 'a trace that holds no start of the program'
}

if ($ScanRoot) {
	Assert-NoVbscriptFirewallPath $ScanRoot
	return
}

Invoke-SelfTest
if ($SelfTest) { return }

$exe = (Resolve-Path (Join-Path $BuildDir 'ranz-node.exe')).Path

# GC_SVC_NAME_NODE (src/GlobalConst.h), lower case as MsServiceEx registers it: the service name and the
# event source (ADR-0020 decision 4)
$service = 'ranzvpnserver'

# SOFTETHER_FW_SCRIPT_HASH of the removed VBScript path: "Software\" GC_REG_COMPANY_NAME "\PacketiX VPN\FW ScriptHash"
$hashKey = 'HKLM:\Software\Hanzcodes\Ranz VPN\PacketiX VPN\FW ScriptHash'

# Microsoft-Windows-Kernel-Process with keyword WINEVENT_KEYWORD_PROCESS (0x10): ProcessStart (event
# ID 1) of every process, with its image as a device path and the process ID of its parent
$traceSession = 'RanzNodeProcessTrace'
$traceProvider = '{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}'

# The rule that stands for one that the service added, in the planted fault of the rule check
$plantedRule = 'Ranz service-eventlog planted rule'

# How long an entry may take to appear (s): the service writes "started" once the server runs
$waitSeconds = 120

# How long the service runs before the rules are read (s), so that a rule it added after its start would be there
$settleSeconds = 10

$temp = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath() }
$root = Join-Path $temp 'service-eventlog'
if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
New-Item -ItemType Directory -Force -Path $root | Out-Null
$etl = Join-Path $root 'process.etl'

$since = (Get-Date).AddSeconds(-2)

# Entries of the event source written since the step started, oldest first. The source is not
# registered, so the insertion string is read from Properties instead of Message.
function Get-ServiceEvents {
	@(Get-WinEvent -LogName Application -FilterXPath "*[System[Provider[@Name='$service']]]" -ErrorAction SilentlyContinue |
		Where-Object { $_.TimeCreated -ge $since } | Sort-Object RecordId)
}

# The first entry of the ID written after the entry whose record ID is afterRecord
function Wait-ServiceEvent([int] $id, [long] $afterRecord = 0) {
	$end = (Get-Date).AddSeconds($waitSeconds)
	while ($true) {
		$found = @(Get-ServiceEvents | Where-Object { $_.Id -eq $id -and $_.RecordId -gt $afterRecord })
		if ($found.Count -gt 0) { return $found[0] }
		if ((Get-Date) -ge $end) { return $null }
		Start-Sleep -Seconds 1
	}
}

# logman stop now and then fails with the WMI GUID error, HRESULT 0x80071068 (exit code -2147020696), while the session is
# there: on the arm64 runners, with no change to the code under test (the ETW trace step, etw-trace.ps1, meets it too). The
# next stop finds the session. This stops it up to 3 times, 2 seconds apart, while that error comes back; any other exit
# code is the answer at once. Returns the exit code of the last stop.
function Stop-TraceSession([string] $name) {
	$wmiGuidError = -2147020696
	for ($attempt = 1; $attempt -le 3; $attempt++) {
		& logman stop $name -ets | Out-Host
		$code = $LASTEXITCODE
		if ($code -ne $wmiGuidError) { return $code }
		if ($attempt -lt 3) {
			Write-Host "logman stop failed with the WMI GUID error (attempt $attempt of 3), again in 2 s"
			Start-Sleep -Seconds 2
		}
	}
	return $code
}

# The process starts of the stopped trace session: the image (a device path such as \Device\HarddiskVolume3\...), the
# process ID and the process ID of the parent
function Get-TracedProcesses {
	@(Get-WinEvent -Path $etl -Oldest -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 1 } | ForEach-Object {
			$data = @{}
			([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $data[$_.GetAttribute('Name')] = $_.InnerText }
			[pscustomobject]@{ Image = $data['ImageName']; Id = [uint32]$data['ProcessID']; Parent = [uint32]$data['ParentProcessID'] }
		})
}

function Show-Diagnostics {
	Write-Host "Application log entries of ${service}:"
	Get-ServiceEvents | ForEach-Object {
		Write-Host ("  {0:u} id {1} level {2}: {3}" -f $_.TimeCreated, $_.Id, $_.Level, (($_.Properties | ForEach-Object { $_.Value }) -join ' | '))
	}
	Write-Host "Service Control Manager entries of the System log:"
	Get-WinEvent -LogName System -FilterXPath "*[System[Provider[@Name='Service Control Manager']]]" -MaxEvents 20 -ErrorAction SilentlyContinue |
		Where-Object { $_.TimeCreated -ge $since } | ForEach-Object {
			Write-Host ("  {0:u} id {1}: {2}" -f $_.TimeCreated, $_.Id, $_.Message)
		}
	Get-Service -Name $service -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "service ${service}: $($_.Status)" }
	# The node log of the data directory (NodeDefaultDataDir, src/Cedar/Node.c)
	$log = Get-ChildItem -Path (Join-Path $env:ProgramData 'Hanzcodes\Ranz VPN\node_log') -Filter '*.log' -ErrorAction SilentlyContinue |
		Sort-Object LastWriteTime | Select-Object -Last 1
	if ($log) {
		Write-Host "last lines of $($log.FullName):"
		Get-Content -Path $log.FullName -Tail 40 | ForEach-Object { Write-Host "  $_" }
	}
}

function Invoke-Node([string] $arg) {
	# ranz-node is a GUI-subsystem program: Start-Process -Wait waits for it to exit
	Write-Host "ranz-node $arg"
	$p = Start-Process -FilePath $exe -ArgumentList $arg -Wait -PassThru
	Write-Host "ranz-node $arg exited with code $($p.ExitCode)"
}

# 4. The sources. It needs no service, so a hit fails the step before anything is installed.
Assert-NoVbscriptFirewallPath (Get-Location).Path

# The hex values are quoted, or PowerShell would pass them on as decimal numbers
& logman start $traceSession -p $traceProvider '0x10' '0xff' -o $etl -ets
if ($LASTEXITCODE -ne 0) { throw "logman could not start the process trace session (exit code $LASTEXITCODE)" }
$tracing = $true

try {
	$before = Get-RuleLines
	if ($before.Count -eq 0) { throw 'Windows Firewall reports no rule at all: the rule check would pass whatever the service did' }
	Write-Host "$($before.Count) firewall rules before /install"

	# 1 and 2. /install, which starts the service. The entries of the service count from the last entry of the Application
	# log before it, so that one that an earlier step left is not taken for this start.
	$lastRecord = 0
	Get-WinEvent -LogName Application -MaxEvents 1 -ErrorAction SilentlyContinue | ForEach-Object { $lastRecord = $_.RecordId }
	Invoke-Node '/install'
	$started = Wait-ServiceEvent 1 $lastRecord
	if ($null -eq $started) { throw "no 'started' entry (event ID 1) of $service within $waitSeconds s of /install" }
	Write-Host "started entry: $(($started.Properties | ForEach-Object { $_.Value }) -join ' | ')"
	Start-Sleep -Seconds $settleSeconds
	$installed = Get-RuleLines
	Assert-SameRules $before $installed '/install and the start of the service'
	Write-Host '/install and the start of the service added, deleted or changed no firewall rule'

	# The service stops and starts again: the start path runs a second time
	Write-Host "restarting the service $service"
	Restart-Service -Name $service -Force
	$restarted = Wait-ServiceEvent 1 $started.RecordId
	if ($null -eq $restarted) { throw "no 'started' entry (event ID 1) of $service within $waitSeconds s of the restart" }
	Start-Sleep -Seconds $settleSeconds
	Assert-SameRules $installed (Get-RuleLines) 'the restart of the service'
	Write-Host 'the restart of the service added, deleted or changed no firewall rule'

	# /uninstall
	Invoke-Node '/uninstall'
	$stopped = Wait-ServiceEvent 2 $restarted.RecordId
	if ($null -eq $stopped) { throw "no 'stopped' entry (event ID 2) of $service within $waitSeconds s of /uninstall" }
	Write-Host "stopped entry: $(($stopped.Properties | ForEach-Object { $_.Value }) -join ' | ')"
	Assert-SameRules $before (Get-RuleLines) '/install and /uninstall'
	Write-Host '/uninstall left the rules as they were before /install'

	$failed = @(Get-ServiceEvents | Where-Object { $_.Id -eq 3 })
	if ($failed.Count -gt 0) { throw "$service wrote $($failed.Count) failure entries (event ID 3)" }

	# The rule check on a real rule, in the store that it reads: the rule that a service would have added
	New-NetFirewallRule -DisplayName $plantedRule -Direction Inbound -Action Allow -Program $exe -Profile Any | Out-Null
	Assert-Fails { Assert-SameRules $before (Get-RuleLines) 'the planted rule' } 'a firewall rule that was really added'
	Remove-NetFirewallRule -DisplayName $plantedRule

	# The script host check on a real process start, in the trace that it reads: cmd.exe stands in for the Node and starts a
	# copy of hostname.exe that is named cscript.exe, which the check knows by its name
	$stand = Join-Path $env:SystemRoot 'System32\cmd.exe'
	$fakeHost = Join-Path $root 'cscript.exe'
	Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\hostname.exe') -Destination $fakeHost
	& $stand /c $fakeHost | Out-Null

	# 3. No script host. The trace names the image by its device path.
	$stopCode = Stop-TraceSession $traceSession
	$tracing = $false
	if ($stopCode -ne 0) { throw "logman could not stop the process trace session (exit code $stopCode)" }
	$processes = Get-TracedProcesses
	Assert-NoScriptHost $processes $exe
	if (Test-Path -LiteralPath $hashKey) { throw "the registry key $hashKey of the VBScript hash guard exists" }
	Write-Host "$(Get-ImageLeaf $exe) started no cscript.exe or wscript.exe, and $hashKey does not exist"
	Assert-Fails { Assert-NoScriptHost $processes $stand } 'a script host that was really started by the program'
} catch {
	Show-Diagnostics
	throw
} finally {
	if ($tracing) { Stop-TraceSession $traceSession | Out-Null }
	# By name, not through a pipeline: Remove-NetFirewallRule with no input would delete every rule
	Remove-NetFirewallRule -DisplayName $plantedRule -ErrorAction SilentlyContinue
	# Leave no service behind for the later steps. A service that /uninstall already deleted can
	# still be listed until its process ends; sc.exe then fails, which is not an error of this step,
	# and the exit code it leaves must not become the step's (the runner exits with $LASTEXITCODE).
	if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
		& sc.exe stop $service | Out-Null
		& sc.exe delete $service | Out-Null
	}
	$global:LASTEXITCODE = 0
}

Show-Diagnostics
Write-Host 'ok'
