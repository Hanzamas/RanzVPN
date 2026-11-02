param(
	[string] $Architecture, # x64 or arm64: the architecture of this runner
	[string] $Dir,          # The folder of the MSIs of this architecture: ranz-<arch>.msi, ranz-<arch>-previous.msi, ranz-<arch>-tampered.msi, ranz-<arch>.sha256
	[string] $OtherDir,     # The folder that holds ranz-<other>.msi, the package of the other architecture
	[string] $LogDir,       # Where the Windows Installer logs go
	[string] $NodeSha256,   # The SHA-256 of the signed ranz-node.exe that the ranz.exe of the packages carries as its Payload
	[switch] $StandIn,      # The packages carry a stand-in ranz.exe (.github/msi/standin-ranz.go), which a job without the C build runs
	[switch] $SelfTest,     # Checks the bounds of the waits and the evidence of a hang on planted hangs alone, with no package: no other parameter is read
	[switch] $SelfTestFlow, # What -SelfTest runs in a process of its own: the main flow on a planted hang, which must end with an error
	[string] $CheckLaunches, # Reads the script at this path and fails when it starts msiexec anywhere but in Invoke-Msiexec: no other parameter is read
	[string] $EvidenceRequest, # What a call that does not end runs in a process of its own: collects the evidence that this file asks for
	[string] $EventsRequest, # What the diagnostics of a failed step run in a process of their own: reads the events that this file asks for
	[string] $CheckFlow     # Runs the main flow of the script at this path on a planted hang and fails when what it prints is wrong: no other parameter is read
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
# the cause, then ends the call with its process tree and the process of the service msiserver, and fails its step with the verb
# and the package. An install usually hangs in the service, in the action that it runs as SYSTEM, and neither is a descendant of the
# call, so ending the call alone left them running while the clean-up deleted the folder under them (CI-FLAKE-6-R1, #596). The
# failure lists what was ended and what was not, as each process was found afterwards, and names the evidence only as far as it
# was written. The run stops there: the next call would hang the same way.
#
# The evidence is collected in a process of its own under a bound of its own ($evidenceSeconds): a query that stalls, as the one of
# the Application log can on the computer that #593 is about, must not keep the call from being ended and failed. The other waits
# have a bound too, and print the state of the service and the processes when they reach it: the wait for the Node to stop or to
# start (Wait-ServiceState: Stop-Service and Start-Service wait for ever for a service that never gets there, so they only ask) and
# ranz.exe version (Get-RanzVersionLine). The diagnostics of a failed step ask CIM with a time limit ($cimSeconds) and read the events of
# the System log in a process of their own under a bound ($eventsSeconds), as the evidence does (CI-FLAKE-6-R2, #624). Others stay without
# a bound: the signature, hash and access list reads, the COM queries of Windows Installer, the CIM queries that the steps make themselves
# and the files and the registry that the diagnostics read. Only msiexec, the Node and ranz.exe version have hung or can.
#
# The process of the service msiserver is ended only when sc.exe queryex gives it for the service at that moment and it is named
# msiexec: the service may have ended while the evidence was collected, and its id may be another process by then (#624). A process
# whose exit code the script reads is started with Process.Start (Start-ProcessWithHandle), which holds its handle from its creation: a
# process that Start-Process -PassThru started and that ended before its handle was taken has no exit code to give, and ranz.exe version
# prints one line and ends (#624).
#
# -SelfTest plants a hang of each kind and checks all of that on any computer with PowerShell 7, Windows or Linux: quality-gates-test.py
# runs it on Linux, and the msi job runs it on x64 and arm64. A planted hang ends the service msiserver with its tree, so on Windows it
# ends the real service only in GitHub Actions (GITHUB_ACTIONS is true), where nothing else uses it; on a workstation, where an install
# of somebody else may be running in the service, a process stands in for it as on Linux, and the self-test says so (#624).
# -CheckLaunches reads a script with the parser of PowerShell and fails when msiexec, or an install that has no msiexec, is started
# anywhere but in Invoke-Msiexec; -CheckFlow runs the main flow of a script on a planted hang and fails when its output is wrong:
# quality-gates-test.py runs both on this script and on copies of it with a planted fault.

# The bound of a msiexec call, in seconds. The green runs of 2026-10-31 (five of each architecture, from the pushes to integration)
# took 36 s at the most for the slowest call, the install of the previous package on x64 (23 s on arm64), and 5 s at the most for
# every other call, so 300 s is more than eight times the slowest. The program that a call runs and the arguments before its verb
# are msiexec.exe and none; -SelfTest puts a stand-in there.
$msiexecSeconds = 300
$msiexecFile = 'msiexec.exe'
$msiexecPrefix = @()
# The message of the call that reached its bound, once one did: Step stops the run there, and no other call starts
$script:msiexecHang = $null
# The name of the process of the service msiserver (it runs msiexec.exe /V): the end of a hang ends the process that it finds for the
# service only when it has this name. -SelfTest puts the name of its stand-in for the service there.
$serviceProcessName = 'msiexec'

# The bound of the evidence of a call that does not end, in seconds. The evidence of the hangs that PR 594 ran took under 2 s, so 60 s
# is thirty times that. The bounds of the end of a hang add up to 200 s at the most: the query of the service 30 s, the two reads of
# sc.exe queryex 10 s each, the evidence 60 s, the end of the evidence process 40 s (the table of processes 30 s and a wait of 10 s),
# the table of processes 30 s, and the waits for the call and for the service to be gone 10 s each. $evidenceStall is the seconds that a
# planted stall sleeps in the query of the events.
$evidenceSeconds = 60
$evidenceStall = 0
# The bound of the wait for the Node to stop and to start, and of ranz.exe version, in seconds. The Node takes a few seconds to do
# either (the slowest step of the green runs, which also runs msiexec, took 77 s), and the wait for it to run had 60 s already.
$waitSeconds = 60
# The time limit of a query of CIM and of sc.exe queryex, and the bound of the events that the diagnostics of a failed step read, in
# seconds: each answers in well under a second, and a query that does not is what the bounds are for. $eventsStall is the seconds
# that a planted stall sleeps in the query of those events.
$cimSeconds = 30
$scSeconds = 10
$eventsSeconds = 20
$eventsStall = 0
# This script and the program that runs it: the process that collects the evidence runs this script again, and -SelfTest runs it for the flow
$msiInstallScript = $MyInvocation.MyCommand.Path
if (-not $msiInstallScript) { $msiInstallScript = $PSCommandPath }
$pwshPath = (Get-Process -Id $PID).Path

function Test-ProcessAlive([int] $id) {
	$process = Get-Process -Id $id -ErrorAction SilentlyContinue
	return ($null -ne $process -and -not $process.HasExited)
}

# A time in UTC, as the log of a job shows its lines: the time of a process, of a file and of an event is a local time, and the
# format u adds a Z to whatever it is given
function Format-Utc($when) {
	if ($when -is [datetime]) { return $when.ToUniversalTime().ToString('u') }
	return ''
}

# The text of a file, or nothing when it is not there
function Read-MsiLog([string] $path) {
	if (-not (Test-Path -LiteralPath $path)) { return '' }
	return [System.IO.File]::ReadAllText($path)
}

function Get-Sha256([string] $path) {
	return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}

# Starts $file with $arguments and gives { Process, Output, Error }. Process.Start makes the Process with the handle of the process in
# it, so that its exit code is there whenever the process ended. The Process that Start-Process -PassThru gives takes the handle when it
# is first asked for something, and a process that ended before that has no exit code to give: ranz.exe version prints one line and
# ends, so it could be gone first (CI-FLAKE-6-R2, #624). The arguments are passed as they are and quoted by the framework. With $redirect
# the output and the error are read in the background (Output and Error are the tasks that read them, Get-PipeText gives their text), so
# that a process that writes more than a pipe holds is not waited for for ever.
function Start-ProcessWithHandle([string] $file, [string[]] $arguments, [bool] $redirect = $false) {
	$info = [System.Diagnostics.ProcessStartInfo]::new($file)
	foreach ($argument in $arguments) { $info.ArgumentList.Add($argument) }
	$info.UseShellExecute = $false
	$info.RedirectStandardOutput = $redirect
	$info.RedirectStandardError = $redirect
	$process = [System.Diagnostics.Process]::Start($info)
	$call = [pscustomobject]@{ Process = $process; Output = $null; Error = $null }
	if ($redirect) {
		$call.Output = $process.StandardOutput.ReadToEndAsync()
		$call.Error = $process.StandardError.ReadToEndAsync()
	}
	return $call
}

# What a process wrote to a pipe that Start-ProcessWithHandle reads, once the process is gone. A pipe that a process of the call still
# holds is not waited for for ever: after 10 s the text is nothing.
function Get-PipeText($task) {
	try {
		if ($null -ne $task -and $task.Wait(10000)) { return [string] $task.Result }
	} catch { }
	return ''
}

# Every process of this computer, one object each: the id, the parent, the name, the threads, the seconds of cpu, the start time and
# the command line. Windows asks CIM, with a time limit; another computer (the self-test on Linux) asks Get-Process and /proc.
function Get-ProcessTable {
	if ($IsWindows) {
		foreach ($p in @(Get-CimInstance Win32_Process -OperationTimeoutSec $cimSeconds)) {
			[pscustomobject]@{
				ProcessId = [int] $p.ProcessId
				ParentProcessId = [int] $p.ParentProcessId
				Name = $p.Name
				ThreadCount = [int] $p.ThreadCount
				Cpu = ([double] $p.KernelModeTime + [double] $p.UserModeTime) / 1e7
				Started = $p.CreationDate
				CommandLine = $p.CommandLine
			}
		}
		return
	}
	foreach ($p in @(Get-Process)) {
		try {
			$command = ''
			try { $command = [System.IO.File]::ReadAllText("/proc/$($p.Id)/cmdline").Replace("`0", ' ').Trim() } catch { }
			$cpu = 0.0
			try { $cpu = $p.TotalProcessorTime.TotalSeconds } catch { }
			$started = $null
			try { $started = $p.StartTime } catch { }
			# The fourth field of /proc/<id>/stat, after the name in parentheses, is the parent
			$parentId = 0
			try {
				$stat = [System.IO.File]::ReadAllText("/proc/$($p.Id)/stat")
				$parentId = [int] $stat.Substring($stat.LastIndexOf(')') + 2).Split(' ')[1]
			} catch {
				try { if ($p.Parent) { $parentId = [int] $p.Parent.Id } } catch { }
			}
			[pscustomobject]@{
				ProcessId = [int] $p.Id
				ParentProcessId = $parentId
				Name = $p.ProcessName
				ThreadCount = [int] $p.Threads.Count
				Cpu = $cpu
				Started = $started
				CommandLine = $command
			}
		} catch { }
	}
}

# The rows of $table that the process $id started, directly or not
function Get-Descendants($table, [int] $id) {
	$byId = @{}
	foreach ($row in $table) { $byId[[int] $row.ProcessId] = $row }
	$seen = [System.Collections.Generic.HashSet[int]]::new()
	$queue = [System.Collections.Generic.Queue[int]]::new()
	[void] $seen.Add($id)
	$queue.Enqueue($id)
	while ($queue.Count -gt 0) {
		$parentId = $queue.Dequeue()
		$parentStarted = if ($byId.ContainsKey($parentId)) { $byId[$parentId].Started } else { $null }
		foreach ($child in @($table | Where-Object { $_.ParentProcessId -eq $parentId })) {
			# The id of a parent that ended can name another process later: a child never starts before its parent (with a second
			# of leeway, as the start times of Linux are computed from the clock)
			if ($null -ne $parentStarted -and $null -ne $child.Started -and $child.Started -lt $parentStarted.AddSeconds(-1)) { continue }
			if ($seen.Add($child.ProcessId)) {
				$queue.Enqueue($child.ProcessId)
				$child
			}
		}
	}
}

# The lines that list the processes with the ids $rootIds and the names $rootNames and the tree of each of them, with the parent, the
# time and the command line of each
function Get-ProcessEvidence([int[]] $rootIds, [string[]] $rootNames) {
	$all = @(Get-ProcessTable)
	$shown = [System.Collections.Generic.HashSet[int]]::new()
	$queue = [System.Collections.Generic.Queue[int]]::new()
	foreach ($id in @($rootIds) + @($all | Where-Object { $rootNames -contains $_.Name } | ForEach-Object { $_.ProcessId })) {
		if ([int] $id -gt 0 -and $shown.Add([int] $id)) { $queue.Enqueue([int] $id) }
	}
	while ($queue.Count -gt 0) {
		$parentId = $queue.Dequeue()
		foreach ($child in @($all | Where-Object { $_.ParentProcessId -eq $parentId })) {
			if ($shown.Add($child.ProcessId)) { $queue.Enqueue($child.ProcessId) }
		}
	}
	foreach ($process in @($all | Where-Object { $shown.Contains($_.ProcessId) } | Sort-Object ProcessId)) {
		$parent = @($all | Where-Object { $_.ProcessId -eq $process.ParentProcessId })[0]
		$parentName = if ($parent) { $parent.Name } else { 'gone' }
		'  process {0} {1}, parent {2} {3}, {4} threads, {5:N1} s of cpu, started {6}: {7}' -f $process.ProcessId, $process.Name, $process.ParentProcessId, $parentName, $process.ThreadCount, $process.Cpu, (Format-Utc $process.Started), $process.CommandLine
	}
}

# The Win32_Service object of a service (its state, the process that runs it, its start mode and exit code), with a time limit, or nothing
# when there is no such service. -SelfTest puts a function of this name in front of this one where its service is a stand-in: Linux has
# no CIM, and a workstation's service is not for ending.
function Get-ServiceDetails([string] $name) {
	return Get-CimInstance Win32_Service -Filter "Name='$name'" -OperationTimeoutSec $cimSeconds
}

# The process that the Service Control Manager gives for the service $name (sc.exe queryex): its id, 0 when the service has none, and
# nothing when sc.exe did not answer within $scSeconds or its answer has no process line. It asks the Service Control Manager and not CIM,
# so that it answers when CIM does not. -SelfTest puts a function of this name in front of this one where its service is a stand-in.
function Get-ServiceProcessId([string] $name) {
	try {
		$call = Start-ProcessWithHandle 'sc.exe' @('queryex', $name) $true
		if (-not $call.Process.WaitForExit($scSeconds * 1000)) {
			try { $call.Process.Kill($true) } catch { }
			return $null
		}
		if ((Get-PipeText $call.Output) -match '(?m)^\s*PID\s*:\s*(\d+)') { return [int] $Matches[1] }
	} catch { }
	return $null
}

# Why the process $id, which was read for the service $name some time ago, is not known to be its process now, or nothing when it is: the
# Service Control Manager gives that process for the service now, and the process has the name of the service's. The service may have
# ended since it was read, and another process may have its id (CI-FLAKE-6-R2, #624); that process must not be ended as the service.
function Get-ServiceProcessFault([string] $name, [int] $id) {
	$now = Get-ServiceProcessId $name
	if ($null -eq $now) { return "sc.exe queryex $name did not answer, so process $id is not known to be the service's" }
	if ($now -eq 0) { return "the Service Control Manager says that the service $name has no process now" }
	if ($now -ne $id) { return "the Service Control Manager says that the service $name runs in process $now now, not in process $id" }
	$process = Get-Process -Id $id -ErrorAction SilentlyContinue
	if ($null -eq $process) { return "process $id is gone" }
	if ($process.ProcessName -ne $serviceProcessName) { return "process $id is $($process.ProcessName), not $serviceProcessName" }
	return $null
}

function Format-ServiceLine([string] $name, $service) {
	if ($null -eq $service) { return "service ${name}: not installed" }
	return "service ${name}: $($service.State), process $($service.ProcessId), start mode $($service.StartMode), status $($service.Status), exit code $($service.ExitCode)"
}

# What a person needs to see why a wait for a service or for a program does not end: the state of the service, and the processes of
# the product, of the runner and of the programs that this script started, with the tree of each. Each part says why it could not be
# read. The queries have time limits of their own, so this ends.
function Get-WaitEvidence([string] $name, [int[]] $processIds) {
	$ids = [System.Collections.Generic.List[int]]::new()
	foreach ($id in @($processIds)) { $ids.Add($id) }
	try {
		$svc = Get-Service -Name $name -ErrorAction SilentlyContinue
		$line = if ($svc) { "service ${name}: $($svc.Status)" } else { "service ${name}: not installed" }
		try {
			$details = Get-ServiceDetails $name
			if ($details) {
				$line = Format-ServiceLine $name $details
				if ([int] $details.ProcessId -gt 0) { $ids.Add([int] $details.ProcessId) }
			}
		} catch {
			$line += " (details not read: $($_.Exception.Message))"
		}
		$line
	} catch {
		"service ${name}: not read ($($_.Exception.Message))"
	}
	'the processes of the product, the runner and the programs of this script, and the tree of each, with the parent and the command line of each:'
	try {
		Get-ProcessEvidence $ids.ToArray() @('ranz-node.exe', 'ranz.exe', 'msiexec.exe', 'Runner.Worker.exe', 'Runner.Listener.exe')
	} catch {
		"  not read: $($_.Exception.Message)"
	}
}

# Ends the process $id and every process that it started, and says for each of them, as it is found afterwards, whether it is gone:
# $ended and $notEnded take one line each. $table is the process table from before; when it is not given the table is read now. A
# process that is not there is no line: nothing was ended and nothing is claimed.
function Stop-ProcessTree([int] $id, [string] $role, $table, $ended, $notEnded) {
	$process = Get-Process -Id $id -ErrorAction SilentlyContinue
	if ($null -eq $process) { return }
	if ($null -eq $table) {
		try { $table = @(Get-ProcessTable) } catch { $table = @() }
	}
	$members = [System.Collections.Generic.List[object]]::new()
	$members.Add([pscustomobject]@{ Id = $id; Name = $process.ProcessName; Role = $role })
	foreach ($child in @(Get-Descendants $table $id)) {
		$members.Add([pscustomobject]@{ Id = [int] $child.ProcessId; Name = $child.Name; Role = "started by $role" })
	}
	try {
		$process.Kill($true)
	} catch {
		Write-Host "the process $id could not be ended: $($_.Exception.Message)"
	}
	$deadline = (Get-Date).AddSeconds(10)
	while (@($members | Where-Object { Test-ProcessAlive $_.Id }).Count -gt 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
	foreach ($member in $members) {
		$entry = "$($member.Name) (process $($member.Id), $($member.Role))"
		if (Test-ProcessAlive $member.Id) { $notEnded.Add($entry) } else { $ended.Add($entry) }
	}
}

# Runs this script again in a process of its own with the switch $mode and the request file $requestFile, which says what the process is to
# do, and gives it $seconds at the most. The evidence of a hang and the events of the diagnostics are read this way: a query that stalls
# must not hold this script, and a process can be ended where a job cannot. A process that is not done in time is ended, and its end is
# a line of $ended or $notEnded. Gives { TimedOut, ExitCode, ProcessId }: TimedOut is true only when the process was still running at
# its bound. A process that cannot be started throws.
function Invoke-ScriptProcess([string] $mode, [string] $requestFile, [int] $seconds, [string] $role, $ended, $notEnded) {
	$process = (Start-ProcessWithHandle $pwshPath @('-NoProfile', '-NonInteractive', '-File', $msiInstallScript, $mode, $requestFile)).Process
	$timedOut = -not $process.WaitForExit($seconds * 1000)
	$exitCode = $null
	if ($timedOut) {
		Stop-ProcessTree $process.Id $role $null $ended $notEnded
	} else {
		$exitCode = $process.ExitCode
	}
	return [pscustomobject]@{ TimedOut = $timedOut; ExitCode = $exitCode; ProcessId = $process.Id }
}

# What a call that does not end shows, written to the file that the request names as it is found, line by line, so that a part that
# stalls hides none of the parts before it: the msiexec processes, the processes of the runner and the tree of each, the end of the
# verbose log, the state of the service msiserver (read by the caller, which ends its process) and last the events of Windows Installer,
# the query that can stall. It runs in a process of its own (-EvidenceRequest), which the caller ends when the bound is reached.
function Write-MsiexecEvidence([string] $requestPath) {
	$request = Get-Content -LiteralPath $requestPath -Raw | ConvertFrom-Json
	$file = [string] $request.File
	$log = [string] $request.Log
	[System.IO.File]::WriteAllText($file, '')
	function Add-Evidence([string] $line) {
		Add-Content -LiteralPath $file -Value $line
	}
	Add-Evidence "msiexec processes, runner processes, the call (process $($request.CallId)) and the tree of each, with the parent and the command line of each:"
	try {
		$ids = @($request.RootIds | ForEach-Object { [int] $_ })
		foreach ($line in @(Get-ProcessEvidence $ids @('msiexec.exe', 'Runner.Worker.exe', 'Runner.Listener.exe'))) { Add-Evidence $line }
	} catch {
		Add-Evidence "  not read: $($_.Exception.Message)"
	}

	Add-Evidence "the verbose log ${log}:"
	try {
		if (Test-Path -LiteralPath $log) {
			$item = Get-Item -LiteralPath $log
			Add-Evidence ('  {0} bytes, last written {1}, and its last lines:' -f $item.Length, (Format-Utc $item.LastWriteTime))
			Get-Content -LiteralPath $log -Tail 40 | ForEach-Object { Add-Evidence "  $_" }
		} else {
			Add-Evidence '  the log is not there'
		}
	} catch {
		Add-Evidence "  not read: $($_.Exception.Message)"
	}

	if ($request.Service) {
		Add-Evidence (Format-ServiceLine 'msiserver' $request.Service)
	} elseif ($request.ServiceError) {
		Add-Evidence "service msiserver: not read ($($request.ServiceError))"
	} else {
		Add-Evidence (Format-ServiceLine 'msiserver' $null)
	}

	# The stall that -SelfTest plants where the query that can stall is
	if ([int] $request.StallSeconds -gt 0) { Start-Sleep -Seconds ([int] $request.StallSeconds) }
	Add-Evidence 'events of Windows Installer (provider MsiInstaller, log Application) of the last 15 minutes, the last 60 of them:'
	try {
		$events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'MsiInstaller'; StartTime = (Get-Date).AddMinutes(-15) } -ErrorAction SilentlyContinue)
		if ($events.Count -eq 0) { Add-Evidence '  none' }
		foreach ($record in @($events | Sort-Object RecordId | Select-Object -Last 60)) {
			Add-Evidence ('  {0} id {1}: {2}' -f (Format-Utc $record.TimeCreated), $record.Id, ($record.Message -replace '\s+', ' '))
		}
	} catch {
		Add-Evidence "  not read: $($_.Exception.Message)"
	}
}

# What -EventsRequest runs in a process of its own: the events that the request asks for (a log, a provider and the time to start from),
# one line each, written to the file of the request as they are found, or the reason that they could not be read. The stall that
# -SelfTest plants sleeps where the query that can stall is.
function Write-EventLines([string] $requestPath) {
	$request = Get-Content -LiteralPath $requestPath -Raw | ConvertFrom-Json
	$file = [string] $request.File
	[System.IO.File]::WriteAllText($file, '')
	if ([int] $request.StallSeconds -gt 0) { Start-Sleep -Seconds ([int] $request.StallSeconds) }
	try {
		$start = [datetime]::new([long] $request.StartTicks, [System.DateTimeKind]::Local)
		$events = @(Get-WinEvent -FilterHashtable @{ LogName = [string] $request.LogName; ProviderName = [string] $request.ProviderName; StartTime = $start } -ErrorAction SilentlyContinue)
		foreach ($record in @($events | Sort-Object RecordId)) {
			Add-Content -LiteralPath $file -Value ('  {0} id {1}: {2}' -f (Format-Utc $record.TimeCreated), $record.Id, ($record.Message -replace '\s+', ' '))
		}
	} catch {
		Add-Content -LiteralPath $file -Value "  not read: $($_.Exception.Message)"
	}
}

# Collects the evidence of the call $callId in a process of its own, for $evidenceSeconds at the most, and prints what the file holds
# when that process is done or ended. Whatever happens here, the caller goes on to end the call. A process that has to be ended is
# a line of $ended or $notEnded. Gives the file, the number of its lines, whether the process was still running at its bound and a
# note for the other things that can go wrong: the request could not be written, the process could not be started, or it ended with
# a code. Only TimedOut speaks of the bound (CI-FLAKE-6-R2, #624).
function Invoke-EvidenceCollection([int] $callId, [string] $log, [string] $step, $service, $serviceError, [int] $serviceId, $ended, $notEnded) {
	$file = Join-Path $LogDir "$step-evidence.txt"
	$requestFile = Join-Path $LogDir "$step-evidence-request.json"
	$result = [pscustomobject]@{ File = $file; Lines = 0; TimedOut = $false; Note = '' }
	try {
		$rootIds = @($callId)
		if ($serviceId -gt 0) { $rootIds += $serviceId }
		# The service as plain values: the CIM object holds far more than the line of the evidence needs, and JSON would write all of it
		$plain = $null
		if ($service) {
			$plain = [pscustomobject]@{ State = [string] $service.State; ProcessId = [int] $service.ProcessId; StartMode = [string] $service.StartMode; Status = [string] $service.Status; ExitCode = [long] $service.ExitCode }
		}
		$request = [pscustomobject]@{ CallId = $callId; Log = $log; File = $file; RootIds = $rootIds; Service = $plain; ServiceError = $serviceError; StallSeconds = $evidenceStall }
		$request | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $requestFile -Encoding utf8
		$run = Invoke-ScriptProcess '-EvidenceRequest' $requestFile $evidenceSeconds 'the evidence collection' $ended $notEnded
		$result.TimedOut = $run.TimedOut
		if ($run.TimedOut) {
			Write-Host "the evidence was not done within $evidenceSeconds s: its process $($run.ProcessId) is ended, and what it had found is below"
		} elseif ($run.ExitCode -ne 0) {
			$result.Note = "its process exited with the code $($run.ExitCode)"
		}
	} catch {
		Write-Host "the evidence could not be collected: $($_.Exception.Message)"
		$result.Note = "it could not be collected: $($_.Exception.Message)"
	}
	if (Test-Path -LiteralPath $file) {
		$lines = @(Get-Content -LiteralPath $file)
		$result.Lines = $lines.Count
		foreach ($line in $lines) { Write-Host $line }
	}
	return $result
}

# The end of a call that did not end: reads the state of the service msiserver, collects the evidence, ends the call with its process
# tree and the process of the service with its tree, and gives the message of the failure. The message lists the processes that were
# ended and the ones that were not, each as it was found afterwards, and speaks of the evidence and of the log only as far as they
# are there. The process of the service is ended only when the Service Control Manager says that it is the service's (see
# Get-ServiceProcessFault).
function Stop-HungCall([System.Diagnostics.Process] $call, [string] $what, [string] $step, [string] $log) {
	$ended = [System.Collections.Generic.List[string]]::new()
	$notEnded = [System.Collections.Generic.List[string]]::new()
	$notes = [System.Collections.Generic.List[string]]::new()
	# The service is read before anything ends: an install usually hangs in it, and its process is what the evidence and the end need. CIM
	# gives its state; when CIM does not answer, sc.exe queryex gives its process all the same, so that the service is ended then too
	$service = $null
	$serviceError = $null
	try { $service = Get-ServiceDetails 'msiserver' } catch { $serviceError = $_.Exception.Message }
	$serviceId = if ($service) { [int] $service.ProcessId } else { 0 }
	if ($serviceId -le 0) { $serviceId = [int] (Get-ServiceProcessId 'msiserver') }
	$evidence = Invoke-EvidenceCollection $call.Id $log $step $service $serviceError $serviceId $ended $notEnded
	$table = @()
	try {
		$table = @(Get-ProcessTable)
	} catch {
		$notes.Add("the processes could not be listed ($($_.Exception.Message)), so the processes that the call and the service started are not named")
	}
	Stop-ProcessTree $call.Id 'the call' $table $ended $notEnded
	# The evidence took a while, and the service may have ended in it, and its id be another process now: that process is ended only when
	# the Service Control Manager says that it is the service's, and it has the name of the service's process (CI-FLAKE-6-R2, #624)
	$serviceFault = $null
	if ($serviceId -gt 0) {
		$serviceFault = Get-ServiceProcessFault 'msiserver' $serviceId
		if (-not $serviceFault) { Stop-ProcessTree $serviceId 'the service msiserver' $table $ended $notEnded }
	}
	if ($serviceError) {
		$serviceText = "was not read ($serviceError)"
		if ($serviceId -gt 0) { $serviceText += ", and sc.exe queryex gives process $serviceId" }
	} elseif ($null -eq $service) {
		$serviceText = 'is not installed'
	} elseif ($serviceId -le 0) {
		$serviceText = "has no process ($($service.State))"
	} else {
		$serviceText = "was $($service.State) in process $serviceId"
	}
	if ($serviceFault) { $serviceText += "; it was not ended: $serviceFault" }
	$endedText = if ($ended.Count -gt 0) { $ended -join ', ' } else { 'nothing' }
	$notEndedText = if ($notEnded.Count -gt 0) { $notEnded -join ', ' } else { 'nothing' }
	$evidenceText = if ($evidence.Lines -gt 0) { "$($evidence.Lines) lines above and in $(Split-Path -Leaf $evidence.File)" } else { 'none was collected' }
	# The bound is named only when it was reached: a request that could not be written or a process that could not be started says what
	# happened in its note, and a bound that was never reached is no part of it
	if ($evidence.TimedOut) { $evidenceText += ", stopped at its bound of $evidenceSeconds s" }
	if ($evidence.Note) { $evidenceText += " ($($evidence.Note))" }
	$logText = if (Test-Path -LiteralPath $log) { "$log ($((Get-Item -LiteralPath $log).Length) bytes)" } else { 'was not written' }
	$message = "$what did not end within $msiexecSeconds s (step $step). Ended: $endedText. Not ended: $notEndedText. The service msiserver $serviceText. Evidence: $evidenceText. Verbose log: $logText."
	if ($notes.Count -gt 0) { $message += " Notes: $($notes -join '; ')." }
	return $message
}

# A msiexec run: its exit code and the path of its verbose log. A call that is not done after $msiexecSeconds is a hang: it prints the
# evidence and keeps it in a file of the log folder, ends the call and the service and fails with a message that names the call. The log
# is written with the flush flag (the ! of /l*v!): msiexec buffers its lines otherwise, and the last ones of a call that hangs, which say
# where, would be missing from its tail.
function Invoke-Msiexec([string] $verb, [string] $package, [string] $step) {
	# After a call that did not end Windows Installer is in a state that nobody knows: no other call starts
	if ($script:msiexecHang) { throw "msiexec $verb $(Split-Path -Leaf $package) was not started: an earlier call did not end ($script:msiexecHang)" }
	$log = Join-Path $LogDir "$step.log"
	$call = Start-Process -FilePath $msiexecFile -ArgumentList ($msiexecPrefix + @($verb, "`"$package`"", '/qn', '/norestart', '/l*v!', "`"$log`"")) -PassThru
	$script:lastLog = $log
	if (-not $call.WaitForExit($msiexecSeconds * 1000)) {
		$what = "msiexec $verb $(Split-Path -Leaf $package)"
		Write-Host "$what did not end within $msiexecSeconds s (step $step, process $($call.Id)). What the computer shows:"
		# Whatever the end of the call does, it fails
		try {
			$script:msiexecHang = Stop-HungCall $call $what $step $log
		} catch {
			$failure = $_.Exception.Message
			Write-Host "the end of the call stopped: $failure"
			try { $call.Kill($true) } catch { }
			$script:msiexecHang = "$what did not end within $msiexecSeconds s (step $step). Its end failed ($failure), so what was ended is not known."
		}
		throw $script:msiexecHang
	}
	Write-Host "msiexec $verb $(Split-Path -Leaf $package): exit code $($call.ExitCode) (log $log)"
	return [pscustomobject]@{ Code = $call.ExitCode; Log = $log }
}

function Wait-ServiceState([string] $name, [string] $state, [int] $seconds = 60) {
	$end = (Get-Date).AddSeconds($seconds)
	while ($true) {
		$svc = Get-Service -Name $name -ErrorAction SilentlyContinue
		if ($svc -and $svc.Status -eq $state) { return }
		if ((Get-Date) -ge $end) {
			Write-Host "$name did not reach $state within $seconds s. What the computer shows:"
			try {
				foreach ($line in @(Get-WaitEvidence $name @())) { Write-Host $line }
			} catch {
				Write-Host "the evidence stopped: $($_.Exception.Message)"
			}
			throw "$name did not reach $state within $seconds s (it is $(if ($svc) { $svc.Status } else { 'not installed' }))"
		}
		Start-Sleep -Milliseconds 500
	}
}

# Asks a service to stop or to start, and does not wait for it: Stop-Service and Start-Service wait for ever for a service that never
# gets there, so Wait-ServiceState waits, with a bound
function Request-ServiceState([string] $name, [string] $state) {
	$svc = Get-Service -Name $name
	if ($svc.Status -eq $state) { return }
	if ($state -eq 'Stopped') { $svc.Stop() } else { $svc.Start() }
}

# The SHA-256 of the Configuration store of the Node, read while the Node is stopped: it closes its store then.
# The Node runs again afterwards.
function Get-ClosedStoreHash {
	Request-ServiceState $nodeService 'Stopped'
	Wait-ServiceState $nodeService 'Stopped' $waitSeconds
	$hash = Get-Sha256 $store
	Request-ServiceState $nodeService 'Running'
	Wait-ServiceState $nodeService 'Running' $waitSeconds
	return $hash
}

# What ranz.exe version prints: its exit code and its line, with a bound. A call that is not done in $seconds prints the state of the
# Node service and the processes, ends the call and fails. $file and $prefix are ranz.exe and no arguments; -SelfTest puts a stand-in there.
# The call is started with Start-ProcessWithHandle, which holds its handle from its creation: ranz.exe version prints one line and
# ends, so it can be gone before a handle that is taken afterwards, and the exit code with it (CI-FLAKE-6-R2, #624).
function Get-RanzVersionLine([string] $file, [string[]] $prefix, [int] $seconds) {
	$out = Join-Path $LogDir 'ranz-version.out'
	$err = Join-Path $LogDir 'ranz-version.err'
	$call = Start-ProcessWithHandle $file @($prefix + @('version')) $true
	$process = $call.Process
	if (-not $process.WaitForExit($seconds * 1000)) {
		Write-Host "ranz.exe version did not end within $seconds s (process $($process.Id)). What the computer shows:"
		try {
			foreach ($line in @(Get-WaitEvidence $nodeService @($process.Id))) { Write-Host $line }
		} catch {
			Write-Host "the evidence stopped: $($_.Exception.Message)"
		}
		$ended = [System.Collections.Generic.List[string]]::new()
		$notEnded = [System.Collections.Generic.List[string]]::new()
		Stop-ProcessTree $process.Id 'the call' $null $ended $notEnded
		$endedText = if ($ended.Count -gt 0) { $ended -join ', ' } else { 'nothing' }
		$notEndedText = if ($notEnded.Count -gt 0) { $notEnded -join ', ' } else { 'nothing' }
		throw "ranz.exe version did not end within $seconds s. Ended: $endedText. Not ended: $notEndedText."
	}
	# What the call wrote stays in the log folder, as the redirection of Start-Process kept it
	$output = Get-PipeText $call.Output
	[System.IO.File]::WriteAllText($out, $output)
	[System.IO.File]::WriteAllText($err, (Get-PipeText $call.Error))
	return [pscustomobject]@{ Code = $process.ExitCode; Line = $output.Trim() }
}

# The events of the Service Control Manager since $since, for the diagnostics of a failed step. Get-WinEvent has no time limit, and a
# query that stalls would hold the diagnostics, and the end of the job with them, as it held the evidence of a hang (CI-FLAKE-6-R1, #596):
# the query runs in a process of its own (-EventsRequest) for $eventsSeconds at the most, and the lines that it had found are printed when
# it is done or ended (CI-FLAKE-6-R2, #624).
function Show-ServiceControlEvents([datetime] $since) {
	Write-Host 'Service Control Manager events since the start of the job:'
	$file = Join-Path $LogDir 'diagnostics-events.txt'
	$requestFile = Join-Path $LogDir 'diagnostics-events-request.json'
	$ended = [System.Collections.Generic.List[string]]::new()
	$notEnded = [System.Collections.Generic.List[string]]::new()
	try {
		$request = [pscustomobject]@{ File = $file; LogName = 'System'; ProviderName = 'Service Control Manager'; StartTicks = $since.Ticks; StallSeconds = $eventsStall }
		$request | ConvertTo-Json | Set-Content -LiteralPath $requestFile -Encoding utf8
		$run = Invoke-ScriptProcess '-EventsRequest' $requestFile $eventsSeconds 'the query of the events' $ended $notEnded
		if ($run.TimedOut) {
			Write-Host "  the events were not read within $eventsSeconds s: its process $($run.ProcessId) is ended, and what it had found is below"
			if ($notEnded.Count -gt 0) { Write-Host "  not ended: $($notEnded -join ', ')" }
		} elseif ($run.ExitCode -ne 0) {
			Write-Host "  the query of the events exited with the code $($run.ExitCode)"
		}
	} catch {
		Write-Host "  the events could not be read: $($_.Exception.Message)"
	}
	if (Test-Path -LiteralPath $file) {
		foreach ($line in @(Get-Content -LiteralPath $file)) { Write-Host $line }
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

# The main flow: the steps, then the clean-up whatever they did, then the list of the steps that failed as the error that fails the
# job. A call that did not end stops the steps (Step throws its message): the failure of its step is in the list already, and the
# clean-up still runs. Any other error of the steps is the script's own and ends it, after the clean-up.
function Invoke-Flow([scriptblock] $steps, [scriptblock] $cleanUp) {
	try {
		$null = & $steps
	} catch {
		if (-not $script:msiexecHang) { throw }
		$squeezed = ($script:msiexecHang -replace '\s+', ' ')
		if (@($failures | Where-Object { $_.EndsWith($squeezed) }).Count -eq 0) { $failures.Add("clean-up: $squeezed") }
	} finally {
		$null = & $cleanUp
	}
	if ($failures.Count -gt 0) {
		throw "$($failures.Count) steps failed:`n$($failures -join "`n")"
	}
}

# The lines of the script at $path that start msiexec anywhere but in Invoke-Msiexec, each as "line: text". The parser of PowerShell
# reads the script, so a comment, a message or a string that names msiexec starts nothing. A command starts msiexec when it is msiexec
# itself (by name or by path), or when it starts a program (Start-Process, Start-ProcessWithHandle, the call operator & or ., cmd,
# Invoke-Expression) or a Process (its Start) and names msiexec in its text, which holds the variables $msiexecFile and $msiexecPrefix
# too. Three more forms are forbidden (CI-FLAKE-6-R2, #624): a program started with a splat (Start-Process @splat), whose program is in
# a hashtable that this check does not read; a command that is given msiexec as an argument, which is how a helper that takes the program
# starts it (a command that prints, as Write-Host, only names it); and a call of a method of the Windows Installer object that installs
# (InstallProduct, ConfigureProduct, ReinstallProduct, ConfigureFeature, ApplyPatch): an install that has no msiexec.exe and no bound.
# Not seen, and left to the review of the diff: a program named by another variable or built from pieces of text, a ProcessStartInfo
# whose FileName is assigned, and a call of msi.dll through Add-Type.
function Get-MsiexecLaunches([string] $path) {
	$tokens = $null
	$errors = $null
	$ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref] $tokens, [ref] $errors)
	if ($errors.Count -gt 0) { throw "$path does not parse: line $($errors[0].Extent.StartLineNumber): $($errors[0].Message)" }
	$allowed = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-Msiexec' }, $true)
	if ($null -eq $allowed) { throw "$path has no function Invoke-Msiexec" }
	$starters = @('start-process', 'start', 'saps', 'start-processwithhandle', 'invoke-expression', 'iex', 'invoke-command', 'icm', 'cmd', 'cmd.exe')
	$printers = @('write-host', 'write-output', 'write-warning', 'write-error', 'write-verbose', 'write-debug', 'write-information')
	$installs = @('InstallProduct', 'ConfigureProduct', 'ReinstallProduct', 'ConfigureFeature', 'ApplyPatch')
	$nodes = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -or $node -is [System.Management.Automation.Language.MemberExpressionAst] }, $true)
	foreach ($node in $nodes) {
		if ($node.Extent.StartOffset -ge $allowed.Extent.StartOffset -and $node.Extent.EndOffset -le $allowed.Extent.EndOffset) { continue }
		$text = $node.Extent.Text
		$starts = $false
		if ($node -is [System.Management.Automation.Language.CommandAst]) {
			$name = $node.GetCommandName()
			$lowerName = if ($name) { $name.ToLowerInvariant() } else { '' }
			$operator = $node.InvocationOperator -ne [System.Management.Automation.Language.TokenKind]::Unknown
			$splatted = @($node.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.VariableExpressionAst] -and $_.Splatted }).Count -gt 0
			$given = @($node.CommandElements | Select-Object -Skip 1 | Where-Object { $_ -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $_.Value -match '^(.*[\\/])?msiexec(\.exe)?$' }).Count -gt 0
			if ($name -and $name -match '(^|[\\/])msiexec(\.exe)?$') {
				$starts = $true
			} elseif ($text -match 'msiexec' -and ($operator -or $starters -contains $lowerName)) {
				$starts = $true
			} elseif ($splatted -and $starters -contains $lowerName) {
				$starts = $true
			} elseif ($given -and $printers -notcontains $lowerName) {
				$starts = $true
			}
		} elseif ($installs -contains $node.Member.Extent.Text) {
			$starts = $true
		} elseif ($node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $text -match 'msiexec' -and @('Start', 'new') -contains $node.Member.Extent.Text) {
			$starts = $true
		}
		if ($starts) { "$($node.Extent.StartLineNumber): $($text -replace '\s+', ' ')" }
	}
}

# The self-test below. A bound that no hang has tested proves nothing, so each wait is run on a planted hang: a stand-in for msiexec.exe
# that never ends and starts a child that never ends either, a stand-in for the service msiserver (a process with a child) on Linux,
# which has none, a Node that does not stop and one that does not start, and a ranz.exe that never prints its version. Each must fail
# within its bound, with a message that names it, with the evidence that belongs to it, and every process that the message says was
# ended must be gone. The evidence of a call is checked part by part, and so is the check of the evidence: for each part a copy of the
# evidence without it, or with what a query that failed prints in its place ("none", "not read"), must fail the check. The stand-ins
# sleep for 120 s, so a call with no bound returns after 120 s with no failure, and the check fails on that. On Windows the real
# msiexec.exe runs once, on a package that is not there, and the evidence holds its event (id 1040) and the state of the real service.

# The folder of a planted run, with the stand-ins in it, which are scripts that pwsh runs
function New-PlantedWork {
	$work = Join-Path ([System.IO.Path]::GetTempPath()) "msi-install-selftest-$([guid]::NewGuid().ToString('N'))"
	New-Item -ItemType Directory -Force -Path $work | Out-Null
	Set-Content -LiteralPath (Join-Path $work 'standin-msiexec.ps1') -Value @'
# A stand-in for msiexec.exe (the self-test of msi-install.ps1): refused.msi exits with 23 at once, any other package hangs. The stand-in
# writes its verbose log as msiexec does with the flush flag /l*v!, each line as it is written; without the flag the last line stays in its
# buffer and is lost when the process is ended. It starts a child that does not end either, writes both process ids and its arguments
# next to the log and sleeps.
$package = $args[1]
$flag = @($args | Where-Object { $_ -like '/l*v*' })[0]
$log = $args[[array]::IndexOf($args, $flag) + 1]
if ((Split-Path -Leaf $package) -eq 'refused.msi') { exit 23 }
$lines = @('planted verbose log, line 1', 'planted verbose log, line 2: the last line')
if ($flag -ne '/l*v!') { $lines = @($lines[0]) }
Set-Content -LiteralPath $log -Value $lines
Set-Content -LiteralPath "$log.args" -Value ($args -join ' ')
$child = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 120') -PassThru
Set-Content -LiteralPath "$log.pids" -Value "$PID $($child.Id)"
Start-Sleep -Seconds 120
'@
	Set-Content -LiteralPath (Join-Path $work 'standin-service.ps1') -Value @'
# A stand-in for the Windows Installer service on a computer that has none (the self-test on Linux): a process that never ends, with a
# child that does not end either, as the service has the action that an install hung in under it. Both process ids go to the file.
$child = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 120') -PassThru
Set-Content -LiteralPath $args[0] -Value "$PID $($child.Id)"
Start-Sleep -Seconds 120
'@
	Set-Content -LiteralPath (Join-Path $work 'standin-ranz.ps1') -Value @'
# A stand-in for ranz.exe (the self-test of msi-install.ps1): "quick version" prints the line of ranz.exe version at once, "gone version"
# ends at once with the exit code 42 and prints nothing, any other call hangs
if ($args[0] -eq 'quick') { 'ranz 9.9.9'; exit 0 }
if ($args[0] -eq 'gone') { exit 42 }
Start-Sleep -Seconds 120
'@
	return $work
}

# The process ids that a stand-in wrote to a file
function Read-Pids([string] $path) {
	return @(((Read-MsiLog $path) -split '\s+') | Where-Object { $_ } | ForEach-Object { [int] $_ })
}

# Waits until a file has something in it
function Wait-File([string] $path, [int] $seconds) {
	$end = (Get-Date).AddSeconds($seconds)
	while (-not ((Test-Path -LiteralPath $path) -and (Get-Item -LiteralPath $path).Length -gt 0) -and (Get-Date) -lt $end) { Start-Sleep -Milliseconds 200 }
	return ((Test-Path -LiteralPath $path) -and (Get-Item -LiteralPath $path).Length -gt 0)
}

# A stand-in for the service msiserver: its process ids, and what Get-ServiceDetails gives for it
function Start-StandInService([string] $work, [string] $name) {
	$pidsFile = Join-Path $work "$name.pids"
	$null = Start-Process -FilePath $pwshPath -ArgumentList @('-NoProfile', '-NonInteractive', '-File', "`"$(Join-Path $work 'standin-service.ps1')`"", "`"$pidsFile`"") -PassThru
	if (-not (Wait-File $pidsFile 60)) { throw "the stand-in for the service wrote no process ids within 60 s" }
	$ids = @(Read-Pids $pidsFile)
	if ($ids.Count -ne 2) { throw "the stand-in for the service wrote $($ids.Count) process ids, not two: its own and its child's" }
	return [pscustomobject]@{
		ProcessIds = $ids
		Details = [pscustomobject]@{ State = 'Running'; ProcessId = $ids[0]; StartMode = 'Manual'; Status = 'OK'; ExitCode = 0 }
	}
}

# Points the calls of Invoke-Msiexec at the stand-in for msiexec.exe in $work
function Set-PlantedMsiexec([string] $work) {
	$script:msiexecFile = $pwshPath
	$script:msiexecPrefix = @('-NoProfile', '-NonInteractive', '-File', "`"$(Join-Path $work 'standin-msiexec.ps1')`"")
}

# Runs $body and gives what it printed, the message that it failed with ($null when it did not fail) and the seconds that it took
function Invoke-Captured([scriptblock] $body) {
	$lines = [System.Collections.Generic.List[string]]::new()
	$thrown = $null
	$watch = [System.Diagnostics.Stopwatch]::StartNew()
	try {
		& $body 6>&1 | ForEach-Object { $lines.Add([string] $_) }
	} catch {
		$thrown = $_.Exception.Message
	}
	return [pscustomobject]@{ Output = ($lines -join "`n"); Thrown = $thrown; Seconds = $watch.Elapsed.TotalSeconds }
}

# The evidence text as its parts, found by the headings that Write-MsiexecEvidence prints: the lines of each part, and the line of the
# state of the service. A part whose heading is not there is not in the result.
function Split-Evidence([string] $text) {
	$parts = @{}
	$current = $null
	foreach ($line in @($text -split "`r?`n")) {
		if ($line.StartsWith('msiexec processes, runner processes')) { $current = 'Processes'; $parts[$current] = @(); continue }
		if ($line.StartsWith('the verbose log ')) { $current = 'Log'; $parts[$current] = @(); continue }
		if ($line.StartsWith('events of Windows Installer (')) { $current = 'Events'; $parts[$current] = @(); continue }
		if ($line.StartsWith('service msiserver: ')) { $parts['Service'] = $line; $current = $null; continue }
		if ($current -and $line.Trim()) { $parts[$current] += $line }
	}
	return $parts
}

# What is wrong with the parts of the evidence of a call that did not end, as one line for each fault. $want names what must be in them:
# the process ids of the processes that must be listed, the last line of the verbose log, a pattern for the line of the state of the
# service and a pattern for the event of the planted call (none: the part must only be there, as on a computer that has no event log). A
# part that says "none" or "not read" is no part that holds what it should.
function Get-EvidenceFaults($parts, $want) {
	$faults = [System.Collections.Generic.List[string]]::new()
	if ($null -eq $parts.Processes) {
		$faults.Add('the list of processes is not there')
	} else {
		$unread = @($parts.Processes | Where-Object { $_.Trim().StartsWith('not read') })
		if ($unread.Count -gt 0) { $faults.Add("the list of processes could not be read ($($unread[0].Trim()))") }
		foreach ($id in $want.ProcessIds) {
			if (@($parts.Processes | Where-Object { $_.StartsWith("  process $id ") }).Count -eq 0) { $faults.Add("the list of processes has no line for process $id") }
		}
	}
	if ($null -eq $parts.Log) {
		$faults.Add('the tail of the verbose log is not there')
	} elseif (@($parts.Log).Count -eq 0 -or @($parts.Log)[-1].Trim() -ne $want.LogLastLine) {
		$faults.Add("the tail of the verbose log does not end with '$($want.LogLastLine)'")
	}
	if ($null -eq $parts.Service) {
		$faults.Add('the state of the service is not there')
	} elseif ($parts.Service -notmatch $want.ServicePattern) {
		$faults.Add("the state of the service is not read: '$($parts.Service)'")
	}
	if ($null -eq $parts.Events) {
		$faults.Add('the events of Windows Installer are not there')
	} elseif ($want.EventPattern) {
		if (@($parts.Events | Where-Object { $_ -match $want.EventPattern }).Count -eq 0) {
			$faults.Add("the events of Windows Installer hold no event of the planted call ($($want.EventPattern)): '$(@($parts.Events) -join ' / ')'")
		}
	}
	return $faults.ToArray()
}

# The bound of the msiexec call of the planted flow, in seconds
$flowBound = 10
# The bound of the evidence in the planted stall, in seconds: the process that collects it needs a few seconds to start on a runner
# before it has a part to write, and the check is that the parts before the stall are kept
$stallBound = 10

# Whether -SelfTest may end the real service msiserver: a planted hang ends the service with its whole tree, busy or not. That harms
# nothing on a runner of GitHub Actions, where nothing else uses it, and it would end the install of somebody else on a workstation
# (CI-FLAKE-6-R2, #624). On any other computer a process stands in for the service: Linux has none at all.
function Test-RealServiceMayBeEnded([bool] $windows, [string] $githubActions) {
	return ($windows -and $githubActions -eq 'true')
}

# Runs the main flow of the script at $path on a planted hang, in a process of its own (-SelfTestFlow), and checks what the job would see:
# a non-zero exit code, the call in the message, the failed step in the list that the summary prints, the clean-up, and no step after
# the call. The line of Invoke-Msiexec that names the call is printed before anything fails, so it does not show that the summary holds
# the list of the failed steps: the step is looked for under its own name, after the first line of the summary, which the process
# prints whole before it fails (CI-FLAKE-6-R2, #624). -SelfTest runs this on the script itself, and -CheckFlow on a script that a
# fixture changed.
function Test-PlantedFlow([string] $path) {
	$call = Start-ProcessWithHandle $pwshPath @('-NoProfile', '-NonInteractive', '-File', $path, '-SelfTestFlow') $true
	$process = $call.Process
	if (-not $process.WaitForExit(180000)) {
		$process.Kill($true)
		throw 'the main flow on a planted hang did not end within 180 s'
	}
	$text = (Get-PipeText $call.Output) + (Get-PipeText $call.Error)
	if ($process.ExitCode -eq 0) { throw "the main flow on a planted hang exited with the code 0, as if nothing had failed:`n$text" }
	foreach ($want in @('1 steps failed:', "the run stops after 'the call that never ends'", 'planted clean-up ran')) {
		if (-not $text.Contains($want)) { throw "the output of the main flow on a planted hang has no '$want':`n$text" }
	}
	$summary = $text.Substring($text.IndexOf('1 steps failed:', [System.StringComparison]::Ordinal))
	$listed = "the call that never ends: msiexec /i hang.msi did not end within $flowBound s"
	if (-not $summary.Contains($listed)) { throw "the summary of the main flow on a planted hang does not list the failed step ('$listed') after its first line, '1 steps failed:':`n$text" }
	if ($text.Contains('planted: the step after the hang ran')) { throw "the main flow ran a step after the call that did not end:`n$text" }
	if ($text.Contains('planted: the flow ended without an error')) { throw "the main flow on a planted hang ended without an error:`n$text" }
	Write-Host "ok: the main flow on a planted hang exits with the code $($process.ExitCode), with the call in its message, after its clean-up, and runs no step after the call"
}

function Invoke-SelfTest {
	$bound = 15
	if (-not $msiInstallScript -or -not (Test-Path -LiteralPath $msiInstallScript)) { throw "this script does not know its own path ('$msiInstallScript'), which the process that collects the evidence and the planted flow need" }
	$work = New-PlantedWork
	$script:LogDir = $work
	try {
		# Where the real service msiserver is not for ending, a process stands in for it below, as on Linux
		$decisions = @(
			@{ Windows = $true; Actions = 'true'; Real = $true },
			@{ Windows = $true; Actions = ''; Real = $false },
			@{ Windows = $false; Actions = 'true'; Real = $false }
		)
		foreach ($case in $decisions) {
			if ((Test-RealServiceMayBeEnded $case.Windows $case.Actions) -ne $case.Real) { throw "the real service msiserver may be ended: $(-not $case.Real), for Windows $($case.Windows) and GITHUB_ACTIONS '$($case.Actions)'" }
		}
		Write-Host 'ok: the real service msiserver may be ended on Windows in GitHub Actions only: not on a workstation, and not on Linux, which has none'
		$realService = Test-RealServiceMayBeEnded $IsWindows $env:GITHUB_ACTIONS
		if ($IsWindows -and -not $realService) {
			Write-Host 'skipped: the planted hangs do not end the real service msiserver here, as GITHUB_ACTIONS is not true and an install of somebody else may be running in it: a process stands in for the service, as on Linux'
		}

		$notThere = Join-Path $work 'not-there.msi'
		if ($IsWindows) {
			# The real call ends in a few seconds, and the first one of a runner starts the service: its bound is wide, so that a slow start
			# is no hang here. The bound is what the planted calls below test.
			$script:msiexecSeconds = 60
			$real = Invoke-Msiexec '/i' $notThere 'planted-not-there'
			# 1619 is ERROR_INSTALL_PACKAGE_OPEN_FAILED: the real msiexec.exe took the command line, with its flush flag, and could not open the package
			if ($real.Code -ne 1619) { throw "the real msiexec.exe gave the exit code '$($real.Code)' for a package that is not there, not 1619 (the package could not be opened)" }
			Write-Host 'ok: the real msiexec.exe gives its exit code for a package that is not there, and takes its command line with the flush flag'
		}
		$script:msiexecSeconds = $bound
		Set-PlantedMsiexec $work

		$refused = Invoke-Msiexec '/i' (Join-Path $work 'refused.msi') 'planted-refused'
		if ($refused.Code -ne 23) { throw "a call that ends gave the exit code $($refused.Code), not 23" }
		if (Test-Path -LiteralPath (Join-Path $work 'planted-refused-evidence.txt')) { throw 'a call that ended left the evidence of a hang' }
		Write-Host 'ok: a call that ends gives its exit code, and leaves no evidence of a hang'

		# The time limit of a query of CIM and the bound of the events of the diagnostics. They run here, before the stand-in for the service
		# below hides the function whose limit the first of them tests
		Invoke-SelfTestQueries

		# Where the service is a stand-in (Linux has no Windows Installer service, and a workstation's is not for ending) a process stands in
		# for it, and functions hide the CIM query and sc.exe queryex for everything below
		$standInServices = @{}
		$standInSc = @{}
		$service = $null
		if (-not $realService) {
			function Get-ServiceDetails([string] $name) { if ($standInServices.ContainsKey($name)) { $standInServices[$name] } }
			function Get-ServiceProcessId([string] $name) { if ($standInSc.ContainsKey($name)) { $standInSc[$name] } }
			$service = Start-StandInService $work 'planted-service-1'
			$standInServices['msiserver'] = $service.Details
			$standInSc['msiserver'] = $service.ProcessIds[0]
			$script:serviceProcessName = (Get-Process -Id $PID).ProcessName
		}

		$thrown = $null
		$watch = [System.Diagnostics.Stopwatch]::StartNew()
		try {
			$hung = Invoke-Msiexec '/i' (Join-Path $work 'hang.msi') 'planted-hang'
		} catch {
			$thrown = $_.Exception.Message
		}
		$seconds = $watch.Elapsed.TotalSeconds
		if (-not $thrown) { throw "a msiexec that never ends was not bounded: the call returned after $([int] $seconds) s with the exit code $($hung.Code) and no failure, and its bound is $bound s" }
		if ($seconds -lt $bound -or $seconds -gt $bound + 60) { throw "the call failed after $([int] $seconds) s, not within its bound of $bound s (and 60 s for the evidence and the end)" }
		if ($thrown -notlike "msiexec /i hang.msi did not end within $bound s*") { throw "the failure does not name the verb and the package: $thrown" }
		if ($thrown -ne $script:msiexecHang) { throw "Step stops the run at the message in msiexecHang, which is '$script:msiexecHang', not '$thrown'" }
		Write-Host "ok: a msiexec that never ends fails within its bound ($bound s, after $([int] $seconds) s), and the failure names the verb and the package"

		# What the failure says was ended and what was not: every process that it lists as ended is gone, the processes of the call and of
		# the stand-in for the service (Linux) are in the list, and so is the process of the real service when there was one
		$ids = @(Read-Pids (Join-Path $work 'planted-hang.log.pids'))
		if ($ids.Count -ne 2) { throw "the stand-in wrote $($ids.Count) process ids, not two: its own and its child's" }
		$tree = @($ids)
		if (-not $realService) { $tree += $service.ProcessIds }
		if (-not ($thrown -match 'Ended: (?<ended>.*?)\. Not ended: (?<notended>.*?)\. The service msiserver (?<service>.*?)\. Evidence: ')) { throw "the failure has no 'Ended: ... Not ended: ... The service msiserver ... Evidence: ...' to read: $thrown" }
		$endedText = $Matches['ended']
		$notEndedText = $Matches['notended']
		$serviceText = $Matches['service']
		$deadline = (Get-Date).AddSeconds(15)
		while (@($tree | Where-Object { Test-ProcessAlive ([int] $_) }).Count -gt 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
		$alive = @($tree | Where-Object { Test-ProcessAlive ([int] $_) })
		if ($alive.Count -gt 0) { throw "the process tree of the call, or the stand-in for the service, is still there after the failure: process $($alive -join ', ')" }
		foreach ($id in $tree) {
			if ($endedText -notmatch "process $id,") { throw "the failure does not list process $id, which it ended, as ended (it says: Ended: $endedText. Not ended: $notEndedText): $thrown" }
		}
		# The stand-ins are all ended; the real service of Windows may refuse to end, and the failure then says so
		if (-not $realService -and $notEndedText -ne 'nothing') { throw "the failure lists processes as not ended, and all of them are gone: $notEndedText" }
		foreach ($match in [regex]::Matches($endedText, 'process (\d+),')) {
			if (Test-ProcessAlive ([int] $match.Groups[1].Value)) { throw "the failure says that process $($match.Groups[1].Value) was ended, and it is still there: $thrown" }
		}
		Write-Host 'ok: the process tree of the call and the process of the service msiserver (with its child) are ended, and the failure lists exactly what was ended'

		# The evidence: a file with every part, whole
		$evidenceFile = Join-Path $work 'planted-hang-evidence.txt'
		if (-not (Test-Path -LiteralPath $evidenceFile)) { throw 'the call that did not end kept no evidence in a file' }
		$evidence = Read-MsiLog $evidenceFile
		$parts = Split-Evidence $evidence
		$eventPattern = 'id 1040:.*' + [regex]::Escape("$(Split-Path -Leaf $work)$([System.IO.Path]::DirectorySeparatorChar)not-there.msi")
		$want = @{
			ProcessIds = $tree
			LogLastLine = 'planted verbose log, line 2: the last line'
			ServicePattern = '^service msiserver: (Running|Stopped|Start Pending|Stop Pending), process \d+'
			EventPattern = $null
		}
		# Windows has the event log: the event of the real call that was planted (id 1040 of not-there.msi). Where the service is the real
		# one, its state is in the evidence as it is: if it ran, the real service is in the message as ended or not ended; if it did not,
		# the message says so.
		if ($IsWindows) { $want.EventPattern = $eventPattern }
		if ($realService) {
			if ($parts.Service -match '^service msiserver: (Running|Start Pending|Stop Pending), process (\d+)') {
				$serviceId = [int] $Matches[2]
				if ($serviceId -gt 0 -and "$endedText, $notEndedText" -notmatch "process $serviceId,") { throw "the service msiserver ran in process $serviceId, and the failure lists it neither as ended nor as not ended: $thrown" }
				$listedAs = if ($endedText -match "process $serviceId,") { 'ended' } else { 'not ended' }
				$serviceNow = if (Test-ProcessAlive $serviceId) { 'still there' } else { 'gone' }
				Write-Host "the real service msiserver ran in process $serviceId, the failure lists it as $listedAs, and the process is $serviceNow"
			} elseif ($serviceText -notmatch '^has no process') {
				throw "the service msiserver has no process in the evidence ($($parts.Service)), and the failure says: The service msiserver $serviceText"
			}
		}
		$faults = @(Get-EvidenceFaults $parts $want)
		if ($faults.Count -gt 0) { throw "the evidence of the call that did not end is not whole: $($faults -join '; ')`n$evidence" }
		Write-Host 'ok: the evidence holds the processes, the end of the verbose log, the state of msiserver and the events of Windows Installer, and is kept in a file'

		$passed = Read-MsiLog (Join-Path $work 'planted-hang.log.args')
		if ($passed -notmatch '(^| )/l\*v!( |$)') { throw "the call did not give msiexec the flush flag /l*v!: '$passed'" }
		Write-Host 'ok: the verbose log is written with the flush flag, and the tail that the evidence prints holds its last line'

		# The check of the evidence on the evidence that lacks a part: it must fail, for that part. The events of Linux are none that
		# this computer has, so a planted event stands in for the one of the planted call there.
		$base = $parts.Clone()
		$wantAll = $want.Clone()
		$wantAll.EventPattern = $eventPattern
		if (-not $IsWindows) { $base.Events = @("  2026-01-01 00:00:00Z id 1040: Beginning a Windows Installer transaction: $notThere. Client Process Id: 1.") }
		$clean = @(Get-EvidenceFaults $base $wantAll)
		if ($clean.Count -gt 0) { throw "the check of the evidence found faults in evidence that has every part: $($clean -join '; ')" }
		$cases = @(
			@{ Part = 'list of processes'; What = 'a list of processes that is not there'; Change = { param($p) $p.Remove('Processes') } },
			@{ Part = 'list of processes'; What = 'a list of processes that could not be read'; Change = { param($p) $p.Processes = @('  not read: planted') } },
			@{ Part = 'list of processes'; What = 'a list that holds none of the processes of the call'; Change = { param($p) $p.Processes = @('  process 1 init, parent 0 gone, 1 threads, 0.0 s of cpu, started : init') } },
			@{ Part = 'tail of the verbose log'; What = 'a tail without the last line of the log'; Change = { param($p) $p.Log = @($p.Log | Select-Object -SkipLast 1) } },
			@{ Part = 'tail of the verbose log'; What = 'a log that is not there'; Change = { param($p) $p.Log = @('  the log is not there') } },
			@{ Part = 'state of the service'; What = 'a state of the service that could not be read'; Change = { param($p) $p.Service = 'service msiserver: not read (planted)' } },
			@{ Part = 'state of the service'; What = 'a state of the service that is not there'; Change = { param($p) $p.Remove('Service') } },
			@{ Part = 'events of Windows Installer'; What = 'events that are none'; Change = { param($p) $p.Events = @('  none') } },
			@{ Part = 'events of Windows Installer'; What = 'events that could not be read'; Change = { param($p) $p.Events = @('  not read: planted') } },
			@{ Part = 'events of Windows Installer'; What = 'events without the one of the planted call'; Change = { param($p) $p.Events = @('  2026-01-01 00:00:00Z id 1033: Windows Installer installed the product.') } }
		)
		foreach ($case in $cases) {
			$copy = $base.Clone()
			& $case.Change $copy
			$found = @(Get-EvidenceFaults $copy $wantAll)
			if (@($found | Where-Object { $_ -like "*$($case.Part)*" }).Count -eq 0) { throw "the check of the evidence passed $($case.What): it found [$($found -join '; ')], none for the $($case.Part)" }
			Write-Host "ok: the check of the evidence fails on $($case.What)"
		}

		$after = $null
		try {
			[void](Invoke-Msiexec '/i' (Join-Path $work 'refused.msi') 'planted-after-hang')
		} catch {
			$after = $_.Exception.Message
		}
		if (-not $after) { throw 'a call started after a call that did not end' }
		Write-Host 'ok: no other call starts after a call that did not end'

		# A stall in the collection of the evidence: the query of the events sleeps for 120 s, the evidence has a bound of $stallBound s, and
		# the call is still ended and failed, with the bound in the message and the parts that were found before the stall
		$script:msiexecHang = $null
		$script:evidenceSeconds = $stallBound
		$script:evidenceStall = 120
		$service2 = $null
		if (-not $realService) {
			$service2 = Start-StandInService $work 'planted-service-2'
			$standInServices['msiserver'] = $service2.Details
			$standInSc['msiserver'] = $service2.ProcessIds[0]
		}
		$thrown = $null
		$watch = [System.Diagnostics.Stopwatch]::StartNew()
		try {
			[void](Invoke-Msiexec '/i' (Join-Path $work 'hang.msi') 'planted-stall')
		} catch {
			$thrown = $_.Exception.Message
		}
		$seconds = $watch.Elapsed.TotalSeconds
		$script:evidenceSeconds = 60
		$script:evidenceStall = 0
		if (-not $thrown) { throw 'a call whose evidence stalls was not failed' }
		if ($seconds -lt $bound -or $seconds -gt $bound + $stallBound + 60) { throw "the call whose evidence stalls failed after $([int] $seconds) s, not within its bound of $bound s and the $stallBound s of the evidence (and 60 s to end the processes)" }
		if ($thrown -notlike "msiexec /i hang.msi did not end within $bound s*") { throw "the failure of the call whose evidence stalls does not name the verb and the package: $thrown" }
		if ($thrown -notlike "*Evidence: * stopped at its bound of $stallBound s*") { throw "the failure of the call whose evidence stalls does not name the bound of the evidence, $stallBound s: $thrown" }
		if (-not ($thrown -match 'Ended: (?<ended>.*?)\. Not ended: ') -or $Matches['ended'] -notmatch 'the evidence collection') { throw "the failure does not list the process that collected the evidence as ended: $thrown" }
		$ids2 = @(Read-Pids (Join-Path $work 'planted-stall.log.pids'))
		$tree2 = @($ids2)
		if (-not $realService) { $tree2 += $service2.ProcessIds }
		$deadline = (Get-Date).AddSeconds(15)
		while (@($tree2 | Where-Object { Test-ProcessAlive ([int] $_) }).Count -gt 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
		$alive = @($tree2 | Where-Object { Test-ProcessAlive ([int] $_) })
		if ($ids2.Count -ne 2 -or $alive.Count -gt 0) { throw "after the stall the call (process ids '$($ids2 -join ' ')') or the stand-in for the service is still there: process $($alive -join ', ')" }
		$parts2 = Split-Evidence (Read-MsiLog (Join-Path $work 'planted-stall-evidence.txt'))
		if ($null -eq $parts2.Processes -or $null -ne $parts2.Events) { throw 'the evidence of the call whose collection stalled does not hold the parts before the stall and none after it' }
		Write-Host "ok: a stall in the evidence still ends the call and its processes and fails the step within its bound ($bound s and the $stallBound s of the evidence, after $([int] $seconds) s), and the failure names the bound"
		$script:msiexecHang = $null

		Invoke-SelfTestEnd $work
		Invoke-SelfTestWaits $work

		# The main flow on a planted hang, in a process of its own: the exit code, the message and the clean-up are what the job sees
		Test-PlantedFlow $msiInstallScript
	} finally {
		$script:evidenceSeconds = 60
		$script:evidenceStall = 0
		$script:serviceProcessName = 'msiexec'
		# Whatever a check did, no stand-in stays behind
		foreach ($file in @(Get-ChildItem -LiteralPath $work -Filter '*.pids' -ErrorAction SilentlyContinue)) {
			foreach ($id in @(Read-Pids $file.FullName)) {
				try { (Get-Process -Id $id -ErrorAction Stop).Kill($true) } catch { }
			}
		}
		Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
	}
}

# The waits for the Node and ranz.exe version on a planted hang: a Node that does not stop, a Node that does not start and a ranz.exe that
# never prints. A function in front of Get-Service and Get-ServiceDetails stands in for the Node, on Windows too.
function Invoke-SelfTestWaits([string] $work) {
	$nodeService = 'ranzvpnserver'
	$store = Join-Path $work 'ranz_node.db'
	Set-Content -LiteralPath $store -Value 'the store'
	$stuck = [pscustomobject]@{ Status = 'Running' }
	Add-Member -InputObject $stuck -MemberType ScriptMethod -Name Stop -Value { }
	Add-Member -InputObject $stuck -MemberType ScriptMethod -Name Start -Value { }
	$stops = [pscustomobject]@{ Status = 'Running' }
	Add-Member -InputObject $stops -MemberType ScriptMethod -Name Stop -Value { $this.Status = 'Stopped' }
	Add-Member -InputObject $stops -MemberType ScriptMethod -Name Start -Value { }
	$node = $stuck
	function Get-Service {
		[CmdletBinding()]
		param([string] $Name)
		if ($Name -eq $nodeService) { $node }
	}
	function Get-ServiceDetails([string] $name) {
		if ($name -eq $nodeService) { [pscustomobject]@{ State = $node.Status; ProcessId = $PID; StartMode = 'Auto'; Status = 'OK'; ExitCode = 0 } }
	}
	$script:waitSeconds = 3
	try {
		$r = Invoke-Captured { [void](Get-ClosedStoreHash) }
		if (-not $r.Thrown) { throw 'a Node that does not stop was waited for, and the wait did not fail' }
		if ($r.Seconds -lt 3 -or $r.Seconds -gt 3 + 30) { throw "the wait for a Node that does not stop failed after $([int] $r.Seconds) s, not within its bound of 3 s: $($r.Thrown)" }
		if ($r.Thrown -ne "$nodeService did not reach Stopped within 3 s (it is Running)") { throw "the failure of the wait for a Node that does not stop is '$($r.Thrown)'" }
		foreach ($want in @("service ${nodeService}: Running, process $PID", 'the processes of the product', "  process $PID ")) {
			if (-not $r.Output.Contains($want)) { throw "the evidence of a Node that does not stop has no '$want':`n$($r.Output)" }
		}
		Write-Host "ok: a Node that does not stop fails the wait within its bound (3 s, after $([int] $r.Seconds) s), with the state of the service and the processes"

		$stops.Status = 'Running'
		$node = $stops
		$r = Invoke-Captured { [void](Get-ClosedStoreHash) }
		if (-not $r.Thrown) { throw 'a Node that does not start was waited for, and the wait did not fail' }
		if ($r.Seconds -lt 3 -or $r.Seconds -gt 3 + 30) { throw "the wait for a Node that does not start failed after $([int] $r.Seconds) s, not within its bound of 3 s: $($r.Thrown)" }
		if ($r.Thrown -ne "$nodeService did not reach Running within 3 s (it is Stopped)") { throw "the failure of the wait for a Node that does not start is '$($r.Thrown)'" }
		foreach ($want in @("service ${nodeService}: Stopped, process $PID", 'the processes of the product', "  process $PID ")) {
			if (-not $r.Output.Contains($want)) { throw "the evidence of a Node that does not start has no '$want':`n$($r.Output)" }
		}
		Write-Host "ok: a Node that does not start fails the wait within its bound (3 s, after $([int] $r.Seconds) s), with the state of the service and the processes"

		$stops.Status = 'Running'
		$script:waitSeconds = 30
		$node = $stops
		Add-Member -InputObject $stops -MemberType ScriptMethod -Name Start -Value { $this.Status = 'Running' } -Force
		$hash = Get-ClosedStoreHash
		if ($hash -ne (Get-Sha256 $store)) { throw 'a Node that stops and starts gave the wrong hash of its store' }
		Write-Host 'ok: a Node that stops and starts is left alone, and its store is hashed while it is stopped'
		$script:waitSeconds = 3

		# A process that ends at once keeps its exit code: nothing asks the process for it until 2 s after it ended. A Process that
		# Start-Process -PassThru gives takes its handle when it is first asked for something, and the exit code of a process that ended before
		# that is lost (CI-FLAKE-6-R2, #624).
		$gone = Start-ProcessWithHandle $pwshPath @('-NoProfile', '-NonInteractive', '-Command', 'exit 42')
		Start-Sleep -Seconds 2
		if (-not $gone.Process.WaitForExit(30000)) { throw 'a process that exits at once did not end within 30 s' }
		if ($gone.Process.ExitCode -ne 42) { throw "a process that exited with the code 42 at once, and was asked for it 2 s later, gave '$($gone.Process.ExitCode)'" }
		Write-Host 'ok: a process that ends at once keeps its exit code, which is read after it ended'

		$standIn = Join-Path $work 'standin-ranz.ps1'
		$standInCall = @('-NoProfile', '-NonInteractive', '-File', $standIn)
		$quick = Get-RanzVersionLine $pwshPath @($standInCall + 'quick') 30
		if ($quick.Code -ne 0 -or $quick.Line -ne 'ranz 9.9.9') { throw "a ranz.exe that ends gave the exit code $($quick.Code) and the line '$($quick.Line)'" }
		$goneVersion = Get-RanzVersionLine $pwshPath @($standInCall + 'gone') 30
		if ($goneVersion.Code -ne 42 -or $goneVersion.Line -ne '') { throw "a ranz.exe version that ends at once with the exit code 42 and no line gave the exit code '$($goneVersion.Code)' and the line '$($goneVersion.Line)'" }
		Write-Host 'ok: a ranz.exe version that ends at once keeps its exit code 42, and prints no line'
		$r = Invoke-Captured { [void](Get-RanzVersionLine $pwshPath $standInCall 3) }
		if (-not $r.Thrown) { throw 'a ranz.exe version that never ends was waited for, and the wait did not fail' }
		if ($r.Seconds -lt 3 -or $r.Seconds -gt 3 + 30) { throw "the call of a ranz.exe version that never ends failed after $([int] $r.Seconds) s, not within its bound of 3 s: $($r.Thrown)" }
		if ($r.Thrown -notlike 'ranz.exe version did not end within 3 s. Ended: *(process *, the call)*. Not ended: nothing.') { throw "the failure of a ranz.exe version that never ends is '$($r.Thrown)'" }
		foreach ($want in @("service ${nodeService}: ", 'the processes of the product')) {
			if (-not $r.Output.Contains($want)) { throw "the evidence of a ranz.exe version that never ends has no '$want':`n$($r.Output)" }
		}
		if (-not ($r.Thrown -match 'process (\d+), the call')) { throw "the failure of a ranz.exe version that never ends names no process: $($r.Thrown)" }
		$callId = [int] $Matches[1]
		if (Test-ProcessAlive $callId) { throw "a ranz.exe version that never ends is still there after the failure: process $callId" }
		if (-not $r.Output.Contains("  process $callId ")) { throw "the processes in the evidence of a ranz.exe version that never ends do not hold process $callId, the call:`n$($r.Output)" }
		Write-Host "ok: a ranz.exe version that never ends fails within its bound (3 s, after $([int] $r.Seconds) s), ends the call, and prints the state of the service and the processes"
	} finally {
		$script:waitSeconds = 60
	}
}

# The limits of the two queries that the diagnostics of a failed step ask, each on a planted stall (CI-FLAKE-6-R2, #624): a CIM query that
# never answers, and a query of the events that sleeps for 120 s. A function in front of Get-CimInstance stands in for the provider, on
# Windows too, and only inside the block that tests it: it gives up when its time limit is reached, as the cmdlet does, and with no
# limit it sleeps for 120 s, so a query that is asked with none returns after that, and the check fails on it.
function Invoke-SelfTestQueries {
	$script:cimSeconds = 2
	$script:eventsSeconds = 5
	$script:eventsStall = 120
	try {
		$r = Invoke-Captured {
			function Get-CimInstance {
				[CmdletBinding()]
				param([string] $ClassName, [string] $Filter, [int] $OperationTimeoutSec = 0)
				$wait = if ($OperationTimeoutSec -gt 0) { $OperationTimeoutSec } else { 120 }
				Start-Sleep -Seconds $wait
				throw "the CIM query of $ClassName did not answer within $wait s"
			}
			[void](Get-ServiceDetails 'msiserver')
		}
		if (-not $r.Thrown) { throw 'a CIM query that never answers was waited for, and Get-ServiceDetails did not fail' }
		if ($r.Seconds -lt 2 -or $r.Seconds -gt 2 + 30) { throw "Get-ServiceDetails failed after $([int] $r.Seconds) s, not at its time limit of 2 s: $($r.Thrown)" }
		if ($r.Thrown -ne 'the CIM query of Win32_Service did not answer within 2 s') { throw "the failure of a CIM query that never answers is '$($r.Thrown)', not the one of its time limit of 2 s" }
		Write-Host "ok: a CIM query that never answers fails at its time limit (2 s, after $([int] $r.Seconds) s)"

		$r = Invoke-Captured { Show-ServiceControlEvents (Get-Date) }
		if ($r.Thrown) { throw "the diagnostics failed on a query of the events that stalls: $($r.Thrown)" }
		if ($r.Seconds -lt 5 -or $r.Seconds -gt 5 + 30) { throw "the diagnostics returned after $([int] $r.Seconds) s from a query of the events that stalls, not at its bound of 5 s:`n$($r.Output)" }
		if (-not ($r.Output -match 'the events were not read within 5 s: its process (\d+) is ended')) { throw "the diagnostics do not say that the query of the events was ended at its bound of 5 s:`n$($r.Output)" }
		$queryId = [int] $Matches[1]
		$deadline = (Get-Date).AddSeconds(15)
		while ((Test-ProcessAlive $queryId) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
		if (Test-ProcessAlive $queryId) { throw "the query of the events that stalled is still there after the diagnostics: process $queryId" }
		Write-Host "ok: a stall in the query of the events of the diagnostics is ended at its bound (5 s, after $([int] $r.Seconds) s), and the diagnostics go on"

		# On Windows the same query reads the System log: nothing in it says that it could not
		if ($IsWindows) {
			$script:eventsStall = 0
			$script:eventsSeconds = 60
			$hourAgo = (Get-Date).AddHours(-1)
			$r = Invoke-Captured { Show-ServiceControlEvents $hourAgo }
			if ($r.Thrown -or $r.Output -match '(?m)^  (not read|the events)') { throw "the query of the events of the diagnostics did not read the System log: $($r.Thrown)`n$($r.Output)" }
			Write-Host 'ok: the query of the events of the diagnostics reads the System log'
		}
	} finally {
		$script:cimSeconds = 30
		$script:eventsSeconds = 20
		$script:eventsStall = 0
	}
}

# The end of a hang on planted evidence and planted services (CI-FLAKE-6-R2, #624): Stop-HungCall runs on a planted call that did not end,
# with no wait for its bound. The functions that read the service are stand-ins here on every computer, so nothing below touches the real
# service msiserver, in GitHub Actions too. The planted call is the stand-in for msiexec.exe of the planted hangs above.
function Invoke-SelfTestEnd([string] $work) {
	$pwsh = $pwshPath
	$pwshName = (Get-Process -Id $PID).ProcessName
	$realScript = $msiInstallScript
	$realName = $serviceProcessName
	$standInServices = @{}
	$standInSc = @{}
	$standInCim = $null
	$started = [System.Collections.Generic.List[int]]::new()
	function Get-ServiceDetails([string] $name) {
		if ($standInCim) { throw $standInCim }
		if ($standInServices.ContainsKey($name)) { $standInServices[$name] }
	}
	function Get-ServiceProcessId([string] $name) { if ($standInSc.ContainsKey($name)) { $standInSc[$name] } }
	# A planted call that does not end: it writes its log and the ids of its two processes, and sleeps
	function Start-PlantedHang([string] $step) {
		$hangScript = Join-Path $work 'standin-msiexec.ps1'
		$log = Join-Path $work "$step.log"
		$call = Start-ProcessWithHandle $pwsh @('-NoProfile', '-NonInteractive', '-File', $hangScript, '/i', (Join-Path $work 'hang.msi'), '/qn', '/norestart', '/l*v!', $log)
		if (-not (Wait-File "$log.pids" 60)) { throw "the planted call of the step $step wrote no process ids within 60 s" }
		return [pscustomobject]@{ Process = $call.Process; Log = $log; Ids = @(Read-Pids "$log.pids") }
	}
	# The end of a planted call: the message of the failure, and the ids of the processes of the call
	function Invoke-PlantedEnd([string] $step) {
		$hang = Start-PlantedHang $step
		$message = Stop-HungCall $hang.Process 'msiexec /i hang.msi' $step $hang.Log
		return [pscustomobject]@{ Message = $message; Ids = $hang.Ids }
	}
	function Assert-Gone([int[]] $ids, [string] $what) {
		$deadline = (Get-Date).AddSeconds(15)
		while (@($ids | Where-Object { Test-ProcessAlive $_ }).Count -gt 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
		$alive = @($ids | Where-Object { Test-ProcessAlive $_ })
		if ($alive.Count -gt 0) { throw "$what is still there after the end of the hang: process $($alive -join ', ')" }
	}
	try {
		# An evidence process that cannot be started: the failure says what happened, and names no bound, as none was reached
		$script:pwshPath = Join-Path $work 'no-such-program'
		try { $r = Invoke-PlantedEnd 'planted-no-start' } finally { $script:pwshPath = $pwsh }
		Assert-Gone $r.Ids 'the planted call whose evidence could not be started'
		if ($r.Message -notlike '*Evidence: none was collected (it could not be collected: *') { throw "the failure of a call whose evidence process could not be started does not say what happened: $($r.Message)" }
		if ($r.Message -like '*stopped at its bound*') { throw "the failure of a call whose evidence process could not be started names a bound that was never reached: $($r.Message)" }
		Write-Host 'ok: an evidence process that cannot be started is a failure that says so, and names no bound'

		# An evidence process that ends at once with an exit code: the code is kept, and no bound is named either
		$exitScript = Join-Path $work 'standin-evidence.ps1'
		Set-Content -LiteralPath $exitScript -Value 'exit 7'
		$script:msiInstallScript = $exitScript
		try { $r = Invoke-PlantedEnd 'planted-evidence-exit' } finally { $script:msiInstallScript = $realScript }
		Assert-Gone $r.Ids 'the planted call whose evidence process exited at once'
		if ($r.Message -notlike '*Evidence: none was collected (its process exited with the code 7)*') { throw "the failure of a call whose evidence process exited at once with the code 7 does not say so: $($r.Message)" }
		if ($r.Message -like '*stopped at its bound*') { throw "the failure of a call whose evidence process exited at once names a bound that was never reached: $($r.Message)" }
		Write-Host 'ok: an evidence process that ends at once keeps its exit code, and the failure names no bound'

		# A process id that another process has reused: the service ended, and its id is a process that is not the service's. CIM and
		# sc.exe queryex are stand-ins that still give that id for the service, as they would before the service ended, so the name of
		# the process is what refuses
		$bystander = Start-Process -FilePath $pwsh -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 120') -PassThru
		$started.Add($bystander.Id)
		$standInServices['msiserver'] = [pscustomobject]@{ State = 'Running'; ProcessId = $bystander.Id; StartMode = 'Manual'; Status = 'OK'; ExitCode = 0 }
		$standInSc['msiserver'] = $bystander.Id
		$script:serviceProcessName = 'msiexec'
		try { $r = Invoke-PlantedEnd 'planted-reused-id' } finally { $script:serviceProcessName = $realName }
		Assert-Gone $r.Ids 'the planted call whose service id was reused'
		if (-not (Test-ProcessAlive $bystander.Id)) { throw "process $($bystander.Id), which has the id that the service msiserver had and is another process, was ended" }
		if ($r.Message -match "process $($bystander.Id),") { throw "the failure lists process $($bystander.Id), which is not the service's, as ended or not ended: $($r.Message)" }
		if ($r.Message -notlike "*it was not ended: process $($bystander.Id) is $pwshName, not msiexec*") { throw "the failure does not say that process $($bystander.Id), which is $pwshName and not msiexec, was not ended: $($r.Message)" }
		Write-Host 'ok: a process whose id was the service msiserver and is another process now is not ended, and the failure says so'

		# The service has another process or none now by the Service Control Manager, while CIM, read before, still gives the old one: the old
		# process has the name of the service's, and only the Service Control Manager refuses
		$moved = Start-StandInService $work 'planted-service-moved'
		foreach ($id in $moved.ProcessIds) { $started.Add($id) }
		$standInServices['msiserver'] = $moved.Details
		$standInSc['msiserver'] = 0
		$script:serviceProcessName = $pwshName
		try { $r = Invoke-PlantedEnd 'planted-service-moved-on' } finally { $script:serviceProcessName = $realName }
		Assert-Gone $r.Ids 'the planted call whose service moved on'
		if (-not (Test-ProcessAlive $moved.ProcessIds[0])) { throw "process $($moved.ProcessIds[0]), which the Service Control Manager no longer gives for the service msiserver, was ended" }
		if ($r.Message -notlike '*it was not ended: the Service Control Manager says that the service msiserver has no process now*') { throw "the failure does not say that the Service Control Manager has no process for the service: $($r.Message)" }
		Write-Host 'ok: a process that the Service Control Manager no longer gives for the service msiserver is not ended, and the failure says so'

		# CIM does not answer and sc.exe queryex does: the service is ended all the same, which it was not when only CIM gave its process
		$stuck = Start-StandInService $work 'planted-service-cim'
		foreach ($id in $stuck.ProcessIds) { $started.Add($id) }
		$standInCim = 'planted: the CIM query did not answer within 30 s'
		$standInSc['msiserver'] = $stuck.ProcessIds[0]
		$script:serviceProcessName = $pwshName
		try { $r = Invoke-PlantedEnd 'planted-cim-stuck' } finally { $script:serviceProcessName = $realName; $standInCim = $null }
		Assert-Gone ($r.Ids + $stuck.ProcessIds) 'the planted call, or the service that only sc.exe queryex gave,'
		if ($r.Message -notlike '*The service msiserver was not read (planted: the CIM query did not answer within 30 s), and sc.exe queryex gives process *') { throw "the failure does not say that CIM did not answer and sc.exe queryex gave the process: $($r.Message)" }
		foreach ($id in $stuck.ProcessIds) {
			if ($r.Message -notmatch "process $id,") { throw "the failure does not list process $id, which it ended, as ended: $($r.Message)" }
		}
		Write-Host 'ok: the service msiserver is ended when CIM does not answer and sc.exe queryex gives its process, and the failure says so'
	} finally {
		$script:pwshPath = $pwsh
		$script:msiInstallScript = $realScript
		$script:serviceProcessName = $realName
		foreach ($id in $started) {
			try { (Get-Process -Id $id -ErrorAction Stop).Kill($true) } catch { }
		}
	}
}

# What -SelfTest runs in a process of its own: the main flow, which is Invoke-Flow with Step, on steps that hold a planted hang. A step
# that ends, the step with the call that never ends and a step after it. The flow must end with an error, after its clean-up, with the
# call in the message, and the step after the call must not run. Diagnostics and clean-up are planted: they need a computer with the product.
function Invoke-SelfTestFlow {
	$work = New-PlantedWork
	try {
		$script:LogDir = $work
		$script:msiexecSeconds = $flowBound
		Set-PlantedMsiexec $work
		function Get-ServiceDetails([string] $name) { }
		function Get-ServiceProcessId([string] $name) { }
		function Show-Diagnostics { Write-Host 'planted diagnostics ran' }
		try {
			Invoke-Flow {
				[void](Step 'a call that ends' {
					$r = Invoke-Msiexec '/i' (Join-Path $work 'refused.msi') 'flow-refused'
					if ($r.Code -ne 23) { throw "msiexec exited with code $($r.Code), not 23" }
				})
				[void](Step 'the call that never ends' {
					[void](Invoke-Msiexec '/i' (Join-Path $work 'hang.msi') 'flow-hang')
				})
				[void](Step 'a step after the call that never ends' {
					Write-Host 'planted: the step after the hang ran'
				})
			} {
				Write-Host 'planted clean-up ran'
			}
			Write-Host 'planted: the flow ended without an error'
		} catch {
			# The message that fails the job, whole, as a line of the output: the error view of PowerShell may wrap a long one, and the check
			# of the flow reads this line. The flow still fails with it, so its exit code is the one that the job sees.
			Write-Host "the flow failed with: $($_.Exception.Message)"
			throw
		}
	} finally {
		foreach ($file in @(Get-ChildItem -LiteralPath $work -Filter '*.pids' -ErrorAction SilentlyContinue)) {
			foreach ($id in @(Read-Pids $file.FullName)) {
				try { (Get-Process -Id $id -ErrorAction Stop).Kill($true) } catch { }
			}
		}
		Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
	}
}

# The modes of this script that need no package and no Windows folder run before the lines that read them
if ($EvidenceRequest) {
	Write-MsiexecEvidence $EvidenceRequest
	exit 0
}
if ($EventsRequest) {
	Write-EventLines $EventsRequest
	exit 0
}
if ($CheckLaunches) {
	$launches = @(Get-MsiexecLaunches $CheckLaunches)
	foreach ($launch in $launches) { Write-Host "  $CheckLaunches`:$launch" }
	if ($launches.Count -gt 0) {
		Write-Host "$($launches.Count) commands of $CheckLaunches start msiexec outside Invoke-Msiexec (or install without it), where a call has its bound"
		throw 'msiexec is started outside Invoke-Msiexec'
	}
	Write-Host "ok: $CheckLaunches starts msiexec in Invoke-Msiexec and nowhere else"
	exit 0
}
if ($CheckFlow) {
	# The failure is a line of the output, whole: the error view of PowerShell wraps a long message
	try {
		Test-PlantedFlow $CheckFlow
	} catch {
		Write-Host "the check of the main flow of $CheckFlow failed: $($_.Exception.Message)"
		exit 1
	}
	exit 0
}
if ($SelfTestFlow) {
	Invoke-SelfTestFlow
	exit 0
}
if ($SelfTest) {
	Invoke-SelfTest
	exit 0
}

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

# The process id of the Node service, which a restart changes
function Get-NodeProcessId {
	return [int] (Get-CimInstance Win32_Service -Filter "Name='$nodeService'").ProcessId
}

# The lines "Node started" of the node log of the data directory: one for each time the Node ran
function Get-NodeStarts {
	return @(Get-ChildItem -LiteralPath $nodeLogDir -File -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern 'Node started' -SimpleMatch).Count
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
		$r = Get-RanzVersionLine $installedRanz @() $waitSeconds
		if ($r.Code -ne 0 -or $r.Line -ne "ranz $expectedVersion") { throw "$installedRanz version printed '$($r.Line)' (exit code $($r.Code)), not 'ranz $expectedVersion', the version of the package" }
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

# What a failed step needs to be read from the log alone. It asks CIM and the event log only through Get-ServiceDetails (a time limit) and
# Show-ServiceControlEvents (a process of its own with a bound): a query with no limit would hold the diagnostics and the job with them
# (CI-FLAKE-6-R2, #624), and quality-gates-test.py fails when this function holds a query of its own.
function Show-Diagnostics {
	foreach ($name in @($nodeService, $controllerService)) {
		$svc = $null
		try {
			$svc = Get-ServiceDetails $name
		} catch {
			Write-Host "service ${name}: not read ($($_.Exception.Message))"
			continue
		}
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
		Show-ServiceControlEvents $since
		foreach ($log in @(Get-ChildItem -LiteralPath $nodeLogDir -File -Recurse -ErrorAction SilentlyContinue)) {
			Write-Host "last lines of $($log.FullName):"
			Get-Content -LiteralPath $log.FullName -Tail 30 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $_" }
		}
	}
}

# Steps that share state: the process id of the Node, the canary, the Configuration store as it was
$state = @{}
$since = Get-Date
$script:lastLog = $null
Write-Host "this computer is $(Get-NativeArchitecture) by the registry, and the architecture of this runner is $Architecture"
if ($StandIn) { Remove-Item -LiteralPath $standInDir -Recurse -Force -ErrorAction SilentlyContinue }
Remove-InstalledState

Invoke-Flow {
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
} {
	Remove-InstalledState
}

Write-Host 'ok'

# The last native command above may have left a code that is no failure here, and the step of the job
# returns the code of the last native command
exit 0
