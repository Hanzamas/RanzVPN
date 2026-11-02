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
	[string] $EvidenceRequest # What a call that does not end runs in a process of its own: collects the evidence that this file asks for
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
# ranz.exe version (Get-RanzVersionLine). Others stay without one: the signature, hash and access list reads, the COM queries of
# Windows Installer and the diagnostics of a failed step. Only msiexec, the Node and ranz.exe version have hung or can.
#
# -SelfTest plants a hang of each kind and checks all of that on any computer with PowerShell 7, Windows or Linux: quality-gates-test.py
# runs it on Linux, and the msi job runs it on x64 and arm64. -CheckLaunches reads a script with the parser of PowerShell and fails
# when msiexec is started anywhere but in Invoke-Msiexec: quality-gates-test.py runs it on this script and on planted faults.

# The bound of a msiexec call, in seconds. The green runs of 2026-10-31 (five of each architecture, from the pushes to integration)
# took 36 s at the most for the slowest call, the install of the previous package on x64 (23 s on arm64), and 5 s at the most for
# every other call, so 300 s is more than eight times the slowest. The program that a call runs and the arguments before its verb
# are msiexec.exe and none; -SelfTest puts a stand-in there.
$msiexecSeconds = 300
$msiexecFile = 'msiexec.exe'
$msiexecPrefix = @()
# The message of the call that reached its bound, once one did: Step stops the run there, and no other call starts
$script:msiexecHang = $null

# The bound of the evidence of a call that does not end, in seconds. The evidence of the hangs that PR 594 ran took under 2 s, so 60 s
# is thirty times that; with the bound of the call, the end of the call and the service and the 10 s that each of them is given, the
# step stays inside its timeout of 10 minutes. $evidenceStall is the seconds that a planted stall sleeps in the query of the events.
$evidenceSeconds = 60
$evidenceStall = 0
# The bound of the wait for the Node to stop and to start, and of ranz.exe version, in seconds. The Node takes a few seconds to do
# either (the slowest step of the green runs, which also runs msiexec, took 77 s), and the wait for it to run had 60 s already.
$waitSeconds = 60
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

# Every process of this computer, one object each: the id, the parent, the name, the threads, the seconds of cpu, the start time and
# the command line. Windows asks CIM, with a time limit; another computer (the self-test on Linux) asks Get-Process and /proc.
function Get-ProcessTable {
	if ($IsWindows) {
		foreach ($p in @(Get-CimInstance Win32_Process -OperationTimeoutSec 30)) {
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
# when there is no such service. -SelfTest on Linux has no CIM, so it puts a function of this name in front of this one.
function Get-ServiceDetails([string] $name) {
	return Get-CimInstance Win32_Service -Filter "Name='$name'" -OperationTimeoutSec 30
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

# Collects the evidence of the call $callId in a process of its own, for $evidenceSeconds at the most, and prints what the file holds
# when that process is done or ended. Whatever happens here, the caller goes on to end the call. A process that has to be ended is
# a line of $ended or $notEnded. Gives the file, the number of its lines, whether the process was done in time and a note.
function Invoke-EvidenceCollection([int] $callId, [string] $log, [string] $step, $service, $serviceError, $ended, $notEnded) {
	$file = Join-Path $LogDir "$step-evidence.txt"
	$requestFile = Join-Path $LogDir "$step-evidence-request.json"
	$result = [pscustomobject]@{ File = $file; Lines = 0; Complete = $false; Note = '' }
	try {
		$rootIds = @($callId)
		# The service as plain values: the CIM object holds far more than the line of the evidence needs, and JSON would write all of it
		$plain = $null
		if ($service) {
			$plain = [pscustomobject]@{ State = [string] $service.State; ProcessId = [int] $service.ProcessId; StartMode = [string] $service.StartMode; Status = [string] $service.Status; ExitCode = [long] $service.ExitCode }
			if ($plain.ProcessId -gt 0) { $rootIds += $plain.ProcessId }
		}
		$request = [pscustomobject]@{ CallId = $callId; Log = $log; File = $file; RootIds = $rootIds; Service = $plain; ServiceError = $serviceError; StallSeconds = $evidenceStall }
		$request | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $requestFile -Encoding utf8
		$collector = Start-Process -FilePath $pwshPath -ArgumentList @('-NoProfile', '-NonInteractive', '-File', "`"$msiInstallScript`"", '-EvidenceRequest', "`"$requestFile`"") -PassThru
		# On Windows the exit code of a process that Start-Process started is read from a handle that must be taken while it runs
		if ($IsWindows) { $null = $collector.Handle }
		$result.Complete = $collector.WaitForExit($evidenceSeconds * 1000)
		if (-not $result.Complete) {
			Write-Host "the evidence was not done within $evidenceSeconds s: its process $($collector.Id) is ended, and what it had found is below"
			Stop-ProcessTree $collector.Id 'the evidence collection' $null $ended $notEnded
		} elseif ($collector.ExitCode -ne 0) {
			$result.Note = "its process exited with the code $($collector.ExitCode)"
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
# are there.
function Stop-HungCall([System.Diagnostics.Process] $call, [string] $what, [string] $step, [string] $log) {
	$ended = [System.Collections.Generic.List[string]]::new()
	$notEnded = [System.Collections.Generic.List[string]]::new()
	$notes = [System.Collections.Generic.List[string]]::new()
	# The service is read before anything ends: an install usually hangs in it, and its process is what the evidence and the end need
	$service = $null
	$serviceError = $null
	try { $service = Get-ServiceDetails 'msiserver' } catch { $serviceError = $_.Exception.Message }
	$evidence = Invoke-EvidenceCollection $call.Id $log $step $service $serviceError $ended $notEnded
	$table = @()
	try {
		$table = @(Get-ProcessTable)
	} catch {
		$notes.Add("the processes could not be listed ($($_.Exception.Message)), so the processes that the call and the service started are not named")
	}
	Stop-ProcessTree $call.Id 'the call' $table $ended $notEnded
	$serviceText = if ($serviceError) {
		"was not read ($serviceError)"
	} elseif ($null -eq $service) {
		'is not installed'
	} elseif ([int] $service.ProcessId -le 0) {
		"has no process ($($service.State))"
	} else {
		"was $($service.State) in process $($service.ProcessId)"
	}
	if ($service -and [int] $service.ProcessId -gt 0) { Stop-ProcessTree ([int] $service.ProcessId) 'the service msiserver' $table $ended $notEnded }
	$endedText = if ($ended.Count -gt 0) { $ended -join ', ' } else { 'nothing' }
	$notEndedText = if ($notEnded.Count -gt 0) { $notEnded -join ', ' } else { 'nothing' }
	$evidenceText = if ($evidence.Lines -gt 0) { "$($evidence.Lines) lines above and in $(Split-Path -Leaf $evidence.File)" } else { 'none was collected' }
	if (-not $evidence.Complete) { $evidenceText += ", stopped at its bound of $evidenceSeconds s" }
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
function Get-RanzVersionLine([string] $file, [string[]] $prefix, [int] $seconds) {
	$out = Join-Path $LogDir 'ranz-version.out'
	$err = Join-Path $LogDir 'ranz-version.err'
	$call = Start-Process -FilePath $file -ArgumentList @($prefix + @('version')) -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError $err
	if ($IsWindows) { $null = $call.Handle }
	if (-not $call.WaitForExit($seconds * 1000)) {
		Write-Host "ranz.exe version did not end within $seconds s (process $($call.Id)). What the computer shows:"
		try {
			foreach ($line in @(Get-WaitEvidence $nodeService @($call.Id))) { Write-Host $line }
		} catch {
			Write-Host "the evidence stopped: $($_.Exception.Message)"
		}
		$ended = [System.Collections.Generic.List[string]]::new()
		$notEnded = [System.Collections.Generic.List[string]]::new()
		Stop-ProcessTree $call.Id 'the call' $null $ended $notEnded
		$endedText = if ($ended.Count -gt 0) { $ended -join ', ' } else { 'nothing' }
		$notEndedText = if ($notEnded.Count -gt 0) { $notEnded -join ', ' } else { 'nothing' }
		throw "ranz.exe version did not end within $seconds s. Ended: $endedText. Not ended: $notEndedText."
	}
	return [pscustomobject]@{ Code = $call.ExitCode; Line = (Read-MsiLog $out).Trim() }
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
# itself (by name or by path), or when it starts a program (Start-Process, the call operator & or ., cmd, Invoke-Expression) or a
# Process (its Start) and names msiexec in its text, which holds the variables $msiexecFile and $msiexecPrefix too. A program that is
# named by another variable is not seen: the check is for the way that the hang of #593 came, an unbounded Start-Process.
function Get-MsiexecLaunches([string] $path) {
	$tokens = $null
	$errors = $null
	$ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref] $tokens, [ref] $errors)
	if ($errors.Count -gt 0) { throw "$path does not parse: line $($errors[0].Extent.StartLineNumber): $($errors[0].Message)" }
	$allowed = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-Msiexec' }, $true)
	if ($null -eq $allowed) { throw "$path has no function Invoke-Msiexec" }
	$starters = @('start-process', 'start', 'saps', 'invoke-expression', 'iex', 'invoke-command', 'icm', 'cmd', 'cmd.exe')
	$nodes = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -or $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)
	foreach ($node in $nodes) {
		if ($node.Extent.StartOffset -ge $allowed.Extent.StartOffset -and $node.Extent.EndOffset -le $allowed.Extent.EndOffset) { continue }
		$text = $node.Extent.Text
		$starts = $false
		if ($node -is [System.Management.Automation.Language.CommandAst]) {
			$name = $node.GetCommandName()
			$operator = $node.InvocationOperator -ne [System.Management.Automation.Language.TokenKind]::Unknown
			if ($name -and $name -match '(^|[\\/])msiexec(\.exe)?$') {
				$starts = $true
			} elseif ($text -match 'msiexec' -and ($operator -or ($name -and $starters -contains $name.ToLowerInvariant()))) {
				$starts = $true
			}
		} elseif ($text -match 'msiexec' -and @('Start', 'new') -contains $node.Member.Extent.Text) {
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
# A stand-in for ranz.exe (the self-test of msi-install.ps1): "quick version" prints the line of ranz.exe version at once, any other call hangs
if ($args[0] -eq 'quick') { 'ranz 9.9.9'; exit 0 }
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

function Invoke-SelfTest {
	$bound = 15
	if (-not $msiInstallScript -or -not (Test-Path -LiteralPath $msiInstallScript)) { throw "this script does not know its own path ('$msiInstallScript'), which the process that collects the evidence and the planted flow need" }
	$work = New-PlantedWork
	$script:LogDir = $work
	try {
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

		# Linux has no Windows Installer service: a process stands in for it, and a function hides the CIM query for everything below
		$standInServices = @{}
		$service = $null
		if (-not $IsWindows) {
			function Get-ServiceDetails([string] $name) { if ($standInServices.ContainsKey($name)) { $standInServices[$name] } }
			$service = Start-StandInService $work 'planted-service-1'
			$standInServices['msiserver'] = $service.Details
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
		if (-not $IsWindows) { $tree += $service.ProcessIds }
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
		# The stand-ins of Linux are all ended; the real service of Windows may refuse to end, and the failure then says so
		if (-not $IsWindows -and $notEndedText -ne 'nothing') { throw "the failure lists processes as not ended, and all of them are gone: $notEndedText" }
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
		# Windows has the event log and the real service: the event of the real call that was planted (id 1040 of not-there.msi), and the
		# state of the service as it is. If it ran, the real service is in the message as ended or not ended; if it did not, the message says so.
		if ($IsWindows) {
			$want.EventPattern = $eventPattern
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
		if (-not $IsWindows) {
			$service2 = Start-StandInService $work 'planted-service-2'
			$standInServices['msiserver'] = $service2.Details
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
		if (-not $IsWindows) { $tree2 += $service2.ProcessIds }
		$deadline = (Get-Date).AddSeconds(15)
		while (@($tree2 | Where-Object { Test-ProcessAlive ([int] $_) }).Count -gt 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
		$alive = @($tree2 | Where-Object { Test-ProcessAlive ([int] $_) })
		if ($ids2.Count -ne 2 -or $alive.Count -gt 0) { throw "after the stall the call (process ids '$($ids2 -join ' ')') or the stand-in for the service is still there: process $($alive -join ', ')" }
		$parts2 = Split-Evidence (Read-MsiLog (Join-Path $work 'planted-stall-evidence.txt'))
		if ($null -eq $parts2.Processes -or $null -ne $parts2.Events) { throw 'the evidence of the call whose collection stalled does not hold the parts before the stall and none after it' }
		Write-Host "ok: a stall in the evidence still ends the call and its processes and fails the step within its bound ($bound s and the $stallBound s of the evidence, after $([int] $seconds) s), and the failure names the bound"
		$script:msiexecHang = $null

		Invoke-SelfTestWaits $work

		# The main flow on a planted hang, in a process of its own: the exit code, the message and the clean-up are what the job sees
		$flow = Start-Process -FilePath $pwshPath -ArgumentList @('-NoProfile', '-NonInteractive', '-File', "`"$msiInstallScript`"", '-SelfTestFlow') -PassThru -RedirectStandardOutput (Join-Path $work 'flow.out') -RedirectStandardError (Join-Path $work 'flow.err')
		if ($IsWindows) { $null = $flow.Handle }
		if (-not $flow.WaitForExit(180000)) {
			$flow.Kill($true)
			throw 'the main flow on a planted hang did not end within 180 s'
		}
		$text = (Read-MsiLog (Join-Path $work 'flow.out')) + (Read-MsiLog (Join-Path $work 'flow.err'))
		if ($flow.ExitCode -eq 0) { throw "the main flow on a planted hang exited with the code 0, as if nothing had failed:`n$text" }
		foreach ($want in @("msiexec /i hang.msi did not end within $flowBound s", '1 steps failed:', "the run stops after 'the call that never ends'", 'planted clean-up ran')) {
			if (-not $text.Contains($want)) { throw "the output of the main flow on a planted hang has no '$want':`n$text" }
		}
		if ($text.Contains('planted: the step after the hang ran')) { throw "the main flow ran a step after the call that did not end:`n$text" }
		if ($text.Contains('planted: the flow ended without an error')) { throw "the main flow on a planted hang ended without an error:`n$text" }
		Write-Host "ok: the main flow on a planted hang exits with the code $($flow.ExitCode), with the call in its message, after its clean-up, and runs no step after the call"
	} finally {
		$script:evidenceSeconds = 60
		$script:evidenceStall = 0
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

		$standIn = Join-Path $work 'standin-ranz.ps1'
		$quick = Get-RanzVersionLine $pwshPath @('-NoProfile', '-NonInteractive', '-File', "`"$standIn`"", 'quick') 30
		if ($quick.Code -ne 0 -or $quick.Line -ne 'ranz 9.9.9') { throw "a ranz.exe that ends gave the exit code $($quick.Code) and the line '$($quick.Line)'" }
		$r = Invoke-Captured { [void](Get-RanzVersionLine $pwshPath @('-NoProfile', '-NonInteractive', '-File', "`"$standIn`"") 3) }
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
		function Show-Diagnostics { Write-Host 'planted diagnostics ran' }
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
if ($CheckLaunches) {
	$launches = @(Get-MsiexecLaunches $CheckLaunches)
	foreach ($launch in $launches) { Write-Host "  $CheckLaunches`:$launch" }
	if ($launches.Count -gt 0) {
		Write-Host "$($launches.Count) commands of $CheckLaunches start msiexec outside Invoke-Msiexec, where a call has its bound"
		throw 'msiexec is started outside Invoke-Msiexec'
	}
	Write-Host "ok: $CheckLaunches starts msiexec in Invoke-Msiexec and nowhere else"
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
