param([string] $BuildDir = 'build')

$ErrorActionPreference = 'Stop'

# Service events in the Windows Event Log (ticket #92). ranz-node installed and started as a Windows
# service must write "started" (event ID 1) to the Application log under its service name, and
# "stopped" (event ID 2) when it is stopped and uninstalled, with no failure entry (event ID 3).
# The event IDs are MS_EVENT_SERVICE_* in src/Mayaqua/Microsoft.h; the entries are written by
# MsServiceDispatcher and MsServiceStopProc in src/Mayaqua/Microsoft.c. The service was the slim
# fork's vpnserver until it was retired (CORE-S8-1, #84).

$exe = (Resolve-Path (Join-Path $BuildDir 'ranz-node.exe')).Path

# GC_SVC_NAME_NODE (src/GlobalConst.h), lower case as MsServiceEx registers it: the service name and the
# event source (ADR-0020 decision 4)
$service = 'ranzvpnserver'

# How long an entry may take to appear (s): the service writes "started" once the server runs
$waitSeconds = 120

$since = (Get-Date).AddSeconds(-2)

# Entries of the event source written since the step started, oldest first. The source is not
# registered, so the insertion string is read from Properties instead of Message.
function Get-ServiceEvents {
	@(Get-WinEvent -LogName Application -FilterXPath "*[System[Provider[@Name='$service']]]" -ErrorAction SilentlyContinue |
		Where-Object { $_.TimeCreated -ge $since } | Sort-Object RecordId)
}

function Wait-ServiceEvent([int] $id) {
	$end = (Get-Date).AddSeconds($waitSeconds)
	while ($true) {
		$found = @(Get-ServiceEvents | Where-Object { $_.Id -eq $id })
		if ($found.Count -gt 0) { return $found[0] }
		if ((Get-Date) -ge $end) { return $null }
		Start-Sleep -Seconds 1
	}
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

try {
	Invoke-Node '/install'
	$started = Wait-ServiceEvent 1
	if ($null -eq $started) { throw "no 'started' entry (event ID 1) of $service within $waitSeconds s of /install" }
	Write-Host "started entry: $(($started.Properties | ForEach-Object { $_.Value }) -join ' | ')"

	Invoke-Node '/uninstall'
	$stopped = Wait-ServiceEvent 2
	if ($null -eq $stopped) { throw "no 'stopped' entry (event ID 2) of $service within $waitSeconds s of /uninstall" }
	Write-Host "stopped entry: $(($stopped.Properties | ForEach-Object { $_.Value }) -join ' | ')"

	$failed = @(Get-ServiceEvents | Where-Object { $_.Id -eq 3 })
	if ($failed.Count -gt 0) { throw "$service wrote $($failed.Count) failure entries (event ID 3)" }
} catch {
	Show-Diagnostics
	throw
} finally {
	# Leave no service behind for the later steps. A service that /uninstall already deleted can
	# still be listed until its process ends; sc.exe then fails, which is not an error of this step,
	# and the exit code it leaves must not become the step's (the runner exits with $LASTEXITCODE).
	if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
		& sc.exe stop $service | Out-Null
		& sc.exe delete $service | Out-Null
		$global:LASTEXITCODE = 0
	}
}

Show-Diagnostics
Write-Host 'ok'
