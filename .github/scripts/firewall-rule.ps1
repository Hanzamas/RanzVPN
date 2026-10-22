param([string] $BuildDir = 'build')

$ErrorActionPreference = 'Stop'

# The Windows Firewall rule of vpnserver /install and /uninstall (ticket #47), checked against the
# rules that Windows Firewall reports. vpnserver.exe, vpncmd.exe and vpntest.exe are zipped and
# unzipped into a folder of their own, as a release zip is used, and vpnserver runs from there:
#   1. /install adds exactly one rule, the inbound allow rule "Ranz VPN Server" for the unzipped
#      vpnserver.exe: enabled, all profiles, all protocols, ports and addresses. No other rule is
#      added or changed, and no rule names vpncmd.exe or vpntest.exe.
#   2. A restart of the service, which starts the server again, adds, deletes or changes no rule.
#   3. /uninstall deletes the rule: the rules are those of before /install again.
#   4. vpnserver starts no cscript.exe or wscript.exe (process creation events, ID 4688 of the
#      Security log), and the registry key of the old VBScript hash guard does not exist.
# MsAddFirewallRule and MsDeleteFirewallRule (src/Mayaqua/MicrosoftFirewall.c) add and delete the
# rule; MsService (src/Mayaqua/Microsoft.c) calls them for /install and /uninstall.

# CEDAR_SERVER_STR (src/GlobalConst.h): the name of the rule
$ruleName = 'Ranz VPN Server'

# SOFTETHER_FW_SCRIPT_HASH of the removed VBScript path: "Software\" GC_REG_COMPANY_NAME "\PacketiX VPN\FW ScriptHash"
$hashKey = 'HKLM:\Software\Hanzcodes\Ranz VPN\PacketiX VPN\FW ScriptHash'

# The Process Creation subcategory of the audit policy, by GUID so that the name's language does not matter
$auditProcessCreation = '{0CCE922B-69AE-11D9-BED3-505054503030}'

# How long an entry may take to appear (s): the service writes "started" once the server runs
$waitSeconds = 120

# How long the server runs before the rules are read (s), so that a rule it added after its start
# would be there
$settleSeconds = 10

$root = Join-Path $env:RUNNER_TEMP 'firewall-rule'
if (Test-Path $root) { Remove-Item -Recurse -Force $root }
New-Item -ItemType Directory -Force -Path $root | Out-Null
$zip = Join-Path $root 'ranz-vpn.zip'
$dir = Join-Path $root 'Ranz VPN'

$files = @('vpnserver.exe', 'vpncmd.exe', 'vpntest.exe') | ForEach-Object { (Resolve-Path (Join-Path $BuildDir $_)).Path }
Compress-Archive -Path $files -DestinationPath $zip
Expand-Archive -Path $zip -DestinationPath $dir
$exe = (Resolve-Path (Join-Path $dir 'vpnserver.exe')).Path
$others = @('vpncmd.exe', 'vpntest.exe') | ForEach-Object { (Resolve-Path (Join-Path $dir $_)).Path }
Write-Host "unzipped to $dir"

$since = (Get-Date).AddSeconds(-2)
$service = $null

# Every rule of the local store as one line, sorted: a rule added, deleted or changed changes a line
function Get-RuleLines {
	@(Get-NetFirewallRule | ForEach-Object {
			'{0} | {1} | enabled {2} | {3} | {4} | profile {5}' -f $_.Name, $_.DisplayName, $_.Enabled, $_.Direction, $_.Action, $_.Profile
		} | Sort-Object)
}

function Get-NamedRules {
	@(Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)
}

# The rules of a program. The filters go to Get-NetFirewallRule only when there are some: with no
# input, the cmdlet would list every rule.
function Get-ProgramRules([string] $program) {
	$filters = @(Get-NetFirewallApplicationFilter -All | Where-Object { $_.Program -eq $program })
	if ($filters.Count -eq 0) { return @() }
	@($filters | Get-NetFirewallRule)
}

function Assert-SameRules([string[]] $expected, [string[]] $actual, [string] $what) {
	$diff = @(Compare-Object -ReferenceObject $expected -DifferenceObject $actual)
	if ($diff.Count -gt 0) {
		$diff | ForEach-Object { Write-Host ("  {0} {1}" -f $(if ($_.SideIndicator -eq '=>') { 'added:  ' } else { 'removed:' }), $_.InputObject) }
		throw "$what changed $($diff.Count) firewall rule lines"
	}
}

# The service whose program is the unzipped vpnserver.exe: its name is also the event source
function Get-InstalledService {
	@(Get-CimInstance -ClassName Win32_Service | Where-Object {
			$_.PathName -and $_.PathName.IndexOf($exe, [StringComparison]::OrdinalIgnoreCase) -ge 0
		})
}

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

# Process creation events since the step started: the program and the program that started it
function Get-StartedProcesses {
	@(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = $since } -ErrorAction SilentlyContinue | ForEach-Object {
			$data = @{}
			([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $data[$_.GetAttribute('Name')] = $_.InnerText }
			[pscustomobject]@{ Program = $data['NewProcessName']; Parent = $data['ParentProcessName'] }
		})
}

function Invoke-Vpnserver([string] $arg) {
	# vpnserver is a GUI-subsystem program: Start-Process -Wait waits for it to exit
	Write-Host "vpnserver $arg"
	$p = Start-Process -FilePath $exe -ArgumentList $arg -Wait -PassThru
	Write-Host "vpnserver $arg exited with code $($p.ExitCode)"
}

function Show-Diagnostics {
	Write-Host "rules named ${ruleName}:"
	Get-NamedRules | ForEach-Object {
		$app = $_ | Get-NetFirewallApplicationFilter
		$port = $_ | Get-NetFirewallPortFilter
		Write-Host ("  {0}: enabled {1}, {2}, {3}, profile {4}, program {5}, protocol {6}, local port {7}, remote port {8}" -f
			$_.Name, $_.Enabled, $_.Direction, $_.Action, $_.Profile, $app.Program, $port.Protocol, $port.LocalPort, $port.RemotePort)
	}
	Write-Host 'processes that vpnserver started:'
	Get-StartedProcesses | Where-Object { $_.Parent -eq $exe } | ForEach-Object { Write-Host "  $($_.Program)" }
	if ($service) {
		Get-Service -Name $service -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "service ${service}: $($_.Status)" }
	}
	$log = Get-ChildItem -Path (Join-Path $dir 'server_log') -Filter '*.log' -ErrorAction SilentlyContinue |
		Sort-Object LastWriteTime | Select-Object -Last 1
	if ($log) {
		Write-Host "last lines of $($log.FullName):"
		Get-Content -Path $log.FullName -Tail 40 | ForEach-Object { Write-Host "  $_" }
	}
}

& auditpol.exe /set "/subcategory:$auditProcessCreation" /success:enable
if ($LASTEXITCODE -ne 0) { throw "auditpol could not turn on the audit of process creation (exit code $LASTEXITCODE)" }

try {
	if ((Get-NamedRules).Count -ne 0) { throw "a rule named $ruleName is there before /install" }
	$before = Get-RuleLines
	Write-Host "$($before.Count) firewall rules before /install"

	# 1. /install
	Invoke-Vpnserver '/install'
	$service = @(Get-InstalledService | ForEach-Object { $_.Name })[0]
	if (-not $service) { throw "/install registered no service for $exe" }
	Write-Host "service: $service"
	$started = Wait-ServiceEvent 1
	if ($null -eq $started) { throw "no 'started' entry (event ID 1) of $service within $waitSeconds s of /install" }
	Start-Sleep -Seconds $settleSeconds

	$named = Get-NamedRules
	if ($named.Count -ne 1) { throw "$($named.Count) rules named $ruleName after /install, not 1" }
	$rule = $named[0]
	$app = $rule | Get-NetFirewallApplicationFilter
	$port = $rule | Get-NetFirewallPortFilter
	$address = $rule | Get-NetFirewallAddressFilter
	$wrong = @()
	if ("$($rule.Direction)" -ne 'Inbound') { $wrong += "direction $($rule.Direction)" }
	if ("$($rule.Action)" -ne 'Allow') { $wrong += "action $($rule.Action)" }
	if ("$($rule.Enabled)" -ne 'True') { $wrong += "enabled $($rule.Enabled)" }
	if ("$($rule.Profile)" -ne 'Any' -and "$($rule.Profile)" -ne 'Domain, Private, Public') { $wrong += "profile $($rule.Profile)" }
	if ($app.Program -ne $exe) { $wrong += "program $($app.Program)" }
	if ("$($port.Protocol)" -ne 'Any') { $wrong += "protocol $($port.Protocol)" }
	if ("$($port.LocalPort)" -ne 'Any') { $wrong += "local port $($port.LocalPort)" }
	if ("$($port.RemotePort)" -ne 'Any') { $wrong += "remote port $($port.RemotePort)" }
	if ("$($address.LocalAddress)" -ne 'Any') { $wrong += "local address $($address.LocalAddress)" }
	if ("$($address.RemoteAddress)" -ne 'Any') { $wrong += "remote address $($address.RemoteAddress)" }
	if ($wrong.Count -gt 0) { throw "the rule $ruleName is not an inbound allow rule for $exe on everything: $($wrong -join ', ')" }
	Write-Host "rule ${ruleName}: inbound, allow, enabled, profile $($rule.Profile), program $($app.Program), protocol, ports and addresses Any"

	$installed = Get-RuleLines
	$added = @(Compare-Object -ReferenceObject $before -DifferenceObject $installed | Where-Object { $_.SideIndicator -eq '=>' })
	Assert-SameRules $before @($installed | Where-Object { -not $_.StartsWith("$($rule.Name) | ") }) '/install, apart from its rule,'
	if ($added.Count -ne 1) { throw "/install added $($added.Count) rules, not 1" }

	foreach ($other in $others) {
		$rules = @(Get-ProgramRules $other)
		if ($rules.Count -ne 0) { throw "$($rules.Count) rules for $other" }
	}
	Write-Host "no rule for $($others -join ' or ')"

	# 2. The server starts again
	Write-Host "restarting the service $service"
	Restart-Service -Name $service -Force
	$restarted = Wait-ServiceEvent 1 $started.RecordId
	if ($null -eq $restarted) { throw "no 'started' entry (event ID 1) of $service within $waitSeconds s of the restart" }
	Start-Sleep -Seconds $settleSeconds
	Assert-SameRules $installed (Get-RuleLines) 'the server start'
	Write-Host 'the server start added, deleted or changed no firewall rule'

	# 3. /uninstall
	Invoke-Vpnserver '/uninstall'
	$stopped = Wait-ServiceEvent 2 $restarted.RecordId
	if ($null -eq $stopped) { throw "no 'stopped' entry (event ID 2) of $service within $waitSeconds s of /uninstall" }
	$named = Get-NamedRules
	if ($named.Count -ne 0) { throw "$($named.Count) rules named $ruleName after /uninstall" }
	Assert-SameRules $before (Get-RuleLines) '/install and /uninstall'
	Write-Host "/uninstall deleted the rule $ruleName; the rules are those of before /install"

	# 4. No VBScript
	$processes = Get-StartedProcesses
	if (@($processes | Where-Object { $_.Program -eq $exe }).Count -eq 0) { throw "the Security log has no process creation event of $exe: the audit is not on" }
	$scripts = @($processes | Where-Object { $_.Parent -eq $exe -and (Split-Path -Leaf $_.Program) -in @('cscript.exe', 'wscript.exe') })
	if ($scripts.Count -gt 0) { throw "vpnserver started $($scripts.Count) script hosts: $(($scripts | ForEach-Object { $_.Program }) -join ', ')" }
	if (Test-Path $hashKey) { throw "the registry key $hashKey of the VBScript hash guard exists" }
	Write-Host "vpnserver started no cscript.exe or wscript.exe, and $hashKey does not exist"

	# The sources of the server name no VBScript, script host or hash guard any more
	$sources = Get-ChildItem -Path 'src/Mayaqua', 'src/Cedar', 'src/vpnserver' -Include '*.c', '*.h' -Recurse |
		Where-Object { $_.FullName -notmatch '[\\/]3rdparty[\\/]' }
	$hits = @($sources | Select-String -Pattern 'cscript', 'wscript', '\.vbs\b', 'winfire_', 'FW ScriptHash', 'SOFTETHER_FW_SCRIPT_HASH', 'RegistWindowsFirewall')
	if ($hits.Count -gt 0) {
		$hits | ForEach-Object { Write-Host "  $($_.Path):$($_.LineNumber): $($_.Line.Trim())" }
		throw "$($hits.Count) lines of the server sources still name the VBScript firewall path"
	}
	Write-Host 'the server sources name no VBScript firewall path'
} catch {
	Show-Diagnostics
	throw
} finally {
	# Leave no service and no rule behind for the later steps. sc.exe fails for a service that
	# /uninstall already deleted, which is not an error of this step, and the exit code it leaves
	# must not become the step's (the runner exits with $LASTEXITCODE).
	if ($service -and (Get-Service -Name $service -ErrorAction SilentlyContinue)) {
		& sc.exe stop $service | Out-Null
		& sc.exe delete $service | Out-Null
	}
	# By name, not through a pipeline: Remove-NetFirewallRule with no input would delete every rule
	Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
	& auditpol.exe /set "/subcategory:$auditProcessCreation" /success:disable | Out-Null
	$global:LASTEXITCODE = 0
}

Write-Host 'ok'
