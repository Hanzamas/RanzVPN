param(
	# The signed ranz.exe of this architecture (the artifact ranz-<arch> of sign_and_integrity), which ranz install copies
	[string] $Ranz,
	# The self-signed certificate that signed it (the artifact ci-signing-certificate)
	[string] $Certificate,
	# The folder of the artifact Binaries-<arch>: vpntest.exe and the other test programs
	[string] $Binaries,
	# The architecture of this runner, x64 or arm64
	[ValidateSet('x64', 'arm64')]
	[string] $Architecture = 'x64',
	# The runbook that this script follows
	[string] $Document = 'docs\first-test.md',
	# Read the runbook, check it against this script and print its steps, and touch nothing on the machine
	[switch] $ListOnly
)

$ErrorActionPreference = 'Stop'
# Native exit codes are checked by hand below
$PSNativeCommandUseErrorActionPreference = $false

# The first test of the product on two PCs (docs/first-test.md), run on one runner that plays both PCs. The runbook is
# the script: its steps are marked in it (<!-- step: id pc=a|b|both -->, <!-- gap: id -->), and this script runs them
# in that order, each with the commands of the code blocks of the step:
# - a block "powershell run" is run line by line, in this PowerShell, after the values in angle brackets (<PC-A>,
#   <FINGERPRINT>, ...) are filled in from what the script measured. A line that exits with an error fails the step;
# - a block "powershell background" is started and left running until the script stops it;
# - the checks of a step read what the text of the step says that a person sees: the services, the files, the JSON of
#   the API, the pages of the web UI, the audit log, the adapter and the ping.
# The steps of this script and of the document must be the same, in the same order: the script reads its own Step and Gap
# lines and compares them with the markers of the document before it touches the machine, and each Step checks again
# that it is the next one. A Gap step also checks that the thing that is missing is still missing in the sources, so that
# a gap that someone closes turns the job red until the runbook has real steps for it.
# PC A and PC B are windows of one machine: the RANZ_* variables are kept for each, and the script switches them when the
# PC of the step changes. <PC-A> is the address of the runner that is not loopback, so that PC B reaches the Controller
# through the network, with the fingerprint, as a second PC does. The Nodes are the stand-in (vpntest firsttest) until
# step 20, where the one Node service of the runner joins the Controller as pc-a in place of the stand-in for that Node
# (SDN-90); the stand-in keeps playing pc-b, since two Node services cannot form a session yet (Gap 3 of the document).

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$x64 = ($Architecture -eq 'x64')

# The folders of the runbook (step 1) and the places of the product that it names
$work = 'C:\ranz-test'
$ranzDir = Join-Path $work 'ranz'
$certDir = Join-Path $work 'cert'
$binDir = Join-Path $work 'bin'
$ranzExe = Join-Path $ranzDir 'ranz.exe'
$installDir = Join-Path $env:ProgramFiles 'Ranz VPN'
$controllerData = Join-Path $env:ProgramData 'Ranz\controller'
$nodeData = Join-Path $env:ProgramData 'Hanzcodes\Ranz VPN'
$adminToken = Join-Path $controllerData 'admin.token'
$viewerToken = Join-Path $work 'viewer.token'
$readyFile = Join-Path $work 'ready'
$stopFile = Join-Path $work 'stop'
$nodeService = 'ranzvpnserver'
$controllerService = 'ranz-controller'
$adapterName = 'Ranz default'
# The group of the rules that ranz install makes in Windows Firewall (SDN-91), and the rules of the Node and the Controller:
# protocol, ports and program
$firewallGroup = 'Ranz VPN'
$nodeRules = @("TCP 443 $installDir\ranz-node.exe", "UDP 443 $installDir\ranz-node.exe")
$controllerRules = @("TCP 443,5555 $installDir\ranz.exe")
# The two Nodes of the stand-in and the addresses that the Controller gives them: the lowest free host addresses of the
# pool, in the order of their names (ADR-0028)
$nodeA = 'pc-a'
$nodeB = 'pc-b'
$addressA = '100.64.0.1'
$addressB = '100.64.0.2'

# The values in angle brackets that the commands of the document name, with what the script knows of them so far
$values = [ordered]@{ 'PC-A' = $null; 'PORT' = $null; 'CONTROLLER' = $null; 'FINGERPRINT' = $null; 'CONTROLLER-KEY' = $null; 'VIEWER-TOKEN' = $null; 'PC-A-OVERLAY' = $null; 'NODE-KEY' = $null }

#
# The document
#

$text = Get-Content -Raw -LiteralPath (Join-Path $repo $Document)
$markerPattern = '(?m)^<!-- (step|gap): ([a-z0-9-]+)(?: pc=(a|b|both))? -->[ \t]*\r?$'
$blockPattern = '(?ms)^```powershell (run|background)[ \t]*\r?\n(.*?)^```[ \t]*\r?$'

# The steps of the document in order: kind, id, the PC, the text up to the next marker or heading, and its blocks
$docSteps = @()
$found = [regex]::Matches($text, $markerPattern)
foreach ($m in $found) {
	$rest = $text.Substring($m.Index + $m.Length)
	$end = [regex]::Match($rest, '(?m)^<!-- (?:step|gap): |^#{1,3} \S')
	$body = $(if ($end.Success) { $rest.Substring(0, $end.Index) } else { $rest })
	$blocks = @()
	foreach ($b in [regex]::Matches($body, $blockPattern)) {
		$blocks += [pscustomobject]@{ Kind = $b.Groups[1].Value; Lines = @($b.Groups[2].Value -split '\r?\n' | Where-Object { $_.Trim() -ne '' }) }
	}
	$docSteps += [pscustomobject]@{ Kind = $m.Groups[1].Value; Id = $m.Groups[2].Value; Pc = $m.Groups[3].Value; Body = $body; Blocks = $blocks }
}
if ($docSteps.Count -eq 0) { throw "$Document has no step marker" }

# What a marker or a block of the document may be
$duplicates = @($docSteps | Group-Object Id | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
if ($duplicates.Count -gt 0) { throw "$Document has the step id $($duplicates -join ', ') twice" }
foreach ($s in $docSteps) {
	if ($s.Kind -eq 'step' -and -not $s.Pc) { throw "the step $($s.Id) of $Document names no PC: <!-- step: $($s.Id) pc=a|b|both -->" }
	foreach ($b in $s.Blocks) {
		if ($b.Kind -eq 'background' -and $b.Lines.Count -ne 1) { throw "a background block of the step $($s.Id) has $($b.Lines.Count) lines, not one" }
		foreach ($line in $b.Lines) {
			foreach ($p in [regex]::Matches($line, '<([A-Z][A-Z-]*)>')) {
				if (-not $values.Contains($p.Groups[1].Value)) { throw "the step $($s.Id) of $Document names the value <$($p.Groups[1].Value)>, which this script does not know: $line" }
			}
		}
	}
}

# The steps of this script, as it names them below, against the markers of the document
$own = @([regex]::Matches((Get-Content -Raw -LiteralPath $PSCommandPath), "(?m)^\s*(Step|Gap) '([a-z0-9-]+)' \{") | ForEach-Object { "$($_.Groups[1].Value.ToLower()) $($_.Groups[2].Value)" })
$theirs = @($docSteps | ForEach-Object { "$($_.Kind) $($_.Id)" })
if (($own -join ',') -ne ($theirs -join ',')) {
	throw "the steps of this script and of $Document differ:`n  script:   $($own -join ', ')`n  document: $($theirs -join ', ')"
}

if ($ListOnly) {
	foreach ($s in $docSteps) {
		Write-Host "$($s.Kind) $($s.Id) (PC $($s.Pc))"
		foreach ($b in $s.Blocks) {
			foreach ($line in $b.Lines) { Write-Host "    $($b.Kind): $line" }
		}
	}
	Write-Host "ok: $($docSteps.Count) steps"
	return
}

#
# Running the steps
#

$script:next = 0
$script:current = $null
$script:pc = 'a'
$script:background = @()
$script:windows = @{ a = @{}; b = @{} }
# The events of the admin source allowlist that the Controller holds (AUD1-DT-6): the one of its first start, and one more for
# each change that a step makes by hand
$script:allowlistEvents = 1
$windowVariables = 'RANZ_SERVER', 'RANZ_TOKEN_FILE', 'RANZ_TLS_FINGERPRINT', 'RANZ_TOKEN'

# The window of the PC: its RANZ_* variables are put away, and the ones of the other PC come back
function Enter-Pc([string] $to) {
	if ($to -eq 'both' -or $to -eq '' -or $to -eq $script:pc) { return }
	foreach ($n in $windowVariables) { $script:windows[$script:pc][$n] = [Environment]::GetEnvironmentVariable($n, 'Process') }
	foreach ($n in $windowVariables) { [Environment]::SetEnvironmentVariable($n, $script:windows[$to][$n], 'Process') }
	Write-Host "the window of PC $($to.ToUpper()) now"
	$script:pc = $to
}

# The next step of the document must be this one
function Next-Step([string] $kind, [string] $id) {
	if ($script:next -ge $docSteps.Count) { throw "the script has the $kind '$id', and the document has nothing after '$($docSteps[-1].Id)'" }
	$s = $docSteps[$script:next]
	if ($s.Kind -ne $kind -or $s.Id -ne $id) { throw "the script runs the $kind '$id', where the document has the $($s.Kind) '$($s.Id)' (number $($script:next + 1) of $($docSteps.Count))" }
	$script:next++
	$script:current = $s
	Enter-Pc $s.Pc
	return $s
}

function Step([string] $id, [scriptblock] $body) {
	$s = Next-Step 'step' $id
	Write-Host ''
	Write-Host "=== step $id (PC $($s.Pc))"
	& $body
	Write-Host "ok: $id"
}

function Gap([string] $id, [scriptblock] $body) {
	$null = Next-Step 'gap' $id
	Write-Host ''
	Write-Host "=== gap ${id}: the document says that this does not work yet"
	& $body
	Write-Host "the gap is still there: $id"
}

# The values of the document in a line of a block. A value that the script has not got yet is an error.
function Expand-Values([string] $line, [bool] $hide = $false) {
	foreach ($k in $values.Keys) {
		if ($null -ne $values[$k]) {
			$shown = $(if ($hide -and $k -eq 'VIEWER-TOKEN') { '<VIEWER-TOKEN>' } else { [string] $values[$k] })
			$line = $line.Replace("<$k>", $shown)
		}
	}
	$left = [regex]::Match($line, '<[A-Z][A-Z-]*>')
	if ($left.Success -and -not ($hide -and $left.Value -eq '<VIEWER-TOKEN>')) { throw "the command of the document has the value $($left.Value), which the script has not got yet: $line" }
	return $line
}

# Start the command of a background block as a process that runs on; its output goes to files
function Start-Background([string] $command) {
	$command = Expand-Values $command
	$tokens = @($command -split '\s+' | Where-Object { $_ })
	$exe = (Get-Command $tokens[0] -CommandType Application).Source
	$name = ('background' + ($script:background.Count + 1))
	$out = Join-Path $work "$name.out"
	$err = Join-Path $work "$name.err"
	Write-Host "PS> (in the background) $(Expand-Values $command $true)"
	$p = Start-Process -FilePath $exe -ArgumentList @($tokens[1..($tokens.Count - 1)]) -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError $err
	# The handle keeps the exit code of the process
	$null = $p.Handle
	$script:background += [pscustomobject]@{ Name = $name; Command = $command; Process = $p; Out = $out; Err = $err }
	Start-Sleep -Seconds 2
	if ($p.HasExited) { throw "the background command exited with code $($p.ExitCode) at once: $command`n$(Read-Shared $out)$(Read-Shared $err)" }
	return $script:background[-1]
}

function Stop-Background {
	foreach ($b in $script:background) {
		if (-not $b.Process.HasExited) { Stop-Process -Id $b.Process.Id -Force -ErrorAction SilentlyContinue; $b.Process.WaitForExit(10000) | Out-Null }
	}
	$script:background = @()
}

# The text of a file that a process may still write to
function Read-Shared([string] $path) {
	if (-not (Test-Path -LiteralPath $path)) { return '' }
	$fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
	try {
		return (New-Object System.IO.StreamReader($fs)).ReadToEnd()
	} finally {
		$fs.Dispose()
	}
}

# Run the blocks of the current step in the order of the document: the lines of a run block one after the other, with
# the output of each printed and kept, a background block started. The text of all the lines is returned. -From and
# -Count run some of the blocks only, for a step whose later blocks need a value that an earlier one prints.
function Invoke-Doc([int] $From = 0, [int] $Count = -1) {
	$all = New-Object System.Text.StringBuilder
	$blocks = @($script:current.Blocks)
	$last = $(if ($Count -lt 0) { $blocks.Count } else { [Math]::Min($blocks.Count, $From + $Count) })
	if ($From -ge $last) { throw "the step $($script:current.Id) has no block $From of the document" }
	foreach ($b in $blocks[$From..($last - 1)]) {
		if ($b.Kind -eq 'background') {
			$null = Start-Background $b.Lines[0]
			continue
		}
		foreach ($line in $b.Lines) {
			$command = Expand-Values $line
			Write-Host "PS> $(Expand-Values $line $true)"
			$global:LASTEXITCODE = 0
			$out = (& ([scriptblock]::Create($command)) | Out-String)
			$code = $LASTEXITCODE
			# The secret of a token that a command prints is not printed to the log of the job
			if ($out.Trim()) { Write-Host ($out.TrimEnd() -replace 'ranz_[A-Za-z0-9_\-]{8,}', 'ranz_***') }
			if ($code -ne 0) { throw "the command exited with code ${code}: $(Expand-Values $line $true)" }
			$null = $all.AppendLine($out)
		}
	}
	return $all.ToString()
}

function Wait-Until([scriptblock] $condition, [string] $what, [int] $seconds = 60) {
	$end = (Get-Date).AddSeconds($seconds)
	while ($true) {
		$value = & $condition
		if ($value) { return $value }
		if ((Get-Date) -ge $end) { throw "$what did not happen within $seconds s" }
		Start-Sleep -Milliseconds 500
	}
}

function Wait-Service([string] $name, [string] $state) {
	$null = Wait-Until { $s = Get-Service -Name $name -ErrorAction SilentlyContinue; ($null -ne $s) -and ($s.Status -eq $state) } "the service $name to be $state"
}

function Wait-ServiceGone([string] $name) {
	$null = Wait-Until { $null -eq (Get-Service -Name $name -ErrorAction SilentlyContinue) } "the service $name to be gone"
}

# The JSON object that a text holds, from its first brace
function Get-Json([string] $text) {
	$i = $text.IndexOf('{')
	if ($i -lt 0) { throw "there is no JSON object in:`n$text" }
	return $text.Substring($i) | ConvertFrom-Json
}

# One call of ranz with a token, its JSON answer as an object; the server is the Controller of this PC unless it is named
function Invoke-Ranz([string[]] $argv, [string] $token = $adminToken, [string] $server = 'https://127.0.0.1', [string] $fingerprint = '') {
	$flags = @('-server', $server, '-token-file', $token)
	if ($fingerprint) { $flags += @('-tls-fingerprint', $fingerprint) }
	$out = & $ranzExe @flags @argv
	if ($LASTEXITCODE -ne 0) { throw "ranz $($argv -join ' ') exited with code $LASTEXITCODE" }
	return ($out -join "`n") | ConvertFrom-Json
}

# One call of ranz that the Controller must refuse with the HTTP status $status; ranz prints it after the error
function Assert-Refused([string[]] $argv, [int] $status) {
	$errFile = Join-Path $work 'refused.err'
	& $ranzExe @argv 2> $errFile | Out-Null
	$code = $LASTEXITCODE
	$msg = Get-Content -LiteralPath $errFile -Raw
	if ($code -eq 0 -or $msg -notmatch "\($status ") { throw "ranz $($argv -join ' ') was not refused with $status (exit code $code): $msg" }
	Write-Host "refused: $($msg.Trim())"
}

# What curl.exe answers: the HTTP status, and with -Body the body of the answer
function Invoke-Curl([string] $url, [string] $bearer = '', [switch] $Body) {
	$argv = @('-k', '-s')
	if ($bearer) { $argv += @('-H', "Authorization: Bearer $bearer") }
	if ($Body) { return ((& curl.exe @argv $url) -join "`n") }
	return ((& curl.exe @argv -o NUL -w '%{http_code}' $url) -join '').Trim()
}

# The lines of the logs that a failed run needs
function Show-Tail([string] $path, [int] $lines) {
	if (Test-Path -LiteralPath $path) {
		Write-Host "--- last lines of ${path}:"
		Get-Content -LiteralPath $path -Tail $lines -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $_" }
	}
}

function Show-Diagnostics {
	Write-Host '--- diagnostics'
	foreach ($name in $nodeService, $controllerService) {
		$svc = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
		if ($svc) { Write-Host "service ${name}: $($svc.State), exit code $($svc.ExitCode), start name '$($svc.StartName)', path $($svc.PathName)" } else { Write-Host "service ${name}: not installed" }
	}
	Show-Tail (Join-Path $controllerData 'controller.log') 80
	foreach ($log in @(Get-ChildItem -LiteralPath (Join-Path $nodeData 'node_log') -File -Recurse -ErrorAction SilentlyContinue)) { Show-Tail $log.FullName 40 }
	Write-Host 'Application log entries of ranz-controller:'
	Get-WinEvent -LogName Application -FilterXPath "*[System[Provider[@Name='$controllerService']]]" -MaxEvents 10 -ErrorAction SilentlyContinue |
		ForEach-Object { Write-Host ("  {0:u} id {1}: {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace '\s+', ' ')) }
	foreach ($b in $script:background) {
		Write-Host "--- $($b.Command)"
		Write-Host (Read-Shared $b.Out)
		Write-Host (Read-Shared $b.Err)
	}
	Write-Host '--- adapters and addresses'
	Get-NetAdapter -ErrorAction SilentlyContinue | Format-Table Name, InterfaceDescription, Status | Out-String | Write-Host
	Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Format-Table InterfaceAlias, IPAddress, PrefixLength | Out-String | Write-Host
	Write-Host '--- routes of the adapter and the network profiles'
	Get-NetRoute -InterfaceAlias $adapterName -AddressFamily IPv4 -ErrorAction SilentlyContinue | Format-Table DestinationPrefix, NextHop, RouteMetric | Out-String | Write-Host
	Get-NetConnectionProfile -ErrorAction SilentlyContinue | Format-Table InterfaceAlias, NetworkCategory, IPv4Connectivity | Out-String | Write-Host
}

# The lines of the node log of the Node service of the runner that hold the text what
function Get-NodeLog([string] $what) {
	return @(Get-ChildItem -LiteralPath (Join-Path $nodeData 'node_log') -File -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern $what -SimpleMatch)
}

# The Node of the Controller named name as ranz get nodes reports it, $null when there is none or the API does not answer
# (a Controller that restarts)
function Get-Node([string] $name) {
	try {
		return @((Invoke-Ranz @('get', 'nodes')).nodes | Where-Object { $_.name -eq $name })[0]
	} catch {
		return $null
	}
}

# Whether the default admin source allowlist of ranz install holds an IPv4 address because it is on a private subnet (RFC 1918)
function Test-PrivateAddress([string] $address) {
	return ($address -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)')
}

# The prefixes of the admin source allowlist that the Controller holds, as ranz admin-sources list prints them
function Get-Allowlist {
	return @((Invoke-Ranz @('admin-sources', 'list')).prefixes | ForEach-Object { $_ })
}

# The admin source allowlist must hold the address that a PC calls the Controller from (step 13). A private address is in the default
# list; any other is named by hand with ranz admin-sources set, which replaces the list, so the entries that it holds are named too, as
# the runbook says. The change is an event of its own, which the steps that count the events expect.
function Assert-AllowlistHolds([string] $address) {
	if (Test-PrivateAddress $address) {
		Write-Host "the address $address is private, so the allowlist holds it"
		return
	}
	Write-Host "the address $address is not private, so the allowlist does not hold it: it is added now"
	$held = @(Get-Allowlist)
	$null = Invoke-Ranz (@('admin-sources', 'set') + $held + @($address))
	$script:allowlistEvents++
	$now = @(Get-Allowlist)
	if ($now -notcontains "$address/32") { throw "ranz admin-sources set did not put $address into the allowlist, which holds $($now -join ', ')" }
	foreach ($prefix in $held) {
		if ($now -notcontains $prefix) { throw "ranz admin-sources set took $prefix out of the allowlist, which holds $($now -join ', ')" }
	}
}

# A source file that the Gap steps read: whether a pattern is in the files of a folder, tests left out
function Test-Source([string] $folder, [string] $filter, [string] $pattern) {
	$files = @(Get-ChildItem -Path (Join-Path $repo $folder) -Filter $filter -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '*_test.go' })
	if ($files.Count -eq 0) { throw "the folder $folder holds no ${filter}: this script reads the sources to see that a Gap is still there" }
	return (@(Select-String -Path $files.FullName -Pattern $pattern).Count -gt 0)
}

# The rules of the group of ranz install, read back from Windows Firewall: each must be an enabled inbound rule that allows,
# and the protocols, ports and programs of all of them must be want. The ids of the rules are returned, in order.
function Assert-FirewallRules([string[]] $want) {
	$rules = @(Get-NetFirewallRule -Group $firewallGroup -ErrorAction SilentlyContinue)
	$have = @()
	foreach ($r in $rules) {
		$ports = $r | Get-NetFirewallPortFilter
		$program = ($r | Get-NetFirewallApplicationFilter).Program
		if ($r.Direction -ne 'Inbound' -or $r.Action -ne 'Allow' -or [string] $r.Enabled -ne 'True') { throw "the rule '$($r.DisplayName)' of the group $firewallGroup is $($r.Direction) $($r.Action), enabled $($r.Enabled)" }
		$have += "$($ports.Protocol) $(@($ports.LocalPort) -join ',') $program"
	}
	$haveText = (@($have | Sort-Object) -join '; ')
	$wantText = (@($want | Sort-Object) -join '; ')
	if ($haveText -ne $wantText) { throw "the group $firewallGroup of Windows Firewall holds [$haveText], not [$wantText]" }
	Write-Host "Windows Firewall, the group ${firewallGroup}: $haveText"
	return @($rules | ForEach-Object { $_.Name } | Sort-Object)
}

# ranz node state of the Node service of the runner: its exit code and its JSON
function Get-NodeState {
	$out = (& $ranzExe node state) -join "`n"
	$code = $LASTEXITCODE
	$global:LASTEXITCODE = 0
	return [pscustomobject]@{ Code = $code; State = $(if ($out.Trim()) { $out | ConvertFrom-Json } else { $null }); Text = $out }
}

function Assert-Gap([string] $gap, [bool] $there, [string] $what) {
	if (-not $there) { throw "$gap is closed, or its sources moved: $what. Make the steps of docs/first-test.md real, and then this Gap step a step" }
	Write-Host "$gap is still there: $what"
}

# A diagnostics bundle (SDN-54), a ZIP archive: the text of each part by its name
function Read-Bundle([string] $path) {
	if (-not (Test-Path -LiteralPath $path)) { throw "the bundle $path was not made" }
	Add-Type -AssemblyName System.IO.Compression.FileSystem
	$parts = [ordered]@{}
	$zip = [System.IO.Compression.ZipFile]::OpenRead($path)
	try {
		foreach ($entry in $zip.Entries) {
			$reader = New-Object System.IO.StreamReader($entry.Open())
			try { $parts[$entry.FullName] = $reader.ReadToEnd() } finally { $reader.Dispose() }
		}
	} finally {
		$zip.Dispose()
	}
	return $parts
}

# The parts that a bundle must hold, the folders that must hold a part, and the secrets that no part may hold
function Assert-Bundle([string] $path, [string[]] $names, [string[]] $folders, [string[]] $secrets) {
	$parts = Read-Bundle $path
	Write-Host "the bundle $path holds $($parts.Count) parts: $($parts.Keys -join ', ')"
	foreach ($name in $names) {
		if (-not $parts.Contains($name)) { throw "the bundle $path has no part $name" }
	}
	foreach ($folder in $folders) {
		if (@($parts.Keys | Where-Object { $_.StartsWith($folder) }).Count -eq 0) { throw "the bundle $path has no part under $folder" }
	}
	foreach ($name in $parts.Keys) {
		foreach ($secret in $secrets) {
			if ($secret -and $parts[$name].Contains($secret)) { throw "the part $name of the bundle $path holds the secret of an API token" }
		}
	}
	# The manifest lists a problem for each source that failed and each part that was left out
	$manifest = $parts['manifest.json'] | ConvertFrom-Json
	$problems = @($manifest.problems | Where-Object { $_ })
	if ($manifest.product -ne 'Ranz' -or $problems.Count -ne 0) { throw "the manifest of the bundle $path is $($parts['manifest.json'])" }
}

#
# The steps, in the order of docs/first-test.md
#

$values['PC-A'] = (Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred |
	Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } | Select-Object -First 1).IPAddress
if (-not $values['PC-A']) { throw 'the runner has no IPv4 address outside loopback' }
Write-Host "PC A and PC B are this runner, $($values['PC-A']); the PCs of the runbook are windows of it"

try {
	Step 'download' {
		# The three artifacts of the runbook, in the folders that it names
		New-Item -ItemType Directory -Force -Path $ranzDir, $certDir, $binDir | Out-Null
		Copy-Item -LiteralPath $Ranz -Destination $ranzExe -Force
		Copy-Item -LiteralPath $Certificate -Destination (Join-Path $certDir 'ranz-ci-signing.cer') -Force
		Copy-Item -LiteralPath (Join-Path $Binaries 'vpntest.exe') -Destination $binDir -Force
		foreach ($f in $ranzExe, (Join-Path $certDir 'ranz-ci-signing.cer'), (Join-Path $binDir 'vpntest.exe')) {
			if (-not (Test-Path -LiteralPath $f)) { throw "$f is missing" }
		}
		$out = Invoke-Doc
		if ($out -notmatch '(?m)^ranz \d+\.\d+\.\d+\s*$') { throw "ranz version printed '$out', not ranz and three numbers" }
	}

	Step 'prerequisites' {
		$out = Invoke-Doc
		if ($out -notmatch '(?m)^True\s*$') { throw 'the window is not elevated: the first command did not print True' }
		if ([Environment]::OSVersion.Version.Major -lt 10) { throw "this is Windows $([Environment]::OSVersion.Version), not 10 or newer" }
		$listening = @(Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue)
		if ($listening.Count -gt 0) { throw "TCP 443 is held on this runner (process $($listening[0].OwningProcess)): the Controller would fall back to 5555, which the runbook shows but this script does not follow" }
		Write-Host "this is a $Architecture runner and TCP 443 is free"
	}

	Step 'trust' {
		$out = Invoke-Doc
		if ($out -notmatch '(?m)^Valid\s*$') { throw "the signature of ranz.exe is not Valid after the certificate is trusted: $out" }
	}

	Step 'firewall' {
		# Nothing is opened by hand (SDN-91): before the install the group of ranz install is empty
		$out = Invoke-Doc
		if ($out.Trim()) { throw "the group $firewallGroup of Windows Firewall holds rules before the install:`n$out" }
		$null = Assert-FirewallRules @()
	}

	Step 'install-a' {
		$out = Invoke-Doc
		if ($out -notmatch 'ranz install: done' -or $out -notmatch 'install: the ranz-controller service is running') { throw 'ranz install --controller did not say that it is done and that the Controller runs' }
		# The rules of the Node and the Controller, and only them, read back from Windows Firewall
		if ($out -notmatch 'install: Windows Firewall lets in') { throw 'ranz install --controller did not say which ports it opened in Windows Firewall' }
		# The first install narrows who may reach the API (AUD1-DT-6): loopback and the private subnets, and how to change it
		if ($out -notmatch 'install: the Controller starts with the admin source allowlist [^\r\n]*127\.0\.0\.0/8[^\r\n]*403[^\r\n]*ranz admin-sources set') { throw 'ranz install --controller did not say which sources may reach the API and how to change that' }
		$script:firewallIds = Assert-FirewallRules ($nodeRules + $controllerRules)
		foreach ($name in $nodeService, $controllerService) { Wait-Service $name 'Running' }
		foreach ($f in 'ranz-node.exe', 'ranz.exe', 'wintun.dll', 'NOTICE.txt') {
			if (-not (Test-Path -LiteralPath (Join-Path $installDir $f))) { throw "ranz install did not write $f into $installDir" }
		}
		if ($x64) {
			foreach ($name in 'SeLow', 'xdp') { Write-Host "driver ${name}: $((& sc.exe query $name | Out-String) -replace '\s+', ' ')" }
			$global:LASTEXITCODE = 0
		}
	}

	Step 'controller-up' {
		$out = Invoke-Doc
		foreach ($name in $nodeService, $controllerService) { Wait-Service $name 'Running' }
		# The data directory is the Administrators' (AUD1-DT-10, #458, ST-3): they own it, its access list is protected, and
		# only SYSTEM, the Administrators, the owner and the service account have a rule in it
		if ($out -notmatch '(?m)^BUILTIN\\Administrators\s*$') { throw "the data directory of the Controller is not owned by the Administrators:`n$out" }
		if ($out -notmatch '(?m)^True\s*$') { throw "the access list of the data directory of the Controller is not protected:`n$out" }
		$rules = @((Get-Acl -LiteralPath $controllerData).Access | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
		$others = @($rules | Where-Object { @('BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM', 'OWNER RIGHTS', 'S-1-3-4', "NT SERVICE\$controllerService") -notcontains $_ })
		if ($others.Count -gt 0) { throw "the access list of the data directory of the Controller has rules for $($others -join ', ')" }
		Write-Host "the data directory of the Controller: owned by the Administrators, a protected access list with rules for $($rules -join ', ') only"
		foreach ($f in 'admin.token', 'controller.log', 'tls.fingerprint', 'payload\rqlited.exe', 'rqlite') {
			if (-not (Test-Path -LiteralPath (Join-Path $controllerData $f))) { throw "the Controller did not make $f in $controllerData" }
		}
		$log = Get-Content -LiteralPath (Join-Path $controllerData 'controller.log') -Raw
		foreach ($line in 'first start: the intent of a first install', 'msg="TLS port"', 'first start: the admin source allowlist is set', 'first start: the starter rule default-allow-all allows all traffic inside VRF default') {
			if ($log -notmatch [regex]::Escape($line)) { throw "controller.log does not say '$line'" }
		}
		$token = (Get-Content -LiteralPath $adminToken -Raw).Trim()
		if ($token -notmatch '^ranz_') { throw 'admin.token does not hold a token that starts with ranz_' }
		Write-Host "::add-mask::$token"
	}

	Step 'certificate' {
		$out = Invoke-Doc
		$status = Get-Json $out
		if ($status.tlsFingerprint -notmatch '^[0-9a-f]{64}$') { throw "the TLS fingerprint is '$($status.tlsFingerprint)', not 64 hex digits" }
		if ([Convert]::FromBase64String($status.publicKey).Length -ne 32) { throw "the public key '$($status.publicKey)' is not the base64 of 32 bytes" }
		if ($status.capabilities.tlsPort -ne 443 -or $status.capabilities.tlsPortFallback) { throw 'the Controller is not on TCP 443' }
		# ranz status says who may reach the API and what the starter rule does (AUD1-DT-6)
		if ($status.adminAccess.open -or @($status.adminAccess.sources) -notcontains '127.0.0.0/8' -or $status.adminAccess.note -notmatch 'ranz admin-sources set') { throw "ranz status says $($status.adminAccess | ConvertTo-Json -Compress) about the admin source allowlist, not loopback and the private subnets, with how to change it" }
		if ($status.starterRule.name -ne 'default-allow-all' -or $status.starterRule.note -notmatch 'allows all traffic inside VRF default' -or $status.starterRule.note -notmatch 'docs/first-test\.md') { throw "ranz status says $($status.starterRule | ConvertTo-Json -Compress) about the starter rule" }
		# PC B reaches the Controller through the address of the runner (step 13), so the allowlist must hold it. A runner on a
		# private subnet is in the default; one on a public address is named by hand, as the runbook says
		foreach ($case in @(@('10.1.0.39', $true), @('172.15.255.255', $false), @('172.16.0.1', $true), @('172.31.255.255', $true), @('172.32.0.1', $false), @('192.168.1.1', $true), @('192.169.0.1', $false), @('100.64.0.1', $false), @('203.0.113.77', $false), @('8.8.8.8', $false))) {
			if ((Test-PrivateAddress $case[0]) -ne $case[1]) { throw "the script takes the address $($case[0]) for private: $(Test-PrivateAddress $case[0]), not $($case[1])" }
		}
		Assert-AllowlistHolds $values['PC-A']
		# A runner of CI is on a private subnet, so the branch for an address that is not private is never taken for it (AUD1-DT-15,
		# #497). Take it here for an address of the documentation range (RFC 5737), which no host holds, then put the list back. The two
		# changes are events of their own, which the steps that count the events expect
		$before = @(Get-Allowlist)
		try {
			Assert-AllowlistHolds '203.0.113.77'
		} finally {
			# The list goes back also when the check above throws, the read back of the list included (AUD1-DT-15-R1, #561): a machine
			# that keeps its data directory would hold the address at its next run, and the Controller refuses a list that holds an
			# address twice. A call that fails here must not hide the error that is in flight, and the read back below fails the step
			# when the list is not as it was
			try {
				$null = Invoke-Ranz (@('admin-sources', 'set') + $before)
				$script:allowlistEvents++
			} catch {
				Write-Host "the allowlist could not be put back: $($_.Exception.Message)"
			}
		}
		$after = @(Get-Allowlist)
		if (($after -join ',') -ne ($before -join ',')) { throw "the allowlist holds $($after -join ', ') after the check of the branch for an address that is not private, and held $($before -join ', ') before it" }
		Write-Host "the allowlist is as it was: $($after -join ', ')"
		# What the log says at the first start is what the API says
		# (the log writer quotes a value that holds an equals sign, as a base64 key does)
		$log = Get-Content -LiteralPath (Join-Path $controllerData 'controller.log') -Raw
		if ($log -notmatch ('publicKey="?' + [regex]::Escape($status.publicKey) + '"?') -or $log -notmatch ('tlsFingerprint="?' + [regex]::Escape($status.tlsFingerprint) + '"?')) { throw 'controller.log does not name the key and the fingerprint that ranz status prints' }
		# ranz took the file that the Controller wrote to its data directory to check the certificate of the call above
		# (AUD1-DT-14, #496). It takes it because SYSTEM, the Administrators or the account of the service own it and no other
		# account has a rule that writes it, so no other account can have put its own key there
		$fingerprintFile = Join-Path $controllerData 'tls.fingerprint'
		$fingerprintOwner = (Get-Acl -LiteralPath $fingerprintFile).Owner
		if (@('BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM', "NT SERVICE\$controllerService") -notcontains $fingerprintOwner) { throw "tls.fingerprint is owned by $fingerprintOwner, not by SYSTEM, the Administrators or the account of the service" }
		$fingerprintRules = @((Get-Acl -LiteralPath $fingerprintFile).Access | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
		$strangers = @($fingerprintRules | Where-Object { @('BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM', 'OWNER RIGHTS', 'S-1-3-4', "NT SERVICE\$controllerService") -notcontains $_ })
		if ($strangers.Count -gt 0) { throw "the access list of tls.fingerprint has rules for $($strangers -join ', ')" }
		if ((Get-Content -LiteralPath $fingerprintFile -Raw).Trim() -ne $status.tlsFingerprint) { throw "tls.fingerprint does not hold the fingerprint that ranz status prints, $($status.tlsFingerprint)" }
		Write-Host "tls.fingerprint: owned by $fingerprintOwner, with rules for $($fingerprintRules -join ', ') only, and ranz takes it"
		$values['FINGERPRINT'] = $status.tlsFingerprint
		$values['CONTROLLER-KEY'] = $status.publicKey
		$values['PORT'] = [string] $status.capabilities.tlsPort
		$values['CONTROLLER'] = "$($values['PC-A']):$($values['PORT'])"
		Write-Host "the Controller: $($values['CONTROLLER']), key $($values['CONTROLLER-KEY']), fingerprint $($values['FINGERPRINT'])"
	}

	Step 'web-ui' {
		$out = Invoke-Doc
		if ($out -notmatch '(?m)^200\s*$') { throw "the web UI did not answer 200 on https://localhost/: $out" }
		$me = Get-Json $out
		if ($me.name -ne 'admin' -or $me.role -ne 'admin') { throw "ranz whoami is $($me | ConvertTo-Json -Compress), not the admin token" }
		# Each page of the UI, with its title, and the script that it loads: the pages need no token, they hold no data
		$pages = [ordered]@{ '/' = 'Overview'; '/sign-in' = 'Sign in'; '/vrfs' = 'VRFs'; '/networks' = 'Networks'; '/nodes' = 'Nodes'; '/intent' = 'Intent'; '/revisions' = 'Revisions'; '/events' = 'Events'; '/licence' = 'Licence'; '/diagnostics' = 'Diagnostics'; '/tokens' = 'API tokens' }
		foreach ($path in $pages.Keys) {
			$html = Invoke-Curl "https://localhost$path" -Body
			if ($html -notmatch [regex]::Escape("<title>$($pages[$path]) | Ranz controller</title>")) { throw "the page $path has no title '$($pages[$path]) | Ranz controller'" }
		}
		if ((Invoke-Curl 'https://localhost/assets/overview.js') -ne '200') { throw 'the script of the Overview page is not served' }
		# What the Overview page asks for, with the token that the sign-in keeps: status, resources, nodes, revisions and licence
		$token = (Get-Content -LiteralPath $adminToken -Raw).Trim()
		foreach ($call in 'status', 'resources', 'nodes', 'revisions', 'licence') {
			if ((Invoke-Curl "https://localhost/api/v1/$call" $token) -ne '200') { throw "the API call $call, which the Overview page makes, is not answered 200 with the admin token" }
		}
		if ((Invoke-Curl 'https://localhost/api/v1/status') -ne '401') { throw 'the API answers a call without a token with something else than 401' }
		$licence = Invoke-Ranz @('get', 'licence')
		if ($licence.tier -ne 'Personal') { throw "the licence is the $($licence.tier) tier, not Personal" }
	}

	Step 'default-intent' {
		$null = Invoke-Doc
		$resources = @((Invoke-Ranz @('get', 'resources')).resources)
		$names = ($resources | ForEach-Object { "$($_.kind)/$($_.name)" }) -join ','
		if ($names -ne 'VRF/default,Network/default,Policy/default-allow-all') { throw "the first start made the intent $names" }
		$vrf = $resources[0].spec
		$network = $resources[1].spec
		$rule = $resources[2].spec
		if (-not $vrf.dns -or $vrf.mtu -ne 1280 -or $network.vrf -ne 'default' -or $network.mode -ne 'L3' -or $network.ipv4Pool -ne '100.64.0.0/10' -or $rule.vrf -ne 'default' -or $rule.action -ne 'allow') {
			throw 'VRF default, its Network or the starter rule is not the one of a first install'
		}
		$revisions = @((Invoke-Ranz @('get', 'revisions')).revisions)
		if ($revisions.Count -ne 1 -or $revisions[0].operation -ne 'first-start') { throw "the revisions of the first start are $($revisions | ConvertTo-Json -Compress -Depth 4)" }
		$pool = @((Invoke-Ranz @('get', 'ipam')).pools)[0]
		if ($pool.network -ne 'default' -or $pool.pool -ne '100.64.0.0/10' -or $pool.allocated -ne 0) { throw "the pool of Network default is $($pool | ConvertTo-Json -Compress)" }
	}

	Step 'install-b' {
		$out = Invoke-Doc
		if ($out -notmatch 'install: the ranzvpnserver service is running' -or $out -notmatch 'ranz install: done') { throw 'the second ranz install did not say that the Node runs and that it is done' }
		if (@(Get-CimInstance Win32_Service -Filter "Name='$nodeService'").Count -ne 1) { throw "there is not exactly one service $nodeService" }
		# The runner is PC A too, so the Controller is installed: a second install keeps the same rules, by their ids
		$ids = Assert-FirewallRules ($nodeRules + $controllerRules)
		if (($ids -join ',') -ne ($script:firewallIds -join ',')) { throw "the second ranz install changed the rules of the group ${firewallGroup}: $($script:firewallIds -join ',') before, $($ids -join ',') after" }
		if ($out -notmatch 'which is there already') { throw 'the second ranz install did not say that it kept the rules that are there' }
	}

	Step 'node-up' {
		$logDir = Join-Path $nodeData 'node_log'
		# The node log is written a moment after the Node starts
		$null = Wait-Until { @(Get-ChildItem -LiteralPath $logDir -File -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern 'Capabilities: architecture' -SimpleMatch).Count -gt 0 } 'the node log to name the Capabilities'
		$null = Wait-Until { @(Get-NodeLog 'Controller: none').Count -gt 0 } 'the node log to say that the Node has no Controller'
		$out = Invoke-Doc
		Wait-Service $nodeService 'Running'
		if ($out -notmatch 'Node started') { throw 'the node log does not say that the Node started' }
		if ($out -notmatch "Capabilities: architecture $Architecture, SeLow (yes|no), XDP (yes|no)") { throw "the node log does not give the Capabilities of an $Architecture PC: $out" }
		foreach ($f in 'ranz_node.db', 'node_config.txt') {
			if (-not (Test-Path -LiteralPath (Join-Path $nodeData $f))) { throw "$f is not in $nodeData" }
		}
		# Without Controller settings the Node says so once at each start, and opens no control stream (SDN-90)
		if ($out -notmatch 'Controller: none') { throw 'the node log does not say that the Node has no Controller' }
		if (@(Get-NodeLog 'Overlay started').Count -ne 0) { throw 'the Node without Controller settings started an overlay' }
		# ranz node state asks the running service on its admin pipe (SDN-91): its Roles, no control stream and why, no
		# adapter and no session
		if ($out -notmatch 'Control stream\s+none: the node has no Controller settings') { throw "ranz node state -o table does not say that the Node has no Controller:`n$out" }
		$ns = Get-NodeState
		$s = $ns.State
		if ($ns.Code -ne 0 -or $s.service -ne 'running' -or -not $s.running -or -not $s.roles -or $s.controlStream.set -or $s.controlStream.connected -or $s.controlStream.why -ne 'the node has no Controller settings' -or @($s.adapters).Count -ne 0 -or @($s.sessions).Count -ne 0 -or $null -eq $s.listeners) {
			throw "ranz node state (exit code $($ns.Code)) is $($ns.Text)"
		}
		Write-Host "ranz node state: roles $($s.roles), control stream none: $($s.controlStream.why)"
	}

	Step 'viewer-token' {
		$out = Invoke-Doc
		$token = Get-Json $out
		if ($token.role -ne 'viewer' -or $token.name -ne 'pc-b' -or $token.token -notmatch '^ranz_') { throw "the token is $($token | ConvertTo-Json -Compress)" }
		Write-Host "::add-mask::$($token.token)"
		$values['VIEWER-TOKEN'] = $token.token
	}

	Step 'reach-controller' {
		$out = Invoke-Doc
		if ($out -notmatch 'TcpTestSucceeded\s*:\s*True') { throw "Test-NetConnection to $($values['CONTROLLER']) did not succeed: $out" }
		$server = "https://$($values['CONTROLLER'])"
		$me = Invoke-Ranz @('whoami') -token $viewerToken -server $server -fingerprint $values['FINGERPRINT']
		if ($me.role -ne 'viewer' -or $me.name -ne 'pc-b') { throw "the viewer token answers as $($me | ConvertTo-Json -Compress)" }
		# The token reads and changes nothing, and a certificate with another fingerprint is refused
		$change = Join-Path $work 'refused.json'
		Set-Content -LiteralPath $change -Value '{"resources":[{"kind":"VRF","name":"refused","spec":{"id":99}}]}'
		Assert-Refused @('-server', $server, '-token-file', $viewerToken, '-tls-fingerprint', $values['FINGERPRINT'], 'apply', '-f', $change) 403
		& $ranzExe -server $server -token-file $viewerToken -tls-fingerprint ('00' * 32) whoami 2>$null | Out-Null
		if ($LASTEXITCODE -eq 0) { throw 'ranz accepted the certificate of the Controller with a wrong TLS fingerprint' }
		$global:LASTEXITCODE = 0
		Write-Host 'a wrong fingerprint is refused'
	}

	Step 'link-check' {
		$out = Invoke-Doc
		$address = "$($values['PC-A']):9821"
		if ($out -notmatch "Throughput test to $([regex]::Escape($address))") { throw "the report does not name the server $address" }
		foreach ($row in 'Download', 'Upload', 'Total') {
			if ($out -notmatch "(?m)^\s+$row\s+\d+\s+[\d,]+ bytes\s+[\d.]+ [KMGT]?bps") { throw "the report has no rate for $row" }
		}
		# The server let its port in while it served, with a rule of the group of ranz install (SDN-91)
		$served = Read-Shared $script:background[-1].Out
		if ($served -notmatch 'Windows Firewall lets in TCP 9821') { throw "the server of the link check did not let its port in:`n$served$(Read-Shared $script:background[-1].Err)" }
		Stop-Background
	}

	Step 'declare-nodes' {
		$out = Invoke-Doc
		$applied = Get-Json $out
		$nodes = @($applied.nodes | Sort-Object name)
		if ($applied.revision -ne 2 -or $nodes.Count -ne 2 -or $nodes[0].name -ne $nodeA -or $nodes[1].name -ne $nodeB -or $nodes[0].generation -lt 1 -or $nodes[1].generation -lt 1) {
			throw "the apply is $($applied | ConvertTo-Json -Compress -Depth 4), not revision 2 with a state for $nodeA and $nodeB"
		}
	}

	Step 'addresses' {
		$null = Invoke-Doc
		$joined = @((Invoke-Ranz @('get', 'resources')).resources | Where-Object { $_.kind -eq 'Node' })
		$want = @{ $nodeA = $addressA; $nodeB = $addressB }
		foreach ($n in $joined) {
			if ((@($n.spec.vrfs) -join ',') -ne 'default' -or $n.spec.addresses.default -ne $want[$n.name]) {
				throw "Node $($n.name) is in VRFs $(@($n.spec.vrfs) -join ',') with the addresses $($n.spec.addresses | ConvertTo-Json -Compress), not VRF default with $($want[$n.name])"
			}
		}
		if ($joined.Count -ne 2) { throw "the Intent has $($joined.Count) Nodes, not 2" }
		# The endpoint of pc-a (SDN-93, #410) as the Controller keeps it: one TLS endpoint at the address of PC A, and none for pc-b
		$endpoints = @{}
		foreach ($n in $joined) { $endpoints[$n.name] = @($n.spec.endpoints | Where-Object { $_ }) }
		$wantEndpoint = "$($values['PC-A']):$($values['PORT'])"
		if ($endpoints[$nodeA].Count -ne 1 -or $endpoints[$nodeA][0].transport -ne 'tls' -or $endpoints[$nodeA][0].address -ne $wantEndpoint) {
			throw "Node $nodeA has the endpoints $($endpoints[$nodeA] | ConvertTo-Json -Compress -Depth 4), not one TLS endpoint at $wantEndpoint"
		}
		if ($endpoints[$nodeB].Count -ne 0) { throw "Node $nodeB has the endpoints $($endpoints[$nodeB] | ConvertTo-Json -Compress -Depth 4), not none" }
		$pool = @((Invoke-Ranz @('get', 'ipam')).pools)[0]
		if ($pool.allocated -ne 2) { throw "the pool of Network default has $($pool.allocated) addresses allocated, not 2" }
		$values['PC-A-OVERLAY'] = $addressA
	}

	Step 'stand-in' {
		$null = Invoke-Doc
		$stand = $script:background[-1]
		# The stand-in creates the ready file once both Nodes joined and the adapter holds its address
		$null = Wait-Until { if ($stand.Process.HasExited) { throw "the stand-in exited with code $($stand.Process.ExitCode) before it was ready:`n$(Read-Shared $stand.Out)$(Read-Shared $stand.Err)" }; Test-Path -LiteralPath $readyFile } 'the stand-in to be ready' 180
		$said = Read-Shared $stand.Out
		Write-Host $said
		foreach ($line in "FIRSTTEST NODE $nodeA ADDRESS $addressA HOST fake", "FIRSTTEST NODE $nodeB ADDRESS $addressB ADAPTER `"$adapterName`"", 'FIRSTTEST READY') {
			if ($said -notmatch [regex]::Escape($line)) { throw "the stand-in did not print '$line'" }
		}
		if ($said -match '\[FAIL\]') { throw 'a check of the stand-in failed' }
	}

	Step 'enrol' {
		$null = Invoke-Doc
		$state = Wait-Until {
			$nodes = @((Invoke-Ranz @('get', 'nodes')).nodes | Where-Object { $_.name -in @($nodeA, $nodeB) })
			if ($nodes.Count -eq 2 -and @($nodes | Where-Object { $_.connected -and $_.generation -ge 1 -and $_.ackedGeneration -eq $_.generation }).Count -eq 2) { $nodes }
		} 'both Nodes to be connected at their acknowledged Generation' 60
		foreach ($n in $state) {
			Write-Host "node $($n.name): generation $($n.generation), acknowledged $($n.ackedGeneration), connected $($n.connected), capabilities $($n.capabilities | ConvertTo-Json -Compress)"
			if (-not $n.capabilities -or $n.capabilities.architecture -ne $Architecture) { throw "Node $($n.name) reports the architecture '$($n.capabilities.architecture)' on a $Architecture runner" }
		}
		# The audit log has the enrolment of each Node, from the address that its stream came from, as ranz get audit reads it
		# (SDN-91): its JSON is the JSON of the API, and a call without a valid token is refused
		$audit = Invoke-Ranz @('get', 'audit', '-kind', 'enrolment')
		foreach ($name in $nodeA, $nodeB) {
			$rec = @($audit.records | Where-Object { $_.actor -eq "node:$name" -and $_.outcome -eq 'success' })
			if ($rec.Count -ne 1 -or $rec[0].message -notmatch 'first control stream' -or $rec[0].source -notmatch [regex]::Escape($values['PC-A'])) { throw "the audit log has no enrolment of $name from $($values['PC-A']): $($audit | ConvertTo-Json -Compress -Depth 4)" }
		}
		$token = (Get-Content -LiteralPath $adminToken -Raw).Trim()
		$api = Invoke-Curl 'https://localhost/api/v1/audit?kind=enrolment' $token -Body | ConvertFrom-Json
		if (($api | ConvertTo-Json -Compress -Depth 6) -ne ($audit | ConvertTo-Json -Compress -Depth 6)) { throw "ranz get audit gives $($audit | ConvertTo-Json -Compress -Depth 6), the API $($api | ConvertTo-Json -Compress -Depth 6)" }
		$badToken = Join-Path $work 'bad.token'
		Set-Content -LiteralPath $badToken -Value ('ranz_' + ('0' * 40))
		Assert-Refused @('-server', 'https://127.0.0.1', '-token-file', $badToken, 'get', 'audit') 401
		$log = Get-Content -LiteralPath (Join-Path $controllerData 'controller.log') -Raw
		# One line for each Node: the member that serves it comes before the name of the Node, then the address it came from
		foreach ($name in $nodeA, $nodeB) {
			if ($log -notmatch ('msg="node connected"[^\r\n]* node=' + [regex]::Escape($name) + ' remote=\S+ applied=0')) { throw "controller.log does not say that $name connected, from an address, with the Generation 0 applied" }
		}
	}

	Step 'ping' {
		$out = Invoke-Doc
		if ($out -notmatch [regex]::Escape($addressB) -or $out -notmatch 'PrefixLength\s*:\s*32') { throw "the adapter $adapterName does not show the address $addressB with the prefix length 32" }
		if ($out -notmatch '100\.64\.0\.0/10') { throw "the routes of the adapter $adapterName do not hold 100.64.0.0/10" }
		# Four echo requests: the first of a path that was never used may be lost, so three replies prove the path
		$replies = @([regex]::Matches($out, "Reply from $([regex]::Escape($addressA)): bytes=\d+ time[=<]\d+ms TTL=\d+"))
		if ($replies.Count -lt 3) { throw "the ping to $addressA got $($replies.Count) replies of 4:`n$out" }
		Write-Host "the ping from PC B to $addressA, the overlay address of $nodeA, got $($replies.Count) replies of 4 through the adapter $adapterName"
	}

	Step 'node-service' {
		# The static key of the Node service, which the service makes at the first need, as the publicKey of a Node resource
		$out = Invoke-Doc -From 0 -Count 1
		$key = (Get-Json $out).publicKey
		if (-not $key -or [Convert]::FromBase64String($key).Length -ne 32) { throw "ranz node key printed '$out', not the base64 of a key of 32 bytes" }
		if ($key -eq $values['CONTROLLER-KEY'] -or $key -in @('B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=', 'WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns=')) { throw "ranz node key printed the key $key of another end" }
		$values['NODE-KEY'] = $key
		Write-Host "the static key of the Node service: $key"

		# The verb refuses a wrong value itself, with a message that says which
		$errFile = Join-Path $work 'refused.err'
		& $ranzExe node controller set $values['PC-A'] $values['CONTROLLER-KEY'] $values['FINGERPRINT'] 2> $errFile | Out-Null
		$code = $LASTEXITCODE
		$msg = Get-Content -LiteralPath $errFile -Raw
		if ($code -ne 2 -or $msg -notmatch 'has no port') { throw "ranz node controller set took an address without a port (exit code $code): $msg" }
		$global:LASTEXITCODE = 0
		Write-Host "refused: $($msg.Trim())"

		# A wrong TLS fingerprint and a wrong static key of the Controller fail closed, each with its check in the node log
		$wrongKey = [Convert]::ToBase64String([byte[]](1..32))
		foreach ($case in @(@($values['CONTROLLER-KEY'], ('ab' * 32), 'the TLS fingerprint check failed'), @($wrongKey, $values['FINGERPRINT'], 'the Noise handshake failed'))) {
			$before = @(Get-NodeLog $case[2]).Count
			& $ranzExe node controller set $values['CONTROLLER'] $case[0] $case[1] | Out-Null
			if ($LASTEXITCODE -ne 0) { throw "ranz node controller set with a wrong value exited with code $LASTEXITCODE" }
			$null = Wait-Until { @(Get-NodeLog $case[2]).Count -gt $before } "the node log to say '$($case[2])'" 60
			Write-Host "a wrong value fails closed, and the node log says: $(@(Get-NodeLog $case[2])[-1].Line)"
		}

		# The settings of the runbook; the Controller refuses the key, which no Node resource holds yet, with the key as the
		# actor of its audit log, and the Node keeps dialling
		$null = Invoke-Doc -From 1 -Count 1
		$shown = (& $ranzExe node controller show) -join "`n" | ConvertFrom-Json
		if ($shown.controller.address -ne $values['CONTROLLER'] -or $shown.controller.publicKey -ne $values['CONTROLLER-KEY'] -or $shown.controller.tlsFingerprint -ne $values['FINGERPRINT']) {
			throw "ranz node controller show gives $($shown | ConvertTo-Json -Compress -Depth 4), not the settings of step 7"
		}
		$null = Wait-Until {
			$audit = Invoke-Ranz @('get', 'audit', '-kind', 'auth-failed')
			@($audit.records | Where-Object { $_.actor -eq "key:$key" -and $_.outcome -eq 'failure' }).Count -ge 1
		} 'the audit log to hold the refusal of the key of the Node, with the key as the actor' 90
		$out = Invoke-Doc -From 2 -Count 1
		if ($out -notmatch [regex]::Escape("key:$key")) { throw "ranz get audit -kind auth-failed -o table does not list the refusal of key:${key}:`n$out" }
		# While it is refused, the state of the Node says why
		$ns = Get-NodeState
		if ($ns.Code -ne 0 -or $ns.State.controlStream.connected -or $ns.State.controlStream.controller -ne $values['CONTROLLER'] -or -not $ns.State.controlStream.why) { throw "ranz node state of the refused Node (exit code $($ns.Code)) is $($ns.Text)" }
		Write-Host "ranz node state: not connected to $($values['CONTROLLER']): $($ns.State.controlStream.why)"
		$null = Wait-Until { @(Get-NodeLog 'the Controller refused the node').Count -gt 0 } 'the node log to say that the Controller refused the node' 90

		# Its Node resource in place of the test key of the stand-in: the Node joins on its next attempt, without a restart
		$null = Invoke-Doc -From 3 -Count 1
		$node = Wait-Until {
			$n = Get-Node $nodeA
			if ($n -and $n.connected -and $n.generation -ge 1 -and $n.ackedGeneration -eq $n.generation) { $n }
		} 'the Node service to be connected as pc-a at its acknowledged Generation' 150
		if (-not $node.capabilities -or $node.capabilities.architecture -ne $Architecture) { throw "pc-a reports the architecture '$($node.capabilities.architecture)' on a $Architecture runner" }
		Write-Host "pc-a is the Node service now: generation $($node.generation), acknowledged $($node.ackedGeneration), capabilities $($node.capabilities | ConvertTo-Json -Compress)"
		$null = Wait-Until { @(Get-NodeLog 'Overlay: generation').Count -gt 0 } 'the node log to say that the Node applied a Generation' 30
		$out = Invoke-Doc -From 4 -Count 1
		# The state of the Node on its PC says the same as the Controller (SDN-91): pc-a, connected to the Controller at a
		# Generation, no adapter without the client role, and its listeners
		if ($out -notmatch "Node\s+$nodeA" -or $out -notmatch "connected to $([regex]::Escape($values['CONTROLLER'])) for \d+s, Generation \d+") { throw "ranz node state -o table does not show pc-a connected to $($values['CONTROLLER']):`n$out" }
		$ns = Get-NodeState
		$s = $ns.State
		if ($ns.Code -ne 0 -or $s.name -ne $nodeA -or -not $s.controlStream.connected -or $s.controlStream.controller -ne $values['CONTROLLER'] -or $s.controlStream.generation -lt 1 -or $s.controlStream.why -or @($s.adapters).Count -ne 0 -or $null -eq $s.listeners) {
			throw "ranz node state of the joined Node (exit code $($ns.Code)) is $($ns.Text)"
		}
		Write-Host "ranz node state: $nodeA connected to $($s.controlStream.controller) for $($s.controlStream.connectedSeconds) s at Generation $($s.controlStream.generation), $(@($s.sessions).Count) peers"

		# The Controller restarts: the Node dials again by itself and is connected again. A Controller that starts sees no
		# Node connected until its stream comes.
		$ended = @(Get-NodeLog 'the control stream ended after it was open').Count
		$null = Invoke-Doc -From 5
		Wait-Service $controllerService 'Running'
		$null = Wait-Until { @(Get-NodeLog 'the control stream ended after it was open').Count -gt $ended } 'the node log to say that the control stream ended' 60
		$null = Wait-Until {
			$n = Get-Node $nodeA
			$n -and $n.connected -and $n.ackedGeneration -eq $n.generation
		} 'the Node service to be connected again as pc-a after the restart of the Controller' 150
		Write-Host 'after the restart of the Controller the Node service dialled again by itself and is connected again'
	}

	Step 'replace-certificate' {
		$folder = Join-Path $work 'controller-cert'
		$cert = Join-Path $folder 'controller.pem'
		$key = Join-Path $folder 'controller.key'
		$controllerLog = Join-Path $controllerData 'controller.log'
		$old = $values['FINGERPRINT']
		$server = "https://$($values['CONTROLLER'])"
		# How often the Controller log says that a Node connected: a connection that was up stays up, so the count of a Node
		# that stayed connected does not change
		function Get-Connections([string] $name) {
			return @([regex]::Matches((Get-Content -LiteralPath $controllerLog -Raw), 'msg="node connected"[^\r\n]* node=' + [regex]::Escape($name) + ' ')).Count
		}

		# The CA, the certificate for the address of this runner that it signs, and the access of the service account
		$null = Invoke-Doc -From 0 -Count 1
		foreach ($f in 'ca.pem', 'ca.key', 'controller.pem', 'controller.key') {
			if (-not (Test-Path -LiteralPath (Join-Path $folder $f))) { throw "ranz cert did not write $f into $folder" }
		}
		$acl = (& icacls $key | Out-String)
		if ($acl -notmatch 'ranz-controller') { throw "the key file has no access rule for the service account of the Controller:`n$acl" }
		$global:LASTEXITCODE = 0

		# Nothing is set: the self-signed certificate of step 7, with the fingerprint that the Node service pinned in step 20
		$out = Invoke-Doc -From 1 -Count 1
		$shown = Get-Json $out
		if ($out -match 'PRIVATE KEY') { throw 'ranz controller-cert show printed a key' }
		if ($shown.source -ne 'self-signed' -or $shown.fingerprint -ne $old -or $shown.setting) {
			throw "ranz controller-cert show with no setting is $($shown | ConvertTo-Json -Compress -Depth 4), not the self-signed certificate with the fingerprint $old"
		}

		# A certificate that the Controller refuses changes nothing: a key that is not the key of the certificate (the
		# certificate of the CA with the key of the Controller: the service may read no key of the CA), and a certificate that
		# does not name the host that the Nodes use. The answer says why.
		$refusedFile = Join-Path $work 'refused.err'
		foreach ($case in @(
				@(@('-host', $values['PC-A'], '-cert', (Join-Path $folder 'ca.pem'), '-key', $key), 'does not belong to the certificate'),
				@(@('-host', 'other.example.com', '-cert', $cert, '-key', $key), 'does not name the host "other.example.com"'))) {
			$setArgs = [string[]] $case[0]
			& $ranzExe controller-cert set @setArgs 2> $refusedFile | Out-Null
			$code = $LASTEXITCODE
			$msg = Get-Content -LiteralPath $refusedFile -Raw
			if ($code -eq 0 -or $msg -notmatch '\(400 ' -or $msg -notmatch [regex]::Escape($case[1])) { throw "ranz controller-cert set $($setArgs -join ' ') was not refused with 400 and '$($case[1])' (exit code $code): $msg" }
			$global:LASTEXITCODE = 0
			Write-Host "refused: $($msg.Trim())"
		}
		$shown = Invoke-Ranz @('controller-cert', 'show')
		if ($shown.fingerprint -ne $old -or $shown.source -ne 'self-signed') { throw "a refused certificate changed the certificate in use: $($shown | ConvertTo-Json -Compress -Depth 4)" }

		# The replacement: both Nodes take the new fingerprint before the certificate is served
		$before = @{ $nodeA = (Get-Connections $nodeA); $nodeB = (Get-Connections $nodeB) }
		foreach ($name in $nodeA, $nodeB) {
			if ($before[$name] -lt 1) { throw "controller.log does not say that $name connected" }
		}
		$failedChecks = @(Get-NodeLog 'the TLS fingerprint check failed').Count
		$out = Invoke-Doc -From 2 -Count 1
		if ($out -match 'PRIVATE KEY') { throw 'ranz controller-cert set printed a key' }
		$change = Get-Json $out
		$new = $change.certificate.fingerprint
		if ($change.certificate.source -ne 'file' -or $new -notmatch '^[0-9a-f]{64}$' -or $new -eq $old -or @($change.certificate.names) -notcontains $values['PC-A'] -or $change.certificate.selfSigned) {
			throw "the replacement is $($change | ConvertTo-Json -Compress -Depth 5), not a certificate of the file for $($values['PC-A']) with another fingerprint than $old"
		}
		# unpinned is left out of the answer when it is empty, and the count of @($null) is one
		if ((@($change.pinned) -join ',') -ne "$nodeA,$nodeB" -or @($change.unpinned | Where-Object { $_ }).Count -ne 0) {
			throw "the Nodes that took the new fingerprint before the certificate was served are $(@($change.pinned) -join ','), and $(@($change.unpinned) -join ',') did not"
		}
		$values['FINGERPRINT'] = $new
		Write-Host "the Controller serves the certificate of the file: fingerprint $new, in place of $old"

		# The log, the events and the audit log have the change, and the status and show name the new fingerprint. The
		# Controller writes both lines before it answers, yet a read of controller.log right after the answer has missed the
		# first one on x64 runners while the file held it, so the log is read again until it shows them
		foreach ($line in 'msg="TLS certificate"', 'msg="certificate of the controller changed"') {
			$null = Wait-Until { (Get-Content -LiteralPath $controllerLog -Raw) -match [regex]::Escape($line) } "controller.log to say '$line'" 15
		}
		# The first start set the admin source allowlist and recorded it (AUD1-DT-6), and step 7 recorded one more when it had to add
		# the address of the runner, so the events are those and the change
		$events = @((Invoke-Ranz @('get', 'events')).events | Where-Object { $_ })
		$allowed = @($events | Where-Object { $_.type -eq 'admin-sources-changed' })
		$changed = @($events | Where-Object { $_.type -eq 'controller-certificate-changed' })
		if ($events.Count -ne ($script:allowlistEvents + 1) -or $allowed.Count -ne $script:allowlistEvents -or @($allowed | Where-Object { $_.message -match 'at the first start' }).Count -ne 1 -or
			$changed.Count -ne 1 -or $changed[0].message -notmatch [regex]::Escape($new)) {
			throw "the events are $($events | ConvertTo-Json -Compress -Depth 4), not the $($script:allowlistEvents) of the admin source allowlist, the first at the first start, and the change of the certificate"
		}
		$null = Wait-Until {
			$audit = Invoke-Ranz @('get', 'audit', '-kind', 'operation', '-limit', '1000')
			@($audit.records | Where-Object { $_.action -eq 'PUT /api/v1/controller-certificate' -and $_.actor -eq 'token:admin' -and $_.outcome -eq 'success' }).Count -eq 1
		} 'the audit log to hold the change of the certificate' 15
		$out = Invoke-Doc -From 3 -Count 1
		$shown = Get-Json $out
		if ($out -match 'PRIVATE KEY' -or $shown.fingerprint -ne $new -or $shown.source -ne 'file' -or $shown.setting.file.certificate -ne $cert -or $shown.setting.file.key -ne $key) {
			throw "ranz controller-cert show after the change is $($shown | ConvertTo-Json -Compress -Depth 5)"
		}
		if ((Invoke-Ranz @('status')).tlsFingerprint -ne $new) { throw 'ranz status does not name the fingerprint of the new certificate' }
		# The Controller writes the fingerprint file again when the certificate changes, as step 6 says
		if ((Get-Content -LiteralPath (Join-Path $controllerData 'tls.fingerprint') -Raw).Trim() -ne $new) { throw "tls.fingerprint does not hold the fingerprint of the new certificate, $new" }

		# The connections that were up stayed up: no Node connected again because of the change
		foreach ($name in $nodeA, $nodeB) {
			if ((Get-Connections $name) -ne $before[$name]) { throw "$name connected again while the certificate was replaced: its connection was up and had to stay" }
			$n = Get-Node $name
			if (-not $n -or -not $n.connected) { throw "$name is not connected after the certificate was replaced" }
		}
		Write-Host 'the Nodes that were connected stayed connected while the certificate was replaced'

		# The Node service pinned the old fingerprint in step 20: the Controller sent it the new one with the old one, then the
		# new one alone, and the node keeps what it was sent in its settings
		$null = Wait-Until {
			$s = (& $ranzExe node controller show) -join "`n" | ConvertFrom-Json
			if ($s.controller.tlsFingerprint -eq $new -and (@($s.controller.tlsFingerprints) -join ',') -eq $new) { $s }
		} 'the Node service to hold the new fingerprint alone in its settings' 60
		$null = Invoke-Doc -From 4 -Count 1
		foreach ($want in "accepts are now $old or $new", "accepts are now $new") {
			$null = Wait-Until { @(Get-NodeLog $want).Count -ge 1 } "the node log to say '$want'" 30
		}

		# The Controller restarts, and serves the certificate of its setting again: both Nodes dial again, the Node service
		# with the fingerprint that it was sent
		$ended = @(Get-NodeLog 'the control stream ended after it was open').Count
		$null = Invoke-Doc -From 5 -Count 1
		Wait-Service $controllerService 'Running'
		$null = Wait-Until { @(Get-NodeLog 'the control stream ended after it was open').Count -gt $ended } 'the node log to say that the control stream ended' 60
		$null = Wait-Until {
			$a = Get-Node $nodeA
			$b = Get-Node $nodeB
			$a -and $b -and $a.connected -and $b.connected -and $a.ackedGeneration -eq $a.generation -and $b.ackedGeneration -eq $b.generation
		} 'both Nodes to be connected again after the restart of the Controller' 150
		if ((Invoke-Ranz @('controller-cert', 'show')).fingerprint -ne $new) { throw 'the Controller does not serve the certificate of its setting after a restart' }

		# The Node service restarts: it reads the fingerprints from its Configuration store and dials with them
		$null = Invoke-Doc -From 6 -Count 1
		Wait-Service $nodeService 'Running'
		$null = Wait-Until {
			$a = Get-Node $nodeA
			$a -and $a.connected -and $a.ackedGeneration -eq $a.generation
		} 'the Node service to be connected as pc-a again after its restart' 150
		$out = Invoke-Doc -From 7 -Count 1
		if ($out -notmatch $nodeA -or $out -notmatch $nodeB) { throw "ranz get nodes does not list both Nodes: $out" }
		if (@(Get-NodeLog 'the TLS fingerprint check failed').Count -ne $failedChecks) {
			throw "the fingerprint check of the Node service failed after the certificate was replaced: $(@(Get-NodeLog 'the TLS fingerprint check failed')[-1].Line)"
		}
		Write-Host 'both Nodes are connected with the new certificate, the Node service also after its own restart'

		# PC B: with no fingerprint, ranz checks the chain against the roots of Windows
		Enter-Pc 'b'
		$null = Invoke-Doc -From 8 -Count 1
		$me = Get-Json (Invoke-Doc -From 9 -Count 1)
		if ($me.role -ne 'viewer' -or $me.name -ne 'pc-b') { throw "ranz whoami with no fingerprint answers as $($me | ConvertTo-Json -Compress)" }
		$me = Get-Json (Invoke-Doc -From 10 -Count 1)
		if ($me.role -ne 'viewer' -or $me.name -ne 'pc-b') { throw "ranz whoami with the new fingerprint answers as $($me | ConvertTo-Json -Compress)" }
		& $ranzExe -server $server -token-file $viewerToken -tls-fingerprint $old whoami 2>$null | Out-Null
		if ($LASTEXITCODE -eq 0) { throw 'ranz accepted the old fingerprint of the Controller after the certificate was replaced' }
		$global:LASTEXITCODE = 0
		Write-Host 'the old fingerprint is refused'
		if ((Invoke-Doc -From 11 -Count 1) -notmatch '(?m)^200\s*$') { throw "the web UI did not answer 200 to a client that checks the chain of the certificate" }

		# With the CA out of the store the chain ends in no root that Windows trusts: refused without the fingerprint
		$null = Invoke-Doc -From 12 -Count 1
		if (@(Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like 'CN=Ranz first test CA*' }).Count -ne 0) { throw 'the CA of the test is still trusted' }
		Remove-Item Env:RANZ_TLS_FINGERPRINT -ErrorAction SilentlyContinue
		& $ranzExe whoami 2> $refusedFile | Out-Null
		$msg = Get-Content -LiteralPath $refusedFile -Raw
		if ($LASTEXITCODE -eq 0 -or $msg -notmatch 'unknown authority') { throw "ranz with no fingerprint was not refused for a certificate of no trusted root (exit code $LASTEXITCODE): $msg" }
		$global:LASTEXITCODE = 0
		Write-Host "refused: $($msg.Trim())"
		$null = Invoke-Doc -From 13 -Count 1
		Enter-Pc 'a'
	}

	Step 'doctor' {
		$out = Invoke-Doc
		foreach ($title in 'Kernel System', 'Memory Operation System', 'ANSI / Unicode string processing system', 'File system', 'Thread processing system', 'Network system') {
			if ($out -notmatch [regex]::Escape("Checking '$title'... Pass")) { throw "ranz doctor does not report the check '$title' as passed" }
		}
		if ($out -notmatch 'All checks passed') { throw 'ranz doctor does not report that all checks passed' }
		# The bundle of this PC (SDN-54): the logs, the configuration and the status of what runs here, and no token
		$bundle = Join-Path $work 'bundle-host.zip'
		if ($out -notmatch [regex]::Escape("Diagnostics bundle written to $bundle")) { throw 'ranz doctor -bundle does not say where it wrote the bundle' }
		if ($out -match 'not complete:') { throw "ranz doctor -bundle says that the bundle is not complete:`n$out" }
		$secrets = @((Get-Content -LiteralPath $adminToken -Raw).Trim(), $values['VIEWER-TOKEN'])
		Assert-Bundle $bundle @('manifest.json', 'system.json', 'services.json', 'doctor.txt', 'node/config.txt', 'controller/logs/controller.log') @('node/logs/') $secrets
	}

	Step 'logs' {
		$out = Invoke-Doc
		if ($out -notmatch 'ranz-controller started') { throw 'the Application log does not say that ranz-controller started' }
		# The events are the admin source allowlist of the first start and the change that step 7 made when it had to add the address
		# of the runner (AUD1-DT-6), and the change of the certificate of step 21 (SDN-92)
		$events = @((Invoke-Ranz @('get', 'events')).events | Where-Object { $_ })
		$allowed = @($events | Where-Object { $_.type -eq 'admin-sources-changed' })
		$changed = @($events | Where-Object { $_.type -eq 'controller-certificate-changed' })
		if ($events.Count -ne ($script:allowlistEvents + 1) -or $allowed.Count -ne $script:allowlistEvents -or @($allowed | Where-Object { $_.message -match 'at the first start' }).Count -ne 1 -or $changed.Count -ne 1) {
			throw "the Controller has the events $($events | ConvertTo-Json -Compress -Depth 4), not the $($script:allowlistEvents) of the admin source allowlist, the first at the first start, and the change of the certificate of step 21 alone"
		}
		$revisions = ((Invoke-Ranz @('get', 'revisions')).revisions | ForEach-Object { $_.operation }) -join ','
		if ($revisions -ne 'first-start,apply,apply') { throw "the revisions are $revisions, not the first start and the applies of steps 15 and 20" }
		# The bundle of the Controller, the one that the button of the Diagnostics page downloads
		$admin = (Get-Content -LiteralPath $adminToken -Raw).Trim()
		$secrets = @($admin, $values['VIEWER-TOKEN'])
		Assert-Bundle (Join-Path $work 'bundle-controller.zip') @('manifest.json', 'system.json', 'services.json', 'controller/status.json', 'controller/nodes.json', 'controller/intent.json', 'controller/revisions.json', 'controller/events.json', 'controller/licence.json', 'controller/ipam.json', 'controller/logs.json', 'controller/logs/controller.log') @() $secrets
		# The pull is in the audit log: an operation of the admin token, with the call as its action (the Controller writes
		# the record when the call ends, a moment after curl has the file)
		$null = Wait-Until {
			$audit = Invoke-Ranz @('get', 'audit', '-kind', 'operation', '-limit', '1000')
			@($audit.records | Where-Object { $_.action -eq 'POST /api/v1/diagnostics/bundle' -and $_.actor -eq 'token:admin' -and $_.outcome -eq 'success' }).Count -eq 1
		} 'the audit log to hold the pull of the bundle' 15
	}

	Step 'stop-stand-in' {
		$stand = $script:background[-1]
		$null = Invoke-Doc
		$null = Wait-Until { $stand.Process.HasExited } 'the stand-in to stop' 90
		$said = Read-Shared $stand.Out
		Write-Host $said
		if ($said -notmatch 'FIRSTTEST TEST OK') { throw 'the stand-in did not print FIRSTTEST TEST OK' }
		if ($said -notmatch 'NO MEMORY LEAKS') { throw 'the stand-in leaked memory' }
		if ($said -match '\[FAIL\]') { throw 'a check of the stand-in failed' }
		Stop-Background
	}

	Step 'stand-in-gone' {
		$null = Invoke-Doc
		if (Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue) { throw "the adapter $adapterName is still there after the stand-in stopped" }
		# The stand-in played pc-b; pc-a is the Node service of the runner since step 20, which stays connected
		$null = Wait-Until {
			$nodes = @((Invoke-Ranz @('get', 'nodes') -token $viewerToken -server "https://$($values['CONTROLLER'])" -fingerprint $values['FINGERPRINT']).nodes)
			$nodes.Count -eq 2 -and @($nodes | Where-Object { $_.name -eq $nodeB -and -not $_.connected }).Count -eq 1 -and @($nodes | Where-Object { $_.name -eq $nodeA -and $_.connected }).Count -eq 1
		} 'the Controller to see pc-b as not connected and pc-a, the Node service, as connected' 30
	}

	Step 'uninstall' {
		$null = Invoke-Doc
		foreach ($name in $nodeService, $controllerService) { Wait-ServiceGone $name }
		if (Test-Path -LiteralPath $installDir) { throw "ranz uninstall left $installDir" }
		if (-not (Test-Path -LiteralPath $adminToken)) { throw 'ranz uninstall removed the data directory of the Controller, which it keeps' }
		if (-not (Test-Path -LiteralPath (Join-Path $nodeData 'ranz_node.db'))) { throw 'ranz uninstall removed the Configuration store of the Node, which it keeps' }
		# No rule of the group of ranz install is left, also not the one of the link check whose server was killed (SDN-91)
		$null = Assert-FirewallRules @()
		# ranz node state says that the service is stopped
		$ns = Get-NodeState
		if ($ns.Code -ne 3 -or $ns.State.service -ne 'stopped') { throw "ranz node state after the uninstall (exit code $($ns.Code)) is $($ns.Text)" }
		Write-Host 'ranz node state: the Node service is stopped'
		if ($x64) {
			foreach ($name in 'SeLow', 'xdp') {
				if ((& sc.exe query $name | Out-String) -match 'STATE') { throw "ranz uninstall left the driver $name" }
			}
			$global:LASTEXITCODE = 0
		}
	}

	Step 'clean-up' {
		# The rqlite member of the Controller ends with its service, and a moment later its files can go
		$null = Wait-Until { $null -eq (Get-Process -Name 'rqlited', 'ranz-node' -ErrorAction SilentlyContinue) } 'the processes of the services to end' 30
		$null = Invoke-Doc
		if (@(Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like 'CN=Ranz VPN CI signing*' }).Count -ne 0) { throw 'the CI certificate is still trusted' }
		foreach ($dir in (Join-Path $env:ProgramData 'Ranz'), $nodeData) {
			if (Test-Path -LiteralPath $dir) { throw "$dir is still there" }
		}
	}

	Gap 'gaps' {
		# The document says what is missing. The sources must still say so, or the Gap is closed. Gaps 1 and 2 are closed (step
		# 20, SDN-90), Gaps 4, 5 and 6 (SDN-91), and Gap 7 (step 21, SDN-92), and must stay so: the Node service sets the
		# control stream of its overlay, ranz has the verbs of the node, ranz install makes firewall rules, ranz reads the
		# audit log and the state of a Node, and ranz has the verb that sets the certificate of the Controller.
		if (-not (Test-Source 'src\Cedar' 'Node*.c' '\.Control\s*=|->Control\s*=')) { throw 'Gap 1 is open again: no code of the Node service sets the control stream of its overlay (NODE_OVERLAY_CONFIG.Control)' }
		if (-not (Test-Source 'controller\cmd\ranz' '*.go' 'register\("node"')) { throw 'Gap 2 is open again: ranz has no verb node, which prints the key of a Node' }
		if (-not (Test-Source 'controller\internal\install' '*.go' 'func openPorts\(')) { throw 'Gap 4 is open again: ranz install opens no port in Windows Firewall' }
		if (-not (Test-Source 'controller\cmd\ranz' '*.go' 'args\[1\] == "audit"')) { throw 'Gap 5 is open again: ranz has no verb for the audit log' }
		if (-not (Test-Source 'controller\cmd\ranz' '*.go' 'args\[0\] == "state"')) { throw 'Gap 6 is open again: ranz node has no verb state' }
		if (-not (Test-Source 'controller\cmd\ranz' '*.go' '"controller-cert"')) { throw 'Gap 7 is open again: ranz has no verb controller-cert, which sets the certificate of the Controller' }
		# The Listener of a desired state starts the front door and QUIC of a Node (SDN-45, NodeListener.c), and a Node dials a
		# peer through the endpoints of its Peer object (SDN-93, NodeEndpoints.c), which must stay so; but only the client role
		# dials, and the data transport of the Node service dials nowhere
		if (-not (Test-Source 'src\Cedar' 'NodeEndpoints.c' 'NodeEndpointsTargets')) { throw 'Gap 3 is open again: no code of the Node module dials a peer through its endpoints (NodeEndpointsTargets)' }
		$noDial = Test-Source 'src\Cedar' 'NodeController.c' 'None\.Dial\s*=\s*NodeControllerNoDial'
		Assert-Gap 'Gap 3' $noDial 'the data transport of the Node service dials nowhere: only the client role dials a peer, through its endpoints, and the desired state carries no pin of the certificate of a peer'
	}

	if ($script:next -ne $docSteps.Count) {
		throw "the document has steps that the script did not run, from '$($docSteps[$script:next].Id)' on"
	}
} catch {
	Write-Host "failed: $($_.Exception.Message)"
	Write-Host $_.ScriptStackTrace
	Show-Diagnostics
	throw
} finally {
	Stop-Background
	# A window of one PC must not leave its variables to the next step of the job
	foreach ($n in $windowVariables) { [Environment]::SetEnvironmentVariable($n, $null, 'Process') }
}

Write-Host ''
Write-Host "ok: the $($docSteps.Count) steps of $Document ran in order"
