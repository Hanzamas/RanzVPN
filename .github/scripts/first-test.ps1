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
# through the network, with the fingerprint, as a second PC does. The Nodes are the stand-in (vpntest firsttest): the
# Node service of the PC does not open a control stream to the Controller yet (Gaps 1 to 3 of the document).

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
$firewallRule = 'Ranz first test'
# The two Nodes of the stand-in and the addresses that the Controller gives them: the lowest free host addresses of the
# pool, in the order of their names (ADR-0028)
$nodeA = 'pc-a'
$nodeB = 'pc-b'
$addressA = '100.64.0.1'
$addressB = '100.64.0.2'

# The values in angle brackets that the commands of the document name, with what the script knows of them so far
$values = [ordered]@{ 'PC-A' = $null; 'PORT' = $null; 'CONTROLLER' = $null; 'FINGERPRINT' = $null; 'CONTROLLER-KEY' = $null; 'VIEWER-TOKEN' = $null; 'PC-A-OVERLAY' = $null }

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
# the output of each printed and kept, a background block started. The text of all the lines is returned.
function Invoke-Doc {
	$all = New-Object System.Text.StringBuilder
	foreach ($b in $script:current.Blocks) {
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

# A source file that the Gap steps read: whether a pattern is in the files of a folder, tests left out
function Test-Source([string] $folder, [string] $filter, [string] $pattern) {
	$files = @(Get-ChildItem -Path (Join-Path $repo $folder) -Filter $filter -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '*_test.go' })
	if ($files.Count -eq 0) { throw "the folder $folder holds no ${filter}: this script reads the sources to see that a Gap is still there" }
	return (@(Select-String -Path $files.FullName -Pattern $pattern).Count -gt 0)
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
		$null = Invoke-Doc
		$rule = Get-NetFirewallRule -DisplayName $firewallRule
		$ports = @($rule | Get-NetFirewallPortFilter | ForEach-Object { $_.LocalPort }) -join ','
		if ($rule.Direction -ne 'Inbound' -or $rule.Action -ne 'Allow' -or $ports -ne '443,5555,9821') { throw "the firewall rule is $($rule.Direction) $($rule.Action) on '$ports'" }
	}

	Step 'install-a' {
		$out = Invoke-Doc
		if ($out -notmatch 'ranz install: done' -or $out -notmatch 'install: the ranz-controller service is running') { throw 'ranz install --controller did not say that it is done and that the Controller runs' }
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
		$null = Invoke-Doc
		foreach ($name in $nodeService, $controllerService) { Wait-Service $name 'Running' }
		foreach ($f in 'admin.token', 'controller.log', 'payload\rqlited.exe', 'rqlite') {
			if (-not (Test-Path -LiteralPath (Join-Path $controllerData $f))) { throw "the Controller did not make $f in $controllerData" }
		}
		$log = Get-Content -LiteralPath (Join-Path $controllerData 'controller.log') -Raw
		foreach ($line in 'first start: the intent of a first install', 'msg="TLS port"') {
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
		# What the log says at the first start is what the API says
		# (the log writer quotes a value that holds an equals sign, as a base64 key does)
		$log = Get-Content -LiteralPath (Join-Path $controllerData 'controller.log') -Raw
		if ($log -notmatch ('publicKey="?' + [regex]::Escape($status.publicKey) + '"?') -or $log -notmatch ('tlsFingerprint="?' + [regex]::Escape($status.tlsFingerprint) + '"?')) { throw 'controller.log does not name the key and the fingerprint that ranz status prints' }
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
	}

	Step 'node-up' {
		$logDir = Join-Path $nodeData 'node_log'
		# The node log is written a moment after the Node starts
		$null = Wait-Until { @(Get-ChildItem -LiteralPath $logDir -File -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern 'Capabilities: architecture' -SimpleMatch).Count -gt 0 } 'the node log to name the Capabilities'
		$out = Invoke-Doc
		Wait-Service $nodeService 'Running'
		if ($out -notmatch 'Node started') { throw 'the node log does not say that the Node started' }
		if ($out -notmatch "Capabilities: architecture $Architecture, SeLow (yes|no), XDP (yes|no)") { throw "the node log does not give the Capabilities of an $Architecture PC: $out" }
		foreach ($f in 'ranz_node.db', 'node_config.txt') {
			if (-not (Test-Path -LiteralPath (Join-Path $nodeData $f))) { throw "$f is not in $nodeData" }
		}
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
		# The audit log has the enrolment of each Node, from the address that its stream came from
		$token = (Get-Content -LiteralPath $adminToken -Raw).Trim()
		$audit = Invoke-Curl 'https://localhost/api/v1/audit?kind=enrolment' $token -Body | ConvertFrom-Json
		foreach ($name in $nodeA, $nodeB) {
			$rec = @($audit.records | Where-Object { $_.actor -eq "node:$name" -and $_.outcome -eq 'success' })
			if ($rec.Count -ne 1 -or $rec[0].message -notmatch 'first control stream' -or $rec[0].source -notmatch [regex]::Escape($values['PC-A'])) { throw "the audit log has no enrolment of $name from $($values['PC-A']): $($audit | ConvertTo-Json -Compress -Depth 4)" }
		}
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

	Gap 'gap-node-service' {
		# The document says what is missing. The sources must still say so, or the Gap is closed. Gaps 2, 6 and 7 are not
		# read from the sources: nothing in them says that a verb or a setting is missing.
		$controls = (Test-Source 'src\Cedar' 'Node*.c' '\.Control\s*=') -or (Test-Source 'src\ranz-node' '*.c' '\.Control\s*=')
		Assert-Gap 'Gap 1' (-not $controls) 'no code of the Node service sets the control stream of its overlay (NODE_OVERLAY_CONFIG.Control): only the vpntest harness does'
		$listens = (Test-Source 'src\Cedar' 'Node*.c' 'TransportTlsServerNew|TransportQuicServerNew|FrontDoorStart') -or (Test-Source 'src\ranz-node' '*.c' 'TransportTlsServerNew|TransportQuicServerNew|FrontDoorStart')
		Assert-Gap 'Gap 3' (-not $listens) 'the Node service starts no QUIC listener, no TLS listener and no front door'
		Assert-Gap 'Gap 4' (-not (Test-Source 'controller\internal\install' '*.go' '(?i)firewall')) 'ranz install knows no firewall'
		Assert-Gap 'Gap 5' (-not (Test-Source 'controller\cmd\ranz' '*.go' '(?i)audit')) 'the ranz CLI has no verb for the audit log'
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
		$events = @((Invoke-Ranz @('get', 'events')).events | Where-Object { $_ })
		if ($events.Count -ne 0) { throw "the Controller has events: $($events | ConvertTo-Json -Compress -Depth 4)" }
		$revisions = ((Invoke-Ranz @('get', 'revisions')).revisions | ForEach-Object { $_.operation }) -join ','
		if ($revisions -ne 'first-start,apply') { throw "the revisions are $revisions, not the first start and the apply" }
		# The bundle of the Controller, the one that the button of the Diagnostics page downloads
		$admin = (Get-Content -LiteralPath $adminToken -Raw).Trim()
		$secrets = @($admin, $values['VIEWER-TOKEN'])
		Assert-Bundle (Join-Path $work 'bundle-controller.zip') @('manifest.json', 'system.json', 'services.json', 'controller/status.json', 'controller/nodes.json', 'controller/intent.json', 'controller/revisions.json', 'controller/events.json', 'controller/licence.json', 'controller/ipam.json', 'controller/logs.json', 'controller/logs/controller.log') @() $secrets
		# The pull is in the audit log: an operation of the admin token, with the call as its action (the Controller writes
		# the record when the call ends, a moment after curl has the file)
		$null = Wait-Until {
			$audit = Invoke-Curl 'https://localhost/api/v1/audit?kind=operation' $admin -Body | ConvertFrom-Json
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
		$null = Wait-Until {
			$nodes = @((Invoke-Ranz @('get', 'nodes') -token $viewerToken -server "https://$($values['CONTROLLER'])" -fingerprint $values['FINGERPRINT']).nodes)
			$nodes.Count -eq 2 -and @($nodes | Where-Object { $_.connected }).Count -eq 0
		} 'the Controller to see both Nodes as not connected' 30
	}

	Step 'uninstall' {
		$null = Invoke-Doc
		foreach ($name in $nodeService, $controllerService) { Wait-ServiceGone $name }
		if (Test-Path -LiteralPath $installDir) { throw "ranz uninstall left $installDir" }
		if (-not (Test-Path -LiteralPath $adminToken)) { throw 'ranz uninstall removed the data directory of the Controller, which it keeps' }
		if (-not (Test-Path -LiteralPath (Join-Path $nodeData 'ranz_node.db'))) { throw 'ranz uninstall removed the Configuration store of the Node, which it keeps' }
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
		if (Get-NetFirewallRule -DisplayName $firewallRule -ErrorAction SilentlyContinue) { throw 'the firewall rule is still there' }
		if (@(Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like 'CN=Ranz VPN CI signing*' }).Count -ne 0) { throw 'the CI certificate is still trusted' }
		foreach ($dir in (Join-Path $env:ProgramData 'Ranz'), $nodeData) {
			if (Test-Path -LiteralPath $dir) { throw "$dir is still there" }
		}
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
