# The QTIP step of the XDP job (CORE-S7-2, #83; ADR-0018 decisions 2 and 5; seam 3 of #45 as the ADR-0002 amendment of
# 2026-10-21 has it: two node processes on one runner, each on its own KM-TEST adapter), on Windows Server 2022 and 2025
# x64, after the step of the L2 adapter (kmtest.ps1), with the XDP runtime that the signed ranz.exe installs and the
# msquic.dll of the pinned package next to vpntest:
# 1. ranz install. vpntest qtip in one process: the rule (Windows Server x64 only), the msquic release that ships QTIP,
#    default off, opt-in and the normal datapath as before, a QTIP listener on 8443 that holds both the TCP and the UDP
#    port and takes plain QUIC too, and the QuicXdp and Qtip settings of a node, here with the XDP runtime.
# 2. Two server node processes. node-s (vpntest qtip serve STOPFILE) brings up its own KM-TEST adapter with XDP and its
#    Listener with QTIP on 8443, and prints READY with the thumbprint of its certificate; from outside, Get-NetTCPConnection
#    and Get-NetUDPEndpoint must show TCP 8443 and UDP 8443 held by its process. node-c (vpntest qtip dial THUMBPRINT) brings
#    up its own KM-TEST adapter with XDP, finds both ports held from its process, opens a session of plain QUIC to the
#    QTIP port of node-s, and dials node-s over QTIP between the two adapters. Whether that link came up goes to the job
#    summary as a record, not a check: a KM-TEST adapter sends nowhere what XDP injects for it to transmit, so with no wire
#    between the two adapters of a hosted runner the QUIC-over-TCP-header link cannot come up, which the pull request of
#    #83 reports as a criterion not met.
# 3. ranz uninstall.
# Each run of vpntest is a process of its own with a time limit.
param(
	[Parameter(Mandatory = $true)]
	[string] $Ranz,
	[Parameter(Mandatory = $true)]
	[string] $Vpntest,
	[string] $Runner = ''
)

$ErrorActionPreference = 'Stop'
# Native exit codes are checked by hand below
$PSNativeCommandUseErrorActionPreference = $false

$ranzExe = (Resolve-Path -LiteralPath $Ranz).Path
$vpntestExe = (Resolve-Path -LiteralPath $Vpntest).Path
# TRANSPORT_QUIC_QTIP_PORT of src/Core/Transport.h
$port = 8443
$firewallRule = 'ranz-qtip'
$script:failures = @()
$script:runs = 0

# A step that failed: the job goes on with the next one and fails at the end
function Add-Failure([string] $step) {
	$script:failures += $step
	Write-Host "::error::$step"
}

# Run ranz.exe with arguments: its exit code and its output, standard error included
function Invoke-Ranz([string[]] $argv) {
	$out = (& $ranzExe @argv 2>&1 | Out-String)
	$code = $LASTEXITCODE
	Write-Host "ranz $($argv -join ' '): exit $code`n$out"
	return [pscustomobject]@{ Code = $code; Out = $out }
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

# Start vpntest qtip with arguments as a process of its own: the process and the files of its output
function Start-Qtip([string[]] $argv) {
	$script:runs++
	$out = Join-Path $env:RUNNER_TEMP "qtip-$($script:runs).out"
	$err = Join-Path $env:RUNNER_TEMP "qtip-$($script:runs).err"
	Write-Host "vpntest qtip $($argv -join ' ')"
	$p = Start-Process -FilePath $vpntestExe -ArgumentList (@('qtip') + $argv) -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError $err
	# The handle keeps the exit code of the process
	$null = $p.Handle
	return [pscustomobject]@{ Process = $p; Out = $out; Err = $err }
}

# Wait for a run to end, $minutes at most, and give its output; it passed when it printed its OK marker and no leak, and
# ended, and did not skip for a missing msquic.dll
function Wait-Qtip($run, [int] $minutes) {
	$ended = $run.Process.WaitForExit($minutes * 60000)
	if (-not $ended) {
		Stop-Process -Id $run.Process.Id -Force -ErrorAction SilentlyContinue
		$ended = $run.Process.WaitForExit(30000)
		Write-Host "::error::vpntest qtip did not end within $minutes minutes: stopped$(if (-not $ended) { ', and it does not end' })"
	}
	$text = (Read-Shared $run.Out) + (Read-Shared $run.Err)
	Write-Host $text
	$skipped = $text -match 'the test is skipped'
	if ($skipped) { Write-Host '::error::vpntest qtip skipped: msquic.dll is not next to vpntest' }
	$ok = $text -match '(?m)^QTIP TEST OK' -and $text -match 'NO MEMORY LEAKS' -and -not $skipped
	return [pscustomobject]@{ Ok = ($ok -and $ended); Text = $text }
}

$os = Get-CimInstance Win32_OperatingSystem
Write-Host "$($os.Caption), build $($os.BuildNumber), on the runner $Runner, $([Environment]::ProcessorCount) processors"
if (-not (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $vpntestExe) 'msquic.dll'))) { Add-Failure 'msquic.dll is not next to vpntest' }

# The node processes take sessions on their ports: an inbound rule for vpntest, as a product that listens has its own
New-NetFirewallRule -DisplayName $firewallRule -Direction Inbound -Program $vpntestExe -Action Allow -Profile Any | Out-Null

# 1. The XDP runtime, then the checks of one process
$r = Invoke-Ranz @('install')
if ($r.Code -ne 0) { Add-Failure "ranz install exited with code $($r.Code)" }
$one = Wait-Qtip (Start-Qtip @()) 5
if (-not $one.Ok) { Add-Failure 'vpntest qtip in one process' }
if ($one.Text -notmatch 'the XDP runtime of ranz install is installed') { Add-Failure 'vpntest qtip did not find the XDP runtime that ranz install put on the runner' }

# 2. Two server node processes, each on its own KM-TEST adapter with XDP
$stop = Join-Path $env:RUNNER_TEMP 'qtip-serve.stop'
Remove-Item -LiteralPath $stop -Force -ErrorAction SilentlyContinue
$serve = Start-Qtip @('serve', $stop)
$thumbprint = $null
$deadline = (Get-Date).AddMinutes(3)
while ((Get-Date) -lt $deadline -and -not $serve.Process.HasExited) {
	$m = [regex]::Match((Read-Shared $serve.Out), '(?m)^QTIP SERVE READY ([0-9A-Fa-f]{40})')
	if ($m.Success) {
		$thumbprint = $m.Groups[1].Value
		break
	}
	Start-Sleep -Milliseconds 500
}

if (-not $thumbprint) {
	Add-Failure 'node-s did not say QTIP SERVE READY'
} else {
	# From outside: the QTIP listener of node-s holds both the TCP and the UDP port (msquic binds the TCP one without listening)
	$id = $serve.Process.Id
	$tcp = @(Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -eq $id })
	$udp = @(Get-NetUDPEndpoint -LocalPort $port -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -eq $id })
	Write-Host "node-s (process $id) holds TCP $port in $($tcp.Count) socket(s) ($(@($tcp | ForEach-Object { "$($_.LocalAddress) $($_.State)" }) -join '; ')) and UDP $port in $($udp.Count) ($(@($udp | ForEach-Object { $_.LocalAddress }) -join '; '))"
	if ($tcp.Count -lt 1) { Add-Failure "the QTIP listener of node-s holds no TCP $port" }
	if ($udp.Count -lt 1) { Add-Failure "the QTIP listener of node-s holds no UDP $port" }

	$dial = Wait-Qtip (Start-Qtip @('dial', $thumbprint)) 5
	if (-not $dial.Ok) { Add-Failure 'vpntest qtip dial: node-c' }
	$link = [regex]::Match($dial.Text, '(?m)^QTIP LINK (UP|DOWN).*$')
	$record = $(if ($link.Success) { $link.Value.Trim() } else { 'QTIP LINK: node-c printed no line of the link' })
	Write-Host $record
	if ($env:GITHUB_STEP_SUMMARY) {
		"QTIP between two server node processes on $Runner, each on its own KM-TEST adapter with XDP: $record" | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Encoding utf8 -Append
	}
}

New-Item -ItemType File -Force -Path $stop | Out-Null
$served = Wait-Qtip $serve 3
if (-not $served.Ok) { Add-Failure 'vpntest qtip serve: node-s' }

# 3. The drivers go again
$r = Invoke-Ranz @('uninstall')
if ($r.Code -ne 0 -and $r.Code -ne 3010) { Add-Failure "ranz uninstall exited with code $($r.Code)" }

Remove-NetFirewallRule -DisplayName $firewallRule -ErrorAction SilentlyContinue

if ($script:failures.Count -gt 0) {
	throw "qtip: $($script:failures.Count) step(s) failed: $($script:failures -join '; ')"
}
Write-Host 'qtip: every step passed'
