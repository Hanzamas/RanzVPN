$ErrorActionPreference = 'Stop'

# ETW trace check (ticket #92). Debug() hands its messages to the TraceLogging provider of
# src/Mayaqua/Trace.c only while an ETW trace session listens, and prints only while debug output
# is on, with or without a session. Two runs of "vpntest trace" (src/vpntest/runtime.c):
#   1. without a session: the test expects the provider to be off;
#   2. as "trace listening" inside a logman session on the provider: the test expects it to be on,
#      and the session's .etl file must hold both probe messages of the test.
# Each run must print the probe sent with debug output on, not the one sent with it off, and end
# with "TRACE TEST OK" and "NO MEMORY LEAKS". The .etl file stays in harness-out.

if (Test-Path "env:BUILD_BINARIESDIRECTORY") {
	$BUILD_BINARIESDIRECTORY = $env:BUILD_BINARIESDIRECTORY
} else {
	$BUILD_BINARIESDIRECTORY = "build"
}

# Provider of TRACELOGGING_DEFINE_PROVIDER in src/Mayaqua/Trace.c: the GUID is the EventSource
# hash of its name "Ranz.VPN"
$providerGuid = '{75b1770a-b78d-5167-6ab6-c837a52a76a2}'
$session = 'RanzVpnTraceCheck'

# Probe messages of trace_test (RT_TRACE_PROBE_FMT, RT_TRACE_PROBE_NUM)
$probeOn = 'RANZ TRACE PROBE 92 debug-on'
$probeOff = 'RANZ TRACE PROBE 92 debug-off'

$outDir = Join-Path $BUILD_BINARIESDIRECTORY 'harness-out'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$etl = Join-Path (Resolve-Path $outDir).Path 'trace.etl'
if (Test-Path $etl) { Remove-Item $etl }

# Number of output lines that hold the text
function Get-LineCount([string[]] $lines, [string] $text) {
	@($lines | Select-String -Pattern $text -SimpleMatch -CaseSensitive).Count
}

function Invoke-TraceTest([string[]] $testArgs) {
	$name = 'vpntest ' + ($testArgs -join ' ')
	Write-Host "testing: $name"

	$full = @(Write-Output "q\n" | & "$BUILD_BINARIESDIRECTORY\vpntest.exe" @testArgs)

	$failed = @()
	if ((Get-LineCount $full 'TRACE TEST OK') -ne 1) { $failed += "no 'TRACE TEST OK'" }
	if ((Get-LineCount $full 'NO MEMORY LEAKS') -ne 1) { $failed += "no 'NO MEMORY LEAKS'" }
	if ((Get-LineCount $full $probeOn) -ne 1) { $failed += "'$probeOn' is not printed once" }
	if ((Get-LineCount $full $probeOff) -ne 0) { $failed += "'$probeOff' is printed, with debug output off" }

	if ($failed.Count -gt 0) {
		$full | ForEach-Object { Write-Host $_ }
		throw ("${name}: " + ($failed -join '; '))
	}
	Write-Host 'ok'
}

# 1. No trace session
Invoke-TraceTest @('trace')

# 2. A trace session on the provider: every keyword, every level. The hex values are quoted, or
# PowerShell would pass them on as decimal numbers (0xffffffffffffffff as -1).
& logman start $session -p $providerGuid '0xffffffffffffffff' '0xff' -o $etl -ets
if ($LASTEXITCODE -ne 0) { throw "logman could not start the trace session (exit code $LASTEXITCODE)" }
try {
	Invoke-TraceTest @('trace', 'listening')
} finally {
	& logman stop $session -ets
	$stopCode = $LASTEXITCODE
}
if ($stopCode -ne 0) { throw "logman could not stop the trace session (exit code $stopCode)" }

# logman may add a suffix to the file name
if (-not (Test-Path $etl)) {
	$written = Get-ChildItem -Path $outDir -Filter 'trace*.etl' | Sort-Object LastWriteTime | Select-Object -Last 1
	if (-not $written) { throw "the trace session wrote no .etl file in $outDir" }
	$etl = $written.FullName
}

# The probes are UTF-16LE strings in the event payload (TraceLoggingWideString). A payload string
# need not start at an even offset of the file, so the file is decoded from both offsets.
$bytes = [System.IO.File]::ReadAllBytes($etl)
Write-Host "trace session file: $etl ($($bytes.Length) bytes)"
$texts = @(0, 1) | ForEach-Object {
	$n = $bytes.Length - $_
	[System.Text.Encoding]::Unicode.GetString($bytes, $_, $n - ($n % 2))
}
$missing = @($probeOn, $probeOff) | Where-Object {
	$probe = $_
	@($texts | Where-Object { $_.Contains($probe) }).Count -eq 0
}
if ($missing) {
	throw ("the trace session received no event with '" + ($missing -join "', '") + "'")
}
Write-Host "the trace session received '$probeOn' and '$probeOff'"
