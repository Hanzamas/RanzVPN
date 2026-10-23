param([string] $BuildDir = 'build')

$ErrorActionPreference = 'Stop'

# Benchmark results: every "BENCH ..." line of the named tests is printed, also when the test passes, and
# saved to harness-out\bench-<arch>.txt (uploaded with the harness-out artifact). This script does not judge
# them; the performance regression gate of windows.yml (.github/scripts/bench-gate.py, ADR-0040 item 5)
# compares the files with the recorded medians. ARCHITECTURE (x64, arm64) names the file; without it the
# architecture of the machine does. RANZ_BENCH_RUNS (default 1) is how many times in all a test that prints
# BENCH lines runs: run n goes to bench-<arch>-run<n>.txt, run 1 to bench-<arch>.txt, and the gate takes the
# best run of each case, so one run that a busy machine slowed does not fail it.
if ($env:ARCHITECTURE) {
	$benchArch = $env:ARCHITECTURE
} elseif ($env:PROCESSOR_ARCHITEW6432) {
	$benchArch = $env:PROCESSOR_ARCHITEW6432
} else {
	$benchArch = $env:PROCESSOR_ARCHITECTURE
}
switch ($benchArch) {
	'AMD64' { $benchArch = 'x64' }
	'ARM64' { $benchArch = 'arm64' }
}
if (-not $benchArch) { $benchArch = 'unknown' }
$benchArch = $benchArch.ToLower()
$benchDir = Join-Path $BuildDir 'harness-out'
$benchRuns = 1
if ($env:RANZ_BENCH_RUNS) { $benchRuns = [int] $env:RANZ_BENCH_RUNS }
# The files of an earlier run of the script are no results of this one
Get-ChildItem -Path $benchDir -Filter "bench-$benchArch*.txt" -ErrorAction SilentlyContinue | Remove-Item

# Start/stop smoke test: server mode must exit without leaks
('s') | % {

	[String] $mode = $_
	Write-Host "testing: $mode"

	$full = (Write-Output "q\n" | & "$BuildDir\vpntest.exe" $mode)
	$t = ($full | Select-String -Pattern 'NO MEMORY LEAKS' -CaseSensitive)

	if (($t).Count -ne 1) {
		$full
		Write-Error 'failed'
		return $false
	} else {
		Write-Host 'ok'
	}
}

# The tests: vpntest prints its own list ("vpntest list": one "TESTLIST <name> <tags>" line per test, <tags> comma-separated
# or - for none). A test registers itself with RANZ_TEST in its own file (src/vpntest/testlist.h), so a new test needs no
# line in this script, the harness or CMake.
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$registered = [ordered]@{}
$listing = @(& "$BuildDir\vpntest.exe" list)
foreach ($line in $listing) {
	if ($line -cmatch '^TESTLIST (\S+) (\S+)\s*$') {
		$name = $Matches[1]
		if ($registered.Contains($name)) { Write-Error "vpntest lists the test $name twice" }
		if ($Matches[2] -eq '-') { $registered[$name] = @() } else { $registered[$name] = @($Matches[2] -split ',') }
	}
}
if ($registered.Count -eq 0) {
	$listing | % { Write-Host $_ }
	Write-Error 'vpntest list printed no test'
}

# A registration that the linker did not collect would be a test that never runs: every RANZ_TEST of the sources must be in the list
$sources = Join-Path $repo 'src\vpntest'
if (Test-Path -LiteralPath $sources) {
	$declared = @(Get-ChildItem -LiteralPath $sources -Filter '*.c' | Select-String -CaseSensitive -Pattern '^RANZ_TEST(?:_TAGS)?\(\s*"([^"]+)"' | % { $_.Matches[0].Groups[1].Value })
	$dropped = @($declared | ? { -not $registered.Contains($_) })
	if ($dropped.Count -gt 0) {
		Write-Error ('src/vpntest registers ' + ($dropped -join ', ') + ', which vpntest does not list')
	}
}

# .github/quality/<kind>-exclude.txt: "<name> <reason>" per line, a line that starts with # is a comment. Returns the names.
function Read-ExcludeFile([string] $kind) {
	$path = Join-Path $repo ".github\quality\$kind-exclude.txt"
	if (-not (Test-Path -LiteralPath $path)) { Write-Error "$path does not exist" }
	$names = @()
	$number = 0
	foreach ($line in Get-Content -LiteralPath $path) {
		$number++
		$text = $line.Trim()
		if (-not $text -or $text.StartsWith('#')) { continue }
		$fields = $text -split '\s+', 2
		if ($fields.Count -lt 2) { Write-Error "${path}:${number}: '$text' has no reason: <name> <reason>" }
		if (-not $registered.Contains($fields[0])) { Write-Error "${path}:${number}: $($fields[0]) is not a test that vpntest lists" }
		$names += $fields[0]
	}
	return $names
}

# Named self-tests: must print their OK marker and no leak. Every test that vpntest lists runs, in alphabetical order,
# except the ones in smoke-exclude.txt. RANZ_SMOKE_TESTS (comma list) overrides the list; RANZ_SMOKE_TAG keeps the tests
# with that tag (core: the tests of the new core, which the coverage job runs); RANZ_SMOKE_EXCLUDE (comma list) names
# more exclude files (asan: asan-exclude.txt, which the fuzz-asan job leaves out).
$excluded = @(Read-ExcludeFile 'smoke')
if ($env:RANZ_SMOKE_EXCLUDE) {
	foreach ($kind in @($env:RANZ_SMOKE_EXCLUDE -split ',' | % { $_.Trim() } | ? { $_ })) { $excluded += Read-ExcludeFile $kind }
}
if ($env:RANZ_SMOKE_TESTS) {
	$named = @($env:RANZ_SMOKE_TESTS -split ',' | % { $_.Trim() } | ? { $_ })
	$unknown = @($named | ? { -not $registered.Contains($_) })
	if ($unknown.Count -gt 0) { Write-Error ('RANZ_SMOKE_TESTS names ' + ($unknown -join ', ') + ', which vpntest does not list') }
} else {
	$tag = ''
	if ($env:RANZ_SMOKE_TAG) { $tag = $env:RANZ_SMOKE_TAG.Trim() }
	$named = @($registered.Keys | Sort-Object | ? { ($excluded -notcontains $_) -and (-not $tag -or ($registered[$_] -contains $tag)) })
	if ($named.Count -eq 0) { Write-Error "no test to run (the tag is '$tag')" }
}

# Runs one test and checks it: its OK marker once, no leak, no golden file recorded in place of a comparison. The BENCH
# lines of run number $run go to the bench file of that run; $script:printedBench says whether there were any.
function Invoke-SmokeTest([string] $test, [int] $run) {
	if ($run -gt 1) { Write-Host "testing: $test (run $run of $benchRuns)" } else { Write-Host "testing: $test" }

	$full = (Write-Output "q\n" | & "$BuildDir\vpntest.exe" $test)
	$exit = $LASTEXITCODE

	# Benchmark lines before the result check, so a failed test still shows and saves them
	$bench = @($full | ? { $_ -cmatch '^BENCH ' -and $_ -cnotmatch '^BENCH TEST ' })
	$script:printedBench = ($bench.Count -gt 0)
	if ($bench.Count -gt 0) {
		Write-Host "benchmark results of ${test}:"
		$bench | % { Write-Host $_ }
		New-Item -ItemType Directory -Force -Path $benchDir | Out-Null
		if ($run -gt 1) { $benchFile = Join-Path $benchDir "bench-$benchArch-run$run.txt" } else { $benchFile = Join-Path $benchDir "bench-$benchArch.txt" }
		Add-Content -Path $benchFile -Value $bench -Encoding Ascii
	}

	$ok = ($full | Select-String -Pattern ($test.ToUpper() + ' TEST OK') -CaseSensitive)
	$leak = ($full | Select-String -Pattern 'NO MEMORY LEAKS' -CaseSensitive)

	if (($ok).Count -ne 1 -or ($leak).Count -ne 1) {
		$full | % { Write-Host $_ }
		Write-Host ('vpntest exit code of ' + $test + ': ' + $exit + ' (0x' + ('{0:X8}' -f $exit) + ')')
		Write-Error 'failed'
	}

	# A test must compare its golden files: a missing or empty golden directory switches a family to update mode, which
	# passes without comparing. A test that does that prints "<FAMILY> GOLDEN MODE update" (or "<FAMILY> GOLDEN MODE
	# <part> update"). RANZ_UPDATE_GOLDEN=1 is the deliberate way to record new files.
	if ($env:RANZ_UPDATE_GOLDEN -ne '1') {
		$updating = @($full | ? { $_ -cmatch ' GOLDEN MODE (?:\S+ )?update\s*$' })
		if ($updating.Count -gt 0) {
			$full | % { Write-Host $_ }
			Write-Error ("$test recorded golden files in place of comparing them ('" + (($updating | % { $_.Trim() }) -join "', '") + "'). A deliberate update runs with RANZ_UPDATE_GOLDEN=1")
		}
	}

	Write-Host 'ok'
}

foreach ($test in $named) {
	Invoke-SmokeTest $test 1
	if ($script:printedBench) {
		for ($run = 2; $run -le $benchRuns; $run++) { Invoke-SmokeTest $test $run }
	}
}
