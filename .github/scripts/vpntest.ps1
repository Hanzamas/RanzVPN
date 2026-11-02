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

# The TLS transport (CORE-S2-1 #69) puts its key exchange groups first in the machine's Schannel group list, which an
# ECC Curve Order policy overrides. The runner image sets one (NistP384, NistP256): a CI run takes it off, so the list
# that the transport sets governs, as on a node without that policy. Only on a runner, whose machine goes after the job.
if ($env:GITHUB_ACTIONS -eq 'true') {
	$eccPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
	$eccCurves = (Get-ItemProperty -LiteralPath $eccPolicy -Name 'EccCurves' -ErrorAction SilentlyContinue).EccCurves
	if ($eccCurves) {
		try {
			Remove-ItemProperty -LiteralPath $eccPolicy -Name 'EccCurves' -ErrorAction Stop
			Write-Host ('ECC Curve Order policy of the runner image (' + ($eccCurves -join ', ') + ') taken off for the TLS transport')
		} catch {
			Write-Host ('ECC Curve Order policy of the runner image (' + ($eccCurves -join ', ') + ') could not be taken off: ' + $_)
		}
	}

	# The congestion control of the outer TCP of the TLS transport (the TCP-over-TCP amendment of ADR-0022: BBR2 where
	# Windows offers it). Windows has no choice per socket: each TCP setting template of the machine has its provider.
	# What this runner's templates use, for the record of each CI run, and whether Windows offers BBR2: the
	# InternetCustom template, which no connection uses without a transport filter, takes it and then gets its own back.
	Get-NetTCPSetting -ErrorAction SilentlyContinue | % { Write-Host ('TCP setting template ' + $_.SettingName + ': congestion provider ' + $_.CongestionProvider) }
	$custom = (Get-NetTCPSetting -SettingName InternetCustom -ErrorAction SilentlyContinue).CongestionProvider
	$answer = (netsh int tcp set supplemental template=internetcustom congestionprovider=bbr2 | Out-String).Trim()
	$taken = (Get-NetTCPSetting -SettingName InternetCustom -ErrorAction SilentlyContinue).CongestionProvider
	Write-Host ('BBR2 on this runner: the InternetCustom template took "' + $taken + '" (netsh: ' + $answer + ')')
	if ($custom -and "$taken" -ne "$custom") {
		netsh int tcp set supplemental template=internetcustom congestionprovider=$custom | Out-Null
	}
}

# A test whose output the job log should show besides its result has a script vpntest.d\<test>.ps1 here, which runs
# after the checks with the output of the test in $full and writes what it wants shown, or checks more
$hooksDir = Join-Path $PSScriptRoot 'vpntest.d'

# A test that compares its output with a golden file in place of an oracle must fail when that file changes (CORE-S8-3
# #577), or it would pass on anything. Its hook calls this: the test runs again on a copy of the golden directory of its
# family (RANZ_GOLDEN_DIR names the directory of the family harness, whose siblings are the families) in which the middle
# line of the golden file $file has a planted change, and it must fail, with a failed check that names $file.
function Assert-FailsOnPlantedGolden([string] $test, [string] $family, [string] $file) {
	$plant = Join-Path ([System.IO.Path]::GetTempPath()) "ranz-golden-plant-$test"
	if (Test-Path -LiteralPath $plant) { Remove-Item -LiteralPath $plant -Recurse -Force }
	New-Item -ItemType Directory -Path $plant | Out-Null
	Copy-Item -LiteralPath (Join-Path $repo "tests\golden\$family") -Destination $plant -Recurse
	$path = Join-Path $plant "$family\$file"
	$lines = @(Get-Content -LiteralPath $path)
	if ($lines.Count -eq 0) { Write-Error "${test}: the golden file $family/$file has no line to plant a change in" }
	$line = [int][Math]::Floor($lines.Count / 2)
	$lines[$line] = $lines[$line] + ' (planted)'
	Set-Content -LiteralPath $path -Value $lines

	$goldenDir = $env:RANZ_GOLDEN_DIR
	$env:RANZ_GOLDEN_DIR = Join-Path $plant 'harness'
	try {
		$planted = @(Write-Output "q\n" | & "$BuildDir\vpntest.exe" $test)
	} finally {
		$env:RANZ_GOLDEN_DIR = $goldenDir
		Remove-Item -LiteralPath $plant -Recurse -Force -ErrorAction SilentlyContinue
	}

	$name = $test.ToUpper()
	$passed = @($planted | ? { $_ -cmatch "^$name TEST OK" })
	$failed = @($planted | ? { $_ -cmatch "^$name TEST FAILED" })
	$caught = @($planted | ? { $_ -cmatch '^\s*\[FAIL\] ' -and $_.Contains($file) })
	if ($passed.Count -ne 0 -or $failed.Count -ne 1 -or $caught.Count -eq 0) {
		$planted | % { Write-Host $_ }
		Write-Error "$test did not fail on a planted change of line $($line + 1) of its golden file $family/$file"
	}
	Write-Host "$test fails on a planted change of line $($line + 1) of its golden file $family/${file}: $($caught[0].Trim())"
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

	$hook = Join-Path $hooksDir "$test.ps1"
	if (Test-Path -LiteralPath $hook) { . $hook }

	Write-Host 'ok'
}

foreach ($test in $named) {
	Invoke-SmokeTest $test 1
	if ($script:printedBench) {
		for ($run = 2; $run -le $benchRuns; $run++) { Invoke-SmokeTest $test $run }
	}
}
