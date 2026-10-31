# run_fuzzers.ps1
# Runs the libFuzzer targets of a RANZ_FUZZ=ON build (cmake/RanzSanitizers.cmake).
#
# For every target:
#   1. replay: every seed of src/fuzz/corpus/<target> once (-runs=0); must exit 0 and print
#      "NO MEMORY LEAKS" (Mayaqua's leak check, run at exit by fuzz_common.c).
#   2. fuzz: -max_total_time=<Seconds> with a fixed -seed; must exit 0. A leak report at the
#      end of this run is printed as a warning only: an input that leaks Mayaqua objects
#      already aborted (FuzzRun() in fuzz_common.c), so this report means a leak that did not
#      repeat on the same input. OpenSSL allocations are not counted by Mayaqua and LeakSanitizer
#      does not exist on Windows: only -rss_limit_mb bounds OpenSSL leaks.
#      Skipped with -Seconds 0, which leaves the deterministic replay only.
# Any AddressSanitizer report, libFuzzer crash, timeout or out-of-memory, a Mayaqua fatal
# error (AbortExitEx, which calls abort() in RANZ_FUZZ builds so libFuzzer saves the input),
# or a leaking input fails the run. Crash and leak inputs land in <BuildDir>/fuzz-artifacts,
# one log per run in <BuildDir>/fuzz-logs.
#
# libFuzzer flags: https://llvm.org/docs/LibFuzzer.html#options
#
# Without -Targets, every fuzz_<name>.c of src/fuzz but fuzz_common.c is a target, built as fuzz_<name>.exe
# (src/fuzz/CMakeLists.txt): a new target is a new file and needs no line here. Its source gives the largest input,
# the -max_len of libFuzzer, in a line "// fuzz-max-len: <bytes>"; the target is not run without one. It may name a
# function that its seeds must reach, in a line "// fuzz-reach: <function>" each: the replay then prints the coverage
# of the seeds (-print_coverage=1), and fails unless libFuzzer lists each such function as covered (COVERED_FUNC). A
# line that starts with "// fuzz-reach:" and names no function stops the run, as it would turn that check off without a
# word; the registry check (.github/scripts/fuzz-registry.py) fails without the lines that a target must have.
#
# Usage: pwsh -File src/fuzz/run_fuzzers.ps1 [-BuildDir build] [-Seconds 60] [-Seed 1] [-Targets fuzz_pack,...]

param(
	[string] $BuildDir = 'build',
	[int] $Seconds = 60,
	[int] $Seed = 1,
	[string[]] $Targets = @()
)

$ErrorActionPreference = 'Stop'

# RANZ_ASAN builds allocate from the CRT heap (cmake/RanzOptions.cmake leaves
# WIN32_USE_HEAP_API_FOR_MEMORY undefined), which AddressSanitizer checks without extra ASAN_OPTIONS.

if ($Targets.Count -eq 0) {
	$Targets = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter 'fuzz_*.c' | Where-Object { $_.BaseName -ne 'fuzz_common' } |
		ForEach-Object { $_.BaseName } | Sort-Object)
	if ($Targets.Count -eq 0) { throw "no fuzz_<name>.c in $PSScriptRoot" }
}

# Largest input per target (-max_len): the "// fuzz-max-len: <bytes>" line of its source
function Get-MaxLen([string] $Target) {
	$source = Join-Path $PSScriptRoot "$Target.c"
	$found = @(Select-String -LiteralPath $source -CaseSensitive -Pattern '^//\s*fuzz-max-len:\s*(\d+)\s*$' | Select-Object -First 1)
	if ($found.Count -eq 0) { throw "$source has no line '// fuzz-max-len: <bytes>'" }
	return [int] $found[0].Matches[0].Groups[1].Value
}

# The functions that the seeds of a target must reach: the "// fuzz-reach: <function>" lines of its source. Every line
# that starts with "// fuzz-reach:" must name one function, or the run stops (CORE-S5-6-R2, #557).
function Get-Reach([string] $Target) {
	$source = Join-Path $PSScriptRoot "$Target.c"
	$functions = @()
	foreach ($line in @(Select-String -LiteralPath $source -CaseSensitive -Pattern '^//\s*fuzz-reach:')) {
		if ($line.Line -cmatch '^//\s*fuzz-reach:\s*(\w+)\s*$') {
			$functions += $Matches[1]
		} else {
			Write-Host "::error::${source}:$($line.LineNumber): '$($line.Line)' is not a line '// fuzz-reach: <function>'"
			exit 1
		}
	}
	return $functions
}

$BuildDir = (Resolve-Path $BuildDir).Path
$CorpusRoot = Join-Path $PSScriptRoot 'corpus'
$WorkRoot = Join-Path $BuildDir 'fuzz-work'
$ArtifactDir = Join-Path $BuildDir 'fuzz-artifacts'
$LogDir = Join-Path $BuildDir 'fuzz-logs'
foreach ($dir in @($WorkRoot, $ArtifactDir, $LogDir)) {
	New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

# Runs one fuzzer process with stdin closed (a leak report waits for Enter otherwise), captures
# stdout (Mayaqua) and stderr (libFuzzer, ASan) into the log, returns the result
function Invoke-Fuzzer([string] $Exe, [string[]] $Arguments, [string] $Log) {
	$psi = New-Object System.Diagnostics.ProcessStartInfo
	$psi.FileName = $Exe
	$psi.Arguments = ($Arguments | ForEach-Object { '"' + $_ + '"' }) -join ' '
	$psi.UseShellExecute = $false
	$psi.RedirectStandardInput = $true
	$psi.RedirectStandardOutput = $true
	$psi.RedirectStandardError = $true
	$psi.WorkingDirectory = $BuildDir

	$proc = [System.Diagnostics.Process]::Start($psi)
	$proc.StandardInput.Close()
	$stdout = $proc.StandardOutput.ReadToEndAsync()
	$stderr = $proc.StandardError.ReadToEndAsync()
	$proc.WaitForExit()

	$text = "> $Exe $($psi.Arguments)`r`n" +
		"===== stderr (libFuzzer, AddressSanitizer) =====`r`n" + $stderr.Result +
		"`r`n===== stdout (Mayaqua) =====`r`n" + $stdout.Result
	Set-Content -Path $Log -Value $text -Encoding UTF8

	return @{ Code = $proc.ExitCode; Text = $text }
}

# Last lines of a run's log (the AddressSanitizer or libFuzzer report and Mayaqua's verdict)
function Write-LogTail($Result) {
	($Result.Text -split "`r?`n" | Select-Object -Last 150) | ForEach-Object { Write-Host $_ }
}

# Problems found in one run, as a list of strings (empty when the run is clean)
function Get-Problems($Result, [bool] $LeaksAreErrors) {
	$problems = @()
	if ($Result.Code -ne 0) { $problems += "exit code $($Result.Code)" }
	if ($Result.Text -match 'ERROR: AddressSanitizer') { $problems += 'AddressSanitizer report' }
	if ($Result.Text -match 'ERROR: libFuzzer') { $problems += 'libFuzzer error' }
	if ($Result.Text -match 'Fatal Error: ') { $problems += 'Mayaqua fatal error (AbortExitEx)' }
	if ($Result.Text -match '==RANZ FUZZ== Mayaqua objects leaked') { $problems += 'an input leaked Mayaqua objects' }
	if ($LeaksAreErrors -and ($Result.Text -notmatch 'NO MEMORY LEAKS')) { $problems += 'no "NO MEMORY LEAKS" verdict' }
	return $problems
}

$failed = @()

foreach ($target in $Targets) {
	$exe = Join-Path $BuildDir "$target.exe"
	$seeds = Join-Path $CorpusRoot $target
	$work = Join-Path $WorkRoot $target
	New-Item -ItemType Directory -Force -Path $work | Out-Null
	if (-not (Test-Path $exe)) { throw "$exe not found (configure with -DRANZ_FUZZ=ON)" }

	$common = @("-max_len=$(Get-MaxLen $target)", '-timeout=25', '-rss_limit_mb=2048',
		('-artifact_prefix=' + (Join-Path $ArtifactDir "$($target)-")))

	# 1. Replay the seed corpus, with the coverage of the seeds when the target names functions that they must reach
	$reach = Get-Reach $target
	$replay = @('-runs=0')
	if ($reach.Count -gt 0) { $replay += '-print_coverage=1' }
	$log = Join-Path $LogDir "$target-replay.log"
	Write-Host "[$target] replay $seeds"
	$result = Invoke-Fuzzer $exe ($common + $replay + @($seeds)) $log
	$problems = Get-Problems $result $true
	foreach ($function in $reach) {
		# libFuzzer prints "COVERED_FUNC: hits: <n> edges: <covered>/<all> <function> <file>:<line>" for a function that a
		# seed reached, and UNCOVERED_FUNC for one that none did
		$covered = @($result.Text -split "`r?`n" | Where-Object { $_ -match ('^COVERED_FUNC: .*\b' + [regex]::Escape($function) + '\b') })
		if ($covered.Count -eq 0) {
			$problems += "no seed reaches $function (fuzz-reach)"
		} else {
			Write-Host "  [$target] the seeds reach ${function}: $($covered[0])"
		}
	}
	if ($problems.Count -ne 0) {
		Write-LogTail $result
		Write-Host "::error::$target replay: $($problems -join ', ')"
		$failed += "$target replay"
		continue
	}

	# 2. Fuzz for a fixed time; new inputs go to the work directory, the seeds stay untouched
	if ($Seconds -le 0) { continue }
	$log = Join-Path $LogDir "$target-fuzz.log"
	Write-Host "[$target] fuzz $Seconds s, seed $Seed"
	$result = Invoke-Fuzzer $exe ($common + @("-max_total_time=$Seconds", "-seed=$Seed",
		'-print_final_stats=1', $work, $seeds)) $log
	$problems = Get-Problems $result $false
	if ($problems.Count -ne 0) {
		Write-LogTail $result
		Write-Host "::error::$target fuzz: $($problems -join ', ')"
		$failed += "$target fuzz"
		continue
	}
	if ($result.Text -notmatch 'NO MEMORY LEAKS') {
		Write-Host "::warning::$target fuzz: Mayaqua reported leaked memory at exit (see $log)"
	}

	# Summary lines of libFuzzer (-print_final_stats=1)
	($result.Text -split "`r?`n") | Where-Object { $_ -match '^(Done |stat::)' } | ForEach-Object { Write-Host "  $_" }
}

if ($failed.Count -ne 0) {
	Write-Host "FAILED: $($failed -join ', ')"
	exit 1
}
Write-Host 'All fuzz targets passed'
