$ErrorActionPreference = 'Stop'

if (Test-Path "env:BUILD_BINARIESDIRECTORY") {
	$BUILD_BINARIESDIRECTORY = $env:BUILD_BINARIESDIRECTORY
} else {
	$BUILD_BINARIESDIRECTORY = "build"
}

# Benchmark results: every "BENCH ..." line of the named tests is printed, also when the test passes, and
# saved to harness-out\bench-<arch>.txt (uploaded with the harness-out artifact). Informational, never a gate.
# ARCHITECTURE (x64, arm64) names the file; without it the architecture of the machine does.
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
$benchDir = Join-Path $BUILD_BINARIESDIRECTORY 'harness-out'
$benchFile = Join-Path $benchDir ('bench-' + $benchArch.ToLower() + '.txt')
if (Test-Path $benchFile) { Remove-Item $benchFile }

# Start/stop smoke test: server mode must exit without leaks
('s') | % {

	[String] $mode = $_
	Write-Host "testing: $mode"

	$full = (Write-Output "q\n" | & "$BUILD_BINARIESDIRECTORY\vpntest.exe" $mode)
	$t = ($full | Select-String -Pattern 'NO MEMORY LEAKS' -CaseSensitive)

	if (($t).Count -ne 1) {
		$full
		Write-Error 'failed'
		return $false
	} else {
		Write-Host 'ok'
	}
}

# Named self-tests: must print their OK marker and no leak. RANZ_SMOKE_TESTS (comma list) overrides the list.
$named = @('mschapv2', 'stun', 'watermark', 'stress', 'harness', 'bench', 'tickorigin', 'timeenc', 'nullsafe', 'fileio', 'threadpool', 'dns', 'trace', 'eventlog', 'certdl')
if ($env:RANZ_SMOKE_TESTS) { $named = $env:RANZ_SMOKE_TESTS -split ',' | % { $_.Trim() } | ? { $_ } }
$named | % {

	[String] $test = $_
	Write-Host "testing: $test"

	$full = (Write-Output "q\n" | & "$BUILD_BINARIESDIRECTORY\vpntest.exe" $test)

	# Benchmark lines before the result check, so a failed test still shows and saves them
	$bench = @($full | ? { $_ -cmatch '^BENCH ' -and $_ -cnotmatch '^BENCH TEST ' })
	if ($bench.Count -gt 0) {
		Write-Host "benchmark results of ${test}:"
		$bench | % { Write-Host $_ }
		New-Item -ItemType Directory -Force -Path $benchDir | Out-Null
		Add-Content -Path $benchFile -Value $bench -Encoding Ascii
	}

	$ok = ($full | Select-String -Pattern ($test.ToUpper() + ' TEST OK') -CaseSensitive)
	$leak = ($full | Select-String -Pattern 'NO MEMORY LEAKS' -CaseSensitive)

	if (($ok).Count -ne 1 -or ($leak).Count -ne 1) {
		$full
		Write-Error 'failed'
		return $false
	}

	# The harness must compare its golden files: a missing or empty golden directory switches a family to update
	# mode, which passes without comparing. RANZ_UPDATE_GOLDEN=1 is the deliberate way to record new files.
	if ($test -eq 'harness' -and $env:RANZ_UPDATE_GOLDEN -ne '1') {
		$missing = @('HARNESS GOLDEN MODE compare', 'HARNESS GOLDEN MODE pack compare') | ? {
			($full | Select-String -Pattern $_ -SimpleMatch -CaseSensitive).Count -ne 1
		}
		if ($missing) {
			$full
			Write-Error ("harness golden files not compared (missing: '" + ($missing -join "', '") + "')")
			return $false
		}
	}

	Write-Host 'ok'
}
