$ErrorActionPreference = 'Stop'

if (Test-Path "env:BUILD_BINARIESDIRECTORY") {
	$BUILD_BINARIESDIRECTORY = $env:BUILD_BINARIESDIRECTORY
} else {
	$BUILD_BINARIESDIRECTORY = "build"
}

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
$named = @('mschapv2', 'stun', 'watermark', 'stress', 'harness', 'bench')
if ($env:RANZ_SMOKE_TESTS) { $named = $env:RANZ_SMOKE_TESTS -split ',' | % { $_.Trim() } | ? { $_ } }
$named | % {

	[String] $test = $_
	Write-Host "testing: $test"

	$full = (Write-Output "q\n" | & "$BUILD_BINARIESDIRECTORY\vpntest.exe" $test)
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
