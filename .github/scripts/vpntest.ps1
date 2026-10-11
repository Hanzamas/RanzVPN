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

# Named self-tests: must print their OK marker and no leak
('mschapv2', 'stun') | % {

	[String] $test = $_
	Write-Host "testing: $test"

	$full = (Write-Output "q\n" | & "$BUILD_BINARIESDIRECTORY\vpntest.exe" $test)
	$ok = ($full | Select-String -Pattern ($test.ToUpper() + ' TEST OK') -CaseSensitive)
	$leak = ($full | Select-String -Pattern 'NO MEMORY LEAKS' -CaseSensitive)

	if (($ok).Count -ne 1 -or ($leak).Count -ne 1) {
		$full
		Write-Error 'failed'
		return $false
	} else {
		Write-Host 'ok'
	}
}
