param([string] $BuildDir = 'build')

$ErrorActionPreference = 'Stop'
# A failing test must not stop the script before its output is printed
$PSNativeCommandUseErrorActionPreference = $false

# The named tests of coretest (src/coretest), the known-answer and certificate tests of the new
# core's crypto module (CORE-F1, #61). Each must print "<TEST> TEST OK" and exit with 0; its output
# is printed in full either way, so the job log shows every vector on x64 and arm64.
# RANZ_CORE_TESTS (comma list) overrides the list.
$named = @('rand', 'sha256', 'hmac', 'hkdf', 'aesgcm', 'x25519', 'identity', 'mlkem', 'selfsign', 'pfx', 'certstore', 'schannel')
if ($env:RANZ_CORE_TESTS) { $named = $env:RANZ_CORE_TESTS -split ',' | % { $_.Trim() } | ? { $_ } }

$failed = @()
foreach ($test in $named) {
	Write-Host "testing: $test"

	$full = (& "$BuildDir\coretest.exe" $test | Out-String)
	$code = $LASTEXITCODE
	Write-Host $full

	$ok = ($full -cmatch ('(?m)^' + $test.ToUpper() + ' TEST OK\r?$'))
	if (-not $ok -or $code -ne 0) {
		$failed += $test
	}
}

if ($failed.Count -gt 0) {
	Write-Error ("coretest failed: " + ($failed -join ', '))
}
