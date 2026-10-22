param([string] $BuildDir = 'build')

$ErrorActionPreference = 'Stop'
# A failing test must not stop the script before its output is printed
$PSNativeCommandUseErrorActionPreference = $false

# The named tests of coretest (src/coretest): the known-answer and certificate tests of the new
# core's crypto module (CORE-F1, #61), the tests of its session module (CORE-F2, #62), whose
# interop test needs ranz-noisepeer.exe (controller/cmd/ranz-noisepeer) next to coretest.exe, and
# the tests of its peer module and relay role (CORE-S5-2, #78), and of its ICE and the port mapping
# of home gateways (CORE-S5-3, #79), which wait for libjuice's consent and check timers (about
# 90 s). Each must print "<TEST> TEST OK" and exit with 0; its output is printed in full either
# way, so the job log shows every vector on x64 and arm64. RANZ_CORE_TESTS (comma list) overrides
# the list.
$named = @('rand', 'sha256', 'hmac', 'hkdf', 'aesgcm', 'x25519', 'identity', 'mlkem', 'selfsign', 'pfx', 'certstore', 'schannel',
	'noise', 'noisehfs', 'noisesession', 'noisetunnel', 'noiseinterop', 'envelope', 'relay', 'relaypolicy', 'iceupgrade', 'icesymmetric')
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
