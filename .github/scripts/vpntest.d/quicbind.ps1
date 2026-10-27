# Run by vpntest.ps1 after the checks of the quicbind test (CORE-H5 #408), with the output of the test in $full: the cost
# of the binding to the exporter of the QUIC connection against the binding to the certificate goes into the job log
$full | ? { $_ -cmatch '^QUICBIND COST ' } | % { Write-Host $_ }

# The test fails where msquic.dll is missing (CORE-H5-R #443): the same test runs again with the msquic.dll of the build
# hidden, and must say that the DLL is not present and fail, not pass on nothing
$quicDll = Join-Path $BuildDir 'msquic.dll'
$quicHidden = Join-Path $BuildDir 'msquic.dll.hidden'
if (-not (Test-Path -LiteralPath $quicDll)) { Write-Error "quicbind: no msquic.dll in $BuildDir to hide" }
Move-Item -LiteralPath $quicDll -Destination $quicHidden
try {
	$missing = @(Write-Output "q\n" | & "$BuildDir\vpntest.exe" quicbind)
	$missingExit = $LASTEXITCODE
} finally {
	Move-Item -LiteralPath $quicHidden -Destination $quicDll
}

$missingOk = @($missing | Select-String -Pattern 'QUICBIND TEST OK' -SimpleMatch -CaseSensitive).Count
$missingFailed = @($missing | Select-String -Pattern 'QUICBIND TEST FAILED (msquic.dll is not present)' -SimpleMatch -CaseSensitive).Count
if ($missingOk -ne 0 -or $missingFailed -ne 1) {
	$missing | % { Write-Host $_ }
	Write-Error "quicbind without msquic.dll did not fail as it must (exit code $missingExit)"
}
Write-Host "quicbind without msquic.dll: QUICBIND TEST FAILED (msquic.dll is not present), as it must"
