# Temporary (ONE-3, #312): runs, on a windows-latest runner, the tests of controller/internal/payload with the files of the
# pinned XDP runtime written over their placeholders, as the job sign_and_integrity builds ranz.exe, and puts the SeLow
# driver and the XDP runtime on the runner as ranz install does (controller/internal/install), in the situations that
# install.ps1 reads. Removed with its workflow when the checks of fetch-xdp.ps1 and install.ps1 are fixed.
$ErrorActionPreference = 'Continue'
$PSNativeCommandUseErrorActionPreference = $false

function Section([string] $title) {
	Write-Host ''
	Write-Host "===== $title ====="
}

Section 'the package'
.github/scripts/fetch-xdp.ps1 -OutDir (Join-Path $env:RUNNER_TEMP 'xdp-files')
foreach ($name in @('xdp.sys', 'xdpapi.dll', 'xdp.cat', 'xdp.inf', 'xdppcw.man')) {
	Copy-Item -Force -LiteralPath (Join-Path $env:RUNNER_TEMP "xdp-files\$name") -Destination "controller/internal/payload/xdp/$name"
}

Section 'go test of controller/internal/payload'
& go test ./controller/internal/payload -count=1 -v 2>&1 | ForEach-Object { Write-Host $_ }
Write-Host "go test: exit code $LASTEXITCODE"

Section 'the drivers, as ranz install puts them on the machine and ranz uninstall takes them off'
$env:DIAG_INSTALL = '1'
& go test ./controller/internal/install -run 'TestDiagInstallDrivers' -count=1 -v 2>&1 | ForEach-Object { Write-Host $_ }
Write-Host "go test: exit code $LASTEXITCODE"
