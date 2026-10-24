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

Section 'gofmt, as the Linux job of ranz.yml runs it'
& gofmt -l controller ranz-bgp 2>&1 | ForEach-Object { Write-Host "needs gofmt: $_" }
& gofmt -d controller/internal/payload controller/internal/install 2>&1 | ForEach-Object { Write-Host $_ }
Write-Host 'gofmt done'

Section 'go vet for the three targets of the module'
& go vet ./... 2>&1 | ForEach-Object { Write-Host $_ }
Write-Host "vet for Windows x64: exit code $LASTEXITCODE"
$env:GOARCH = 'arm64'
& go vet ./... 2>&1 | ForEach-Object { Write-Host $_ }
Write-Host "vet for Windows arm64: exit code $LASTEXITCODE"
Remove-Item Env:\GOARCH
$env:GOOS = 'linux'
& go vet ./... 2>&1 | ForEach-Object { Write-Host $_ }
Write-Host "vet for Linux: exit code $LASTEXITCODE"
Remove-Item Env:\GOOS

Section 'staticcheck v0.8.2 of the two packages, for Windows and for Linux'
$env:GOBIN = Join-Path $env:RUNNER_TEMP 'gobin'
& go install 'honnef.co/go/tools/cmd/staticcheck@v0.8.2' 2>&1 | ForEach-Object { Write-Host $_ }
Remove-Item Env:\GOBIN
$staticcheck = Join-Path $env:RUNNER_TEMP 'gobin\staticcheck.exe'
& $staticcheck ./controller/internal/payload/... ./controller/internal/install/... 2>&1 | ForEach-Object { Write-Host $_ }
Write-Host "staticcheck for Windows: exit code $LASTEXITCODE"
$env:GOOS = 'linux'
& $staticcheck ./controller/internal/payload/... ./controller/internal/install/... 2>&1 | ForEach-Object { Write-Host $_ }
Write-Host "staticcheck for Linux: exit code $LASTEXITCODE"
Remove-Item Env:\GOOS

Section 'go test of controller/internal/payload'
& go test ./controller/internal/payload -count=1 -v 2>&1 | ForEach-Object { Write-Host $_ }
Write-Host "go test: exit code $LASTEXITCODE"

Section 'the drivers, as ranz install puts them on the machine and ranz uninstall takes them off'
$env:DIAG_INSTALL = '1'
& go test ./controller/internal/install -run 'TestDiagInstallDrivers' -count=1 -v 2>&1 | ForEach-Object { Write-Host $_ }
Write-Host "go test: exit code $LASTEXITCODE"
