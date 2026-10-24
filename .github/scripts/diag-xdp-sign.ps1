# Temporary (ONE-3, #312): runs, on a windows-latest runner, the catalog check of controller/internal/payload on the files
# of the pinned XDP runtime and of the SeLow package, and the tests of that package. Removed with its workflow when the
# checks of fetch-xdp.ps1 and install.ps1 are fixed.
$ErrorActionPreference = 'Continue'
$PSNativeCommandUseErrorActionPreference = $false

function Section([string] $title) {
	Write-Host ''
	Write-Host "===== $title ====="
}

Section 'the package'
$version = '1.4.0'
$expected = '20f85306846e7bf18bf448cc68aee82ed0c490256d7d94d2bdbf6ac511204a361b1ae7de2642bd0e33235ad8cffa7df0de5efa2185d2c4345dadb527f7ec9172'
$id = 'microsoft.xdp-for-windows.runtime.x64'
$nupkg = Join-Path $env:RUNNER_TEMP "xdp-$version.nupkg"
Invoke-WebRequest -Uri "https://api.nuget.org/v3-flatcontainer/$id/$version/$id.$version.nupkg" -OutFile $nupkg
$hash = (Get-FileHash -Algorithm SHA512 -LiteralPath $nupkg).Hash.ToLower()
Write-Host "SHA-512 $hash, expected ${expected}: $(if ($hash -eq $expected) { 'match' } else { 'MISMATCH' })"
$extract = Join-Path $env:RUNNER_TEMP "xdp-$version-pkg"
if (Test-Path $extract) { Remove-Item -Recurse -Force $extract }
$zip = Join-Path $env:RUNNER_TEMP "xdp-$version.zip"
Copy-Item -LiteralPath $nupkg -Destination $zip -Force
Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force
$env:DIAG_DIR = Join-Path $extract 'runtime\native'

Section 'the catalog check on the files of the packages'
& go test ./controller/internal/payload -run 'TestDiagVerifyEachFile' -count=1 -v 2>&1 | ForEach-Object { Write-Host $_ }

Section 'go vet of controller/internal/payload, for Windows and for Linux'
& go vet ./controller/internal/payload 2>&1 | ForEach-Object { Write-Host $_ }
Write-Host "vet for Windows: exit code $LASTEXITCODE"
$env:GOOS = 'linux'
& go vet ./controller/internal/payload 2>&1 | ForEach-Object { Write-Host $_ }
Write-Host "vet for Linux: exit code $LASTEXITCODE"
Remove-Item Env:\GOOS

Section 'go test of controller/internal/payload'
& go test ./controller/internal/payload -count=1 -v 2>&1 | ForEach-Object { Write-Host $_ }
Write-Host "go test: exit code $LASTEXITCODE"
