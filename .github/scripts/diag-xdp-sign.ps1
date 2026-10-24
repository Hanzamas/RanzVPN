# Temporary (ONE-3, #312): reads, on a windows-latest runner, what Windows says of each file of the pinned XDP runtime when
# it is checked through the catalog of its package (xdpapi.dll carries a signature that no machine trusts, see the first
# run of this workflow), and what the INF and the setup script of Microsoft do with the files. Removed with its workflow
# when the checks of fetch-xdp.ps1 and install.ps1 are fixed.
$ErrorActionPreference = 'Continue'
$PSNativeCommandUseErrorActionPreference = $false

function Section([string] $title) {
	Write-Host ''
	Write-Host "===== $title ====="
}

function Get-SignTool {
	$roots = @("${env:ProgramFiles(x86)}\Windows Kits\10\bin", "${env:ProgramFiles}\Windows Kits\10\bin")
	$found = foreach ($r in $roots) {
		if (Test-Path -LiteralPath $r) {
			Get-ChildItem -LiteralPath $r -Recurse -Filter 'signtool.exe' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' }
		}
	}
	return ($found | Sort-Object FullName -Descending | Select-Object -First 1).FullName
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
$native = Join-Path $extract 'runtime\native'
$env:DIAG_DIR = $native

Section 'xdp.inf'
Get-Content -LiteralPath (Join-Path $native 'xdp.inf') | ForEach-Object { Write-Host "  $_" }

Section 'what xdp-setup.ps1 does with the files'
Select-String -LiteralPath (Join-Path $native 'xdp-setup.ps1') -Pattern 'netcfg|lodctr|xdpapi|Start-Service|sc\.exe|Copy-Item|System32|\.cat|\.sys|\.inf|\.man|Test-Path' | ForEach-Object { Write-Host "  $($_.LineNumber): $($_.Line.Trim())" }

Section 'signtool through the catalog'
$signtool = Get-SignTool
Write-Host "signtool: $signtool"
$cat = Join-Path $native 'xdp.cat'
# One byte of each file changed, in a folder of its own
$changed = Join-Path $env:RUNNER_TEMP 'xdp-changed'
New-Item -ItemType Directory -Force -Path $changed | Out-Null
foreach ($name in @('xdpapi.dll', 'xdp.sys')) {
	$bytes = [IO.File]::ReadAllBytes((Join-Path $native $name))
	$bytes[[int]($bytes.Length / 2)] = $bytes[[int]($bytes.Length / 2)] -bxor 0xFF
	[IO.File]::WriteAllBytes((Join-Path $changed $name), $bytes)
}
$cases = @(
	@('/pa', $cat, (Join-Path $native 'xdpapi.dll')),
	@('/kp', $cat, (Join-Path $native 'xdpapi.dll')),
	@('/kp', $cat, (Join-Path $native 'xdp.sys')),
	@('/pa', $cat, (Join-Path $native 'xdp.inf')),
	@('/pa', $cat, (Join-Path $native 'xdppcw.man')),
	@('/pa', $cat, (Join-Path $changed 'xdpapi.dll')),
	@('/kp', $cat, (Join-Path $changed 'xdp.sys'))
)
foreach ($case in $cases) {
	Write-Host "--- signtool verify $($case[0]) /c $(Split-Path -Leaf $case[1]) $($case[2])"
	$out = & $signtool verify $case[0] /c $case[1] /v $case[2] 2>&1
	$code = $LASTEXITCODE
	# The chain of the catalog is known from the first run: what decides is in these lines
	$out | Where-Object { $_ -match 'Successfully verified|SignTool Error|Number of (files|errors)|Hash of file|Verifying' } | ForEach-Object { Write-Host "  $_" }
	Write-Host "  exit code $code"
}

Section 'the Go checks of controller/internal/payload'
& go test ./controller/internal/payload -run 'TestDiagVerifyEachFile' -count=1 -v 2>&1 | ForEach-Object { Write-Host $_ }
