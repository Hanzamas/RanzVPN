# Fetch the pinned XDP for Windows runtime of Microsoft for ranz.exe (ONE-3, #312; ADR-0018 amendment of 2026-10-22).
# The Microsoft.XDP-for-Windows.Runtime.x64 NuGet package is pinned by version and verified by the SHA-512 that NuGet
# records for that immutable package. It is x64 only: Microsoft publishes no production-signed runtime for arm64
# (ADR-0022). The files of its runtime\native folder that ranz installs are copied to -OutDir, unchanged: xdp.sys, xdpapi.dll,
# xdp.cat, xdp.inf and xdppcw.man (the manifest of its performance counters). self-integrity.ps1 embeds them in ranz.exe as
# its XDP payload, which ranz install writes out, checks and installs with netcfg and lodctr, as Microsoft's
# xdp-setup.ps1 does, so that no PowerShell script and no second download is left. The driver, its API library and its
# catalog must carry the production signature of Microsoft (a test-signed prerelease has none that a machine trusts, and
# cannot ship), which this script checks, and the install job of windows.yml checks again, with signtool verify /kp, on the
# files that ranz install wrote. A new version changes the pin here and the NOTICE together (TestNoticeNamesThePinnedPayloads).
param(
	[string] $Version = '1.4.0',
	[Parameter(Mandatory = $true)]
	[string] $OutDir
)

$ErrorActionPreference = 'Stop'

# The SHA-512 (base64 to hex) that NuGet records for each pinned package; a changed hash fails the fetch
$knownHash = @{
	'1.4.0' = '20f85306846e7bf18bf448cc68aee82ed0c490256d7d94d2bdbf6ac511204a361b1ae7de2642bd0e33235ad8cffa7df0de5efa2185d2c4345dadb527f7ec9172'
}
if (-not $knownHash.ContainsKey($Version)) {
	throw "No pinned SHA-512 for the XDP runtime $Version. Add it here, and the version to the NOTICE, after verifying the package on nuget.org."
}

$id = 'microsoft.xdp-for-windows.runtime.x64'
$url = "https://api.nuget.org/v3-flatcontainer/$id/$Version/$id.$Version.nupkg"
$nupkg = Join-Path $env:RUNNER_TEMP "xdp-$Version.nupkg"

Write-Host "Downloading the XDP runtime $Version from $url"
Invoke-WebRequest -Uri $url -OutFile $nupkg

$hash = (Get-FileHash -Algorithm SHA512 -LiteralPath $nupkg).Hash.ToLower()
if ($hash -ne $knownHash[$Version]) {
	throw "XDP runtime $Version SHA-512 mismatch: got $hash, expected $($knownHash[$Version])"
}
Write-Host "SHA-512 verified: $hash"

# The .nupkg is a zip; extract it to a clean directory
$extract = Join-Path $env:RUNNER_TEMP "xdp-$Version-pkg"
if (Test-Path $extract) { Remove-Item -Recurse -Force $extract }
$zip = Join-Path $env:RUNNER_TEMP "xdp-$Version.zip"
Copy-Item -LiteralPath $nupkg -Destination $zip -Force
Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force

$native = Join-Path $extract 'runtime\native'
$names = @('xdp.sys', 'xdpapi.dll', 'xdp.cat', 'xdp.inf', 'xdppcw.man')
foreach ($name in $names) {
	if (-not (Test-Path -LiteralPath (Join-Path $native $name))) { throw "The XDP runtime package is missing runtime\native\$name" }
}

# The driver, its API library and its catalog carry the production signature of Microsoft
foreach ($name in @('xdp.sys', 'xdpapi.dll', 'xdp.cat')) {
	$sig = Get-AuthenticodeSignature -LiteralPath (Join-Path $native $name)
	Write-Host "${name}: signature $($sig.Status), signer $($sig.SignerCertificate.Subject)"
	if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft') {
		throw "$name is not signed by Microsoft: $($sig.Status), $($sig.SignerCertificate.Subject)"
	}
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
foreach ($name in $names) {
	$to = Join-Path $OutDir $name
	Copy-Item -Force -LiteralPath (Join-Path $native $name) -Destination $to
	Write-Host "${name}: SHA-256 $((Get-FileHash -Algorithm SHA256 -LiteralPath $to).Hash)"
}
Write-Host "The XDP runtime $Version is in $OutDir"
