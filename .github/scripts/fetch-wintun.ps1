# Fetch the pinned Wintun release of WireGuard LLC (THIRD_PARTY.TXT) for the client role of the node (CORE-S3-1, #71):
# wintun.dll of the target architecture next to the test executables, where the node loads it, with the licence of the
# archive beside it. The archive is pinned by version and verified by the SHA-256 that https://www.wintun.net publishes
# for it, and the DLL by its Authenticode signature, which must be WireGuard LLC's: the licence allows the DLL to be
# redistributed unmodified only. ONE-3 (#312) carries the DLL in ranz.exe later; until then CI fetches it for the
# vpntest harness only.
param(
	[ValidateSet('x64', 'arm64')]
	[string] $Arch = 'x64',
	[string] $Version = '0.14.1',
	[string] $DllDir = ''
)

$ErrorActionPreference = 'Stop'

# The SHA-256 that wintun.net publishes for each pinned archive; a changed hash fails the fetch
$knownHash = @{
	'0.14.1' = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
}
if (-not $knownHash.ContainsKey($Version)) {
	throw "No pinned SHA-256 for Wintun $Version. Add it here and to THIRD_PARTY.TXT after checking it on wintun.net."
}

$url = "https://www.wintun.net/builds/wintun-$Version.zip"
$zip = Join-Path $env:RUNNER_TEMP "wintun-$Version.zip"
Write-Host "Downloading Wintun $Version ($Arch) from $url"
Invoke-WebRequest -Uri $url -OutFile $zip

$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLower()
if ($hash -ne $knownHash[$Version]) {
	throw "Wintun $Version SHA-256 mismatch: got $hash, expected $($knownHash[$Version])"
}
Write-Host "SHA-256 verified: $hash"

$extract = Join-Path $env:RUNNER_TEMP "wintun-$Version"
if (Test-Path $extract) { Remove-Item -Recurse -Force $extract }
Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force

# The archive names the architectures amd64, arm64, x86 and arm
$dir = @{ 'x64' = 'amd64'; 'arm64' = 'arm64' }[$Arch]
$dll = Join-Path $extract "wintun\bin\$dir\wintun.dll"
if (-not (Test-Path -LiteralPath $dll)) { throw "The Wintun archive is missing $dll" }
$licence = Get-ChildItem -LiteralPath (Join-Path $extract 'wintun') -Filter 'LICENSE*' -File | Select-Object -First 1
if (-not $licence) { throw 'The Wintun archive has no licence file' }

$sig = Get-AuthenticodeSignature -LiteralPath $dll
Write-Host "wintun.dll ($Arch): signature $($sig.Status), signer $($sig.SignerCertificate.Subject), file version $((Get-Item -LiteralPath $dll).VersionInfo.FileVersion)"
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'WireGuard LLC') {
	throw "wintun.dll is not signed by WireGuard LLC: $($sig.Status), $($sig.SignerCertificate.Subject)"
}

# The DLL next to the test executables, unmodified, with the licence of the archive
if ($DllDir -ne '') {
	New-Item -ItemType Directory -Force -Path $DllDir | Out-Null
	Copy-Item -Force -LiteralPath $dll -Destination (Join-Path $DllDir 'wintun.dll')
	Copy-Item -Force -LiteralPath $licence.FullName -Destination (Join-Path $DllDir 'wintun-LICENSE.txt')
	Write-Host "wintun.dll and its licence copied to $DllDir"
}
