# Fetch the pinned WireGuardNT SDK of WireGuard LLC (THIRD_PARTY.TXT) for the WireGuard Devices of a gateway Node (SDN-80,
# #375): wireguard.dll of the target architecture next to the test executables, where the node loads it
# (src/Cedar/NodeWireGuard.c), with the licence of the archive beside it. The archive is pinned by version and by its
# SHA-256, and the DLL by its Authenticode signature, which must be WireGuard LLC's: the licence allows the DLL to be
# redistributed unmodified only, and the DLL installs the WireGuardNT driver itself when the node creates an interface.
# -ShowLicence prints the licence of the archive into the log.
param(
	[ValidateSet('x64', 'arm64')]
	[string] $Arch = 'x64',
	[string] $Version = '0.10.1',
	[string] $DllDir = '',
	[switch] $ShowLicence
)

$ErrorActionPreference = 'Stop'

# The SHA-256 of each pinned archive as download.wireguard.com served it when it was pinned, together with the
# signature of WireGuard LLC on its DLLs (THIRD_PARTY.TXT); a changed hash fails the fetch
$knownHash = @{
	'0.10.1' = '772c0b1463d8d2212716f43f06f4594d880dea4f735165bd68e388fc41b81605'
}
if (-not $knownHash.ContainsKey($Version)) {
	throw "No pinned SHA-256 for WireGuardNT $Version. Add it here and to THIRD_PARTY.TXT once the signature of its DLLs is WireGuard LLC's."
}

$url = "https://download.wireguard.com/wireguard-nt/wireguard-nt-$Version.zip"
$zip = Join-Path $env:RUNNER_TEMP "wireguard-nt-$Version.zip"
Write-Host "Downloading WireGuardNT $Version ($Arch) from $url"
Invoke-WebRequest -Uri $url -OutFile $zip

$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLower()
if ($hash -ne $knownHash[$Version]) {
	throw "WireGuardNT $Version SHA-256 mismatch: got $hash, expected $($knownHash[$Version])"
}
Write-Host "SHA-256 verified: $hash"

$extract = Join-Path $env:RUNNER_TEMP "wireguard-nt-$Version"
if (Test-Path $extract) { Remove-Item -Recurse -Force $extract }
Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force

# The archive names the architectures amd64, arm64, x86 and arm
$dir = @{ 'x64' = 'amd64'; 'arm64' = 'arm64' }[$Arch]
$dll = Join-Path $extract "wireguard-nt\bin\$dir\wireguard.dll"
if (-not (Test-Path -LiteralPath $dll)) { throw "The WireGuardNT archive is missing $dll" }
$licence = Get-ChildItem -LiteralPath (Join-Path $extract 'wireguard-nt') -Filter 'LICENSE*' -File | Select-Object -First 1
if (-not $licence) { throw 'The WireGuardNT archive has no licence file' }

$sig = Get-AuthenticodeSignature -LiteralPath $dll
Write-Host "wireguard.dll ($Arch): signature $($sig.Status), signer $($sig.SignerCertificate.Subject), file version $((Get-Item -LiteralPath $dll).VersionInfo.FileVersion)"
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'WireGuard LLC') {
	throw "wireguard.dll is not signed by WireGuard LLC: $($sig.Status), $($sig.SignerCertificate.Subject)"
}

if ($ShowLicence) {
	Write-Host "--- $($licence.Name) of wireguard-nt-$Version.zip:"
	Get-Content -LiteralPath $licence.FullName | ForEach-Object { Write-Host $_ }
	Write-Host '---'
}

# The DLL next to the test executables, unmodified, with the licence of the archive
if ($DllDir -ne '') {
	New-Item -ItemType Directory -Force -Path $DllDir | Out-Null
	Copy-Item -Force -LiteralPath $dll -Destination (Join-Path $DllDir 'wireguard.dll')
	Copy-Item -Force -LiteralPath $licence.FullName -Destination (Join-Path $DllDir 'wireguard-LICENSE.txt')
	Write-Host "wireguard.dll and its licence copied to $DllDir"
}
