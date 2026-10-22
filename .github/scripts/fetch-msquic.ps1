# Fetch the official signed msquic package (the Schannel build, pinned) for the QUIC transport of
# the new core (CORE-S1-1, #67). The Microsoft.Native.Quic.MsQuic.Schannel NuGet package holds the
# signed msquic.dll, its import library and the headers for x64 and arm64; it is pinned by version
# and verified by the SHA-512 that NuGet records for that immutable package. The headers go to
# <Dest>\include for the build (TransportQuic.c loads the DLL at run time through LoadLibrary, so it
# links no import library), and the DLL for the target architecture goes to <Dest>\bin and, when
# -DllDir is given, next to the test executables so vpntest finds it.
#
# RANZ_MSQUIC_DIR is written to GITHUB_ENV so the build step passes it to CMake.
param(
	[ValidateSet('x64', 'arm64')]
	[string] $Arch = 'x64',
	[string] $Version = '2.6.2',
	[string] $Dest = "$env:RUNNER_TEMP\msquic",
	[string] $DllDir = ''
)

$ErrorActionPreference = 'Stop'

# The SHA-512 (base64 -> hex) that NuGet records for each pinned package; a changed hash fails the fetch
$knownHash = @{
	'2.6.2' = 'ac47317021168be9fb5369f95e41e99a58087cd175a7ffd183a1af6141d7455ce58022cd6a2412c8bd6eab7c2e242a982ec95af7959a2707530f31f45c67bea1'
}
if (-not $knownHash.ContainsKey($Version)) {
	throw "No pinned SHA-512 for msquic $Version. Add it to fetch-msquic.ps1 after verifying the package on nuget.org."
}

$id = 'microsoft.native.quic.msquic.schannel'
$url = "https://api.nuget.org/v3-flatcontainer/$id/$Version/$id.$Version.nupkg"
$nupkg = Join-Path $env:RUNNER_TEMP "msquic-$Version.nupkg"

Write-Host "Downloading msquic $Version ($Arch) from $url"
Invoke-WebRequest -Uri $url -OutFile $nupkg

$hash = (Get-FileHash -Algorithm SHA512 -LiteralPath $nupkg).Hash.ToLower()
if ($hash -ne $knownHash[$Version]) {
	throw "msquic $Version SHA-512 mismatch: got $hash, expected $($knownHash[$Version])"
}
Write-Host "SHA-512 verified: $hash"

# The .nupkg is a zip; extract it to a clean directory
$extract = Join-Path $env:RUNNER_TEMP "msquic-$Version-pkg"
if (Test-Path $extract) { Remove-Item -Recurse -Force $extract }
$zip = Join-Path $env:RUNNER_TEMP "msquic-$Version.zip"
Copy-Item -LiteralPath $nupkg -Destination $zip -Force
Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force

$native = Join-Path $extract 'build\native'
$includeSrc = Join-Path $native 'include'
$dllSrc = Join-Path $native "bin\$Arch\msquic.dll"
$libSrc = Join-Path $native "lib\$Arch\msquic.lib"
foreach ($p in @($includeSrc, $dllSrc, $libSrc)) {
	if (-not (Test-Path -LiteralPath $p)) { throw "msquic package is missing $p" }
}

if (Test-Path $Dest) { Remove-Item -Recurse -Force $Dest }
New-Item -ItemType Directory -Force -Path (Join-Path $Dest 'include') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Dest 'bin') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Dest 'lib') | Out-Null
Copy-Item -Recurse -Force -Path (Join-Path $includeSrc '*') -Destination (Join-Path $Dest 'include')
Copy-Item -Force -Path $dllSrc -Destination (Join-Path $Dest 'bin\msquic.dll')
Copy-Item -Force -Path $libSrc -Destination (Join-Path $Dest 'lib\msquic.lib')

Write-Host "msquic headers: $(Join-Path $Dest 'include')"
Write-Host "msquic.dll ($Arch): $(Join-Path $Dest 'bin\msquic.dll')"

# The DLL next to the test executables, so vpntest loads it when the quic test runs
if ($DllDir -ne '') {
	New-Item -ItemType Directory -Force -Path $DllDir | Out-Null
	Copy-Item -Force -Path $dllSrc -Destination (Join-Path $DllDir 'msquic.dll')
	Write-Host "msquic.dll copied to $DllDir"
}

if ($env:GITHUB_ENV) {
	"RANZ_MSQUIC_DIR=$Dest" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
}
