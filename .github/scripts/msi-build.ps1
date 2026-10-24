param(
	[string] $Wxs,             # .github/msi/ranz.wxs
	[string] $OutDir,          # Where the MSIs and the SHA-256 files go
	[string] $X64,             # The ranz.exe that the x64 MSI carries
	[string] $Arm64,           # The ranz.exe that the arm64 MSI carries
	[string] $X64Previous,     # The ranz.exe of the previous x64 MSI; $X64 when left out
	[string] $Arm64Previous,   # The ranz.exe of the previous arm64 MSI; $Arm64 when left out
	[string] $X64Tampered,     # A ranz.exe of x64 whose Payload has one byte changed: one more MSI, which ranz install must refuse
	[string] $Arm64Tampered,   # The same for arm64
	[string] $Version,         # The product version of the MSIs, major.minor.build; what ranz version of $X64 prints when left out
	[string] $PreviousVersion, # The version of the previous MSIs; one build lower than $Version when it came from ranz version
	[string] $Thumbprint       # The self-signed certificate in Cert:\CurrentUser\My that signs each MSI; without one they are not signed
)

$ErrorActionPreference = 'Stop'
# Native exit codes are checked by hand below
$PSNativeCommandUseErrorActionPreference = $false

# The thin MSI of ranz.exe (ONE-5, #314; ADR-0011 and ADR-0020 amendments of 2026-10-22), built with the pinned
# WiX of the job from .github/msi/ranz.wxs, for x64 and arm64: ranz-<arch>.msi carries one ranz.exe, and
# ranz-<arch>-previous.msi carries one at the version before it, for the upgrade and downgrade tests of
# .github/scripts/msi-install.ps1. It builds packages and publishes nothing.
#
# The product version is major.minor.build, the version that ranz version prints for the ranz.exe in the
# package: the major.minor of CMakeLists.txt and the one counter that only grows, the run number of the
# workflow, which every shipped file of the run carries as its build number (ADR-0020 consequences). Windows
# Installer orders upgrades by the first three parts, and the third is at most 65535, so the script stops
# when the counter gets there. The previous version is one build lower.
#
# With -Thumbprint the MSIs are signed like every shipped executable (ADR-0020 amendment of 2026-10-22), and
# the SHA-256 of each ranz.exe that went into a package is written to ranz-<arch>.sha256, so that the job
# that installs the MSI compares the file that it installed with it.

foreach ($name in 'Wxs', 'OutDir', 'X64', 'Arm64') {
	if (-not (Get-Variable -Name $name -ValueOnly)) { throw "-$name is not given" }
}
if ([bool]$Version -ne [bool]$PreviousVersion) { throw '-Version and -PreviousVersion are given together, or neither of them' }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path -LiteralPath $OutDir).Path
$Wxs = (Resolve-Path -LiteralPath $Wxs).Path

# signtool.exe of the Windows SDK: the highest version under the Windows Kits, x64 build
function Get-SignTool {
	$roots = @(
		"${env:ProgramFiles(x86)}\Windows Kits\10\bin",
		"${env:ProgramFiles}\Windows Kits\10\bin"
	)
	$found = foreach ($r in $roots) {
		if (Test-Path -LiteralPath $r) {
			Get-ChildItem -LiteralPath $r -Recurse -Filter 'signtool.exe' -ErrorAction SilentlyContinue |
				Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' }
		}
	}
	$tool = $found | Sort-Object FullName -Descending | Select-Object -First 1
	if (-not $tool) { throw 'signtool.exe was not found under the Windows Kits' }
	return $tool.FullName
}

# Sign a file with the self-signed certificate (by thumbprint) and check that a verified signature is there.
# No timestamp: a self-signed build is not released.
function Protect-File([string] $SignTool, [string] $Path) {
	& $SignTool sign /fd SHA256 /sha1 $Thumbprint $Path
	if ($LASTEXITCODE -ne 0) { throw "signtool sign failed for $Path (exit $LASTEXITCODE)" }
	& $SignTool verify /pa $Path
	if ($LASTEXITCODE -ne 0) { throw "signtool verify found no valid signature on $Path (exit $LASTEXITCODE)" }
}

# One value of a query of the Windows Installer database $db: the first column of each row
function Get-MsiRows($db, [string] $query) {
	$view = $db.OpenView($query)
	$rows = @()
	try {
		# A void method of a COM object gives $null to the pipeline, and the function would return it
		[void]$view.Execute()
		while ($null -ne ($record = $view.Fetch())) { $rows += $record.StringData(1) }
	} finally {
		[void]$view.Close()
		[void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($view)
	}
	return $rows
}

# The package at $Path is what the build was asked for: the version, the platform of its summary
# information (the one that makes Windows Installer refuse it with 1633 on another computer) and one
# file, ranz.exe, and no PDB. The COM object is called directly, as in self-integrity.ps1: the
# InvokeMember reflection path mis-marshals the open-mode argument. The package is read only, so
# the checks follow the signing, which needs the file closed.
function Assert-Msi([string] $Path, [string] $Arch, [string] $Ver) {
	$installer = New-Object -ComObject WindowsInstaller.Installer
	$db = $installer.OpenDatabase($Path, 0)
	try {
		# In a single-quoted string a backtick is only a backtick, the quote of a column or table name, and two single quotes are one
		$got = @(Get-MsiRows $db ('SELECT `Value` FROM `Property` WHERE `Property`=' + '''ProductVersion'''))
		if ($got.Count -ne 1 -or $got[0] -ne $Ver) { throw "$Path has the ProductVersion '$($got -join ',')', not $Ver" }
		$summary = $db.SummaryInformation(0)
		$template = $summary.Property(7)
		[void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($summary)
		$platform = if ($Arch -eq 'x64') { 'x64' } else { 'Arm64' }
		if ($template -notmatch "^$platform;") { throw "$Path has the template '$template', not the platform $platform" }
		$files = @(Get-MsiRows $db 'SELECT `FileName` FROM `File`')
		if ($files.Count -ne 1 -or $files[0] -notmatch '(^|\|)ranz\.exe$') { throw "$Path carries $($files -join ', '), not ranz.exe alone" }
	} finally {
		[void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($db)
		[void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($installer)
		[GC]::Collect()
		[GC]::WaitForPendingFinalizers()
	}
}

if (-not $Version) {
	# The one place the version of the MSI comes from: ranz.exe itself, which runs on this runner when it is x64
	$line = (& $X64 version | Out-String).Trim()
	if ($LASTEXITCODE -ne 0 -or -not ($line -match '^ranz (\d+\.\d+)\.(\d+)$')) { throw "$X64 version printed '$line' (exit code $LASTEXITCODE)" }
	$majorMinor = $Matches[1]
	$build = [int] $Matches[2]
	if ($build -gt 65535) { throw "the build number $build is above 65535, the largest third part of an MSI version: the counter of the version needs a new scheme (ADR-0020 consequences)" }
	if ($build -lt 1) { throw "the build number is ${build}: there is no lower build for the previous package, and a build from a run starts at 1" }
	$Version = "$majorMinor.$build"
	$PreviousVersion = "$majorMinor.$($build - 1)"
}
foreach ($v in $Version, $PreviousVersion) {
	if (-not ($v -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,5})$') -or [int]$Matches[1] -gt 255 -or [int]$Matches[2] -gt 255 -or [int]$Matches[3] -gt 65535) {
		throw "'$v' is not an MSI version: major.minor.build, at most 255.255.65535"
	}
}
if ([version]$PreviousVersion -ge [version]$Version) { throw "the previous version $PreviousVersion is not lower than $Version" }
Write-Host "product version $Version, previous $PreviousVersion"

$signtool = $null
if ($Thumbprint) {
	$signtool = Get-SignTool
	Write-Host "signtool: $signtool"
}

function Build-Msi([string] $Arch, [string] $Exe, [string] $Ver, [string] $Name) {
	$exePath = (Resolve-Path -LiteralPath $Exe).Path
	$other = if ($Arch -eq 'x64') { 'arm64' } else { 'x64' }
	$msi = Join-Path $OutDir $Name
	& wix build -arch $Arch -d "Version=$Ver" -d "PackageArch=$Arch" -d "OtherArch=$other" -d "RanzExe=$exePath" -o $msi $Wxs
	if ($LASTEXITCODE -ne 0) { throw "wix build failed for $Name (exit $LASTEXITCODE)" }
	if ($signtool) { Protect-File $signtool $msi }
	Assert-Msi $msi $Arch $Ver
	Write-Host "built ${msi}: ProductVersion $Ver, $Arch, carries $exePath$(if ($signtool) { ', signed' })"
}

foreach ($arch in @(@{ Name = 'x64'; Exe = $X64; Previous = $X64Previous; Tampered = $X64Tampered }, @{ Name = 'arm64'; Exe = $Arm64; Previous = $Arm64Previous; Tampered = $Arm64Tampered })) {
	$name = $arch.Name
	Build-Msi $name $arch.Exe $Version "ranz-$name.msi"
	$previous = if ($arch.Previous) { $arch.Previous } else { $arch.Exe }
	Build-Msi $name $previous $PreviousVersion "ranz-$name-previous.msi"
	if ($arch.Tampered) { Build-Msi $name $arch.Tampered $Version "ranz-$name-tampered.msi" }
	$hash = (Get-FileHash -LiteralPath $arch.Exe -Algorithm SHA256).Hash
	Set-Content -LiteralPath (Join-Path $OutDir "ranz-$name.sha256") -Value $hash -Encoding ascii
	Write-Host "ranz.exe of $name in ranz-$name.msi: SHA-256 $hash"
}

Write-Host 'msi-build.ps1: the packages are built'
# A native command that ran last may have left a code that is no failure here
exit 0
