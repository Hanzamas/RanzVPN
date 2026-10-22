param(
	[string] $X64Dir,       # The Binaries-x64 artifact: vpnserver.exe, vpncmd.exe, ranz-node.exe, vpntest.exe and the PDBs
	[string] $Arm64Dir,     # The Binaries-arm64 artifact (the same executables for arm64)
	[string] $Wxs,          # .github/signing/signing-proof.wxs
	[string] $LicenseFile,  # The LICENSE of the repository (unused payload, kept for parity with the release spec)
	[string] $GoModuleDir,  # ranz-bgp/ (the shipped Go sidecar, for the symbol-strip check)
	[string] $OutDir        # Work directory: the signed copies and the MSI
)

# SEC-3 (#281), ADR-0020 and ADR-0036 amendments of 2026-10-22. Three things, all provable in CI with a
# self-signed certificate (the production Authenticode certificate is bought near release):
#   1. sign every shipped executable and an MSI, and check a signature is present on each;
#   2. run the self-integrity check on a signed binary (it passes) and on a copy whose .text was changed
#      (it takes the degrade-or-deceive path of ADR-0036, not a crash);
#   3. check the shipped binaries carry no symbols and ship no public PDB: the C executables embed no
#      symbol table and the MSI holds no PDB (their symbols stay in a private PDB), and the Go sidecar
#      built with -trimpath and -ldflags "-s -w" has no symbol table.

$ErrorActionPreference = 'Stop'
# Native exit codes are checked explicitly below (so "go tool nm", which exits 1 when a binary has no
# symbols, is read by its output, not treated as a failure). Without this, PowerShell 7.4 and later throw
# on any non-zero native exit.
$PSNativeCommandUseErrorActionPreference = $false

# The shipped executables of the current server and the new-core node (ADR-0020). vpntest is a test tool,
# not shipped; it is signed only to run the self-integrity test against a signed binary.
$shipped = @('vpnserver.exe', 'vpncmd.exe', 'ranz-node.exe')

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# Absolute paths, so the Go build below (after a Push-Location into the module) still writes to the same
# output directory and reads the same inputs.
$OutDir = (Resolve-Path -LiteralPath $OutDir).Path
$X64Dir = (Resolve-Path -LiteralPath $X64Dir).Path
$Arm64Dir = (Resolve-Path -LiteralPath $Arm64Dir).Path
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
	Write-Host "signtool: $($tool.FullName)"
	return $tool.FullName
}

# Read the whole file as bytes
function Get-FileBytes([string] $Path) {
	return [System.IO.File]::ReadAllBytes($Path)
}

# The PE fields the checks read: the COFF symbol table (a release executable keeps its symbols in a
# private PDB, so the table is empty) and the .text section. Returns a hashtable.
function Get-PeInfo([byte[]] $Bytes) {
	$lfanew = [System.BitConverter]::ToInt32($Bytes, 0x3C)
	if ([System.Text.Encoding]::ASCII.GetString($Bytes, $lfanew, 2) -ne 'PE') {
		throw 'not a PE file (no PE signature)'
	}
	$fileHeader = $lfanew + 4
	$numSections = [System.BitConverter]::ToUInt16($Bytes, $fileHeader + 2)
	$symbolTablePtr = [System.BitConverter]::ToUInt32($Bytes, $fileHeader + 8)   # PointerToSymbolTable
	$numSymbols = [System.BitConverter]::ToUInt32($Bytes, $fileHeader + 12)      # NumberOfSymbols
	$sizeOfOptional = [System.BitConverter]::ToUInt16($Bytes, $fileHeader + 16)
	$opt = $fileHeader + 20
	# The section table follows the whole optional header
	$sec = $opt + $sizeOfOptional
	$text = $null
	for ($i = 0; $i -lt $numSections; $i++) {
		$off = $sec + ($i * 40)
		$name = [System.Text.Encoding]::ASCII.GetString($Bytes, $off, 8).TrimEnd([char]0)
		if ($name -eq '.text') {
			$text = @{
				VirtualSize    = [System.BitConverter]::ToUInt32($Bytes, $off + 8)
				SizeOfRawData  = [System.BitConverter]::ToUInt32($Bytes, $off + 16)
				PointerToRawData = [System.BitConverter]::ToUInt32($Bytes, $off + 20)
			}
		}
	}
	return @{ SymbolTablePtr = $symbolTablePtr; NumSymbols = $numSymbols; Text = $text }
}

# Sign a file with the self-signed certificate in the current user's My store (by thumbprint) and check
# a verified signature is present. No timestamp: a self-signed build is not released.
function Protect-File([string] $SignTool, [string] $Thumbprint, [string] $Path) {
	& $SignTool sign /fd SHA256 /sha1 $Thumbprint $Path
	if ($LASTEXITCODE -ne 0) { throw "signtool sign failed for $Path (exit $LASTEXITCODE)" }
	& $SignTool verify /pa $Path
	if ($LASTEXITCODE -ne 0) { throw "signtool verify found no valid signature on $Path (exit $LASTEXITCODE)" }
	Write-Host "signed and verified: $Path"
}

# ---------------------------------------------------------------------------------------------------
# A self-signed code-signing certificate, trusted on this runner so WinVerifyTrust and signtool verify
# chain to a root. The production certificate (OV or EV) is bought near release (ADR-0020 amendment).
# ---------------------------------------------------------------------------------------------------
$cert = New-SelfSignedCertificate -Type CodeSigningCert `
	-Subject 'CN=Ranz VPN CI signing (self-signed), O=Hanzcodes' `
	-CertStoreLocation Cert:\CurrentUser\My `
	-KeyExportPolicy Exportable -KeyUsage DigitalSignature `
	-NotAfter (Get-Date).AddYears(1)
$thumb = $cert.Thumbprint
Write-Host "self-signed certificate: $thumb"

# Trust it on this machine so the chain verifies (the self-signed root is its own trusted root)
$export = Join-Path $OutDir 'ranz-ci-signing.cer'
Export-Certificate -Cert $cert -FilePath $export | Out-Null
Import-Certificate -FilePath $export -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Import-Certificate -FilePath $export -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null

$signtool = Get-SignTool

# ---------------------------------------------------------------------------------------------------
# 1. Sign every shipped executable (x64 and arm64) and check each has a verified signature.
# ---------------------------------------------------------------------------------------------------
foreach ($pair in @(@{ Dir = $X64Dir; Arch = 'x64' }, @{ Dir = $Arm64Dir; Arch = 'arm64' })) {
	foreach ($exe in $shipped) {
		$path = Join-Path $pair.Dir $exe
		if (-not (Test-Path -LiteralPath $path)) { throw "$($pair.Arch): $exe is missing from $($pair.Dir)" }
		Protect-File $signtool $thumb $path
	}
}

# ---------------------------------------------------------------------------------------------------
# 1 (continued). Build an MSI that packages the signed x64 vpnserver.exe, sign it and verify it.
# ---------------------------------------------------------------------------------------------------
$msi = Join-Path $OutDir 'ranz-vpn-signing-proof.msi'
$version = "0.0.0.$($env:GITHUB_RUN_NUMBER)"
if (-not $env:GITHUB_RUN_NUMBER) { $version = '0.0.0.1' }
wix build -arch x64 `
	-d "Version=$version" `
	-d "ServerExe=$(Join-Path $X64Dir 'vpnserver.exe')" `
	-o $msi `
	$Wxs
if ($LASTEXITCODE -ne 0) { throw "wix build failed (exit $LASTEXITCODE)" }
Protect-File $signtool $thumb $msi

# ---------------------------------------------------------------------------------------------------
# 2. The self-integrity check: it passes on a signed, intact binary, and takes the degrade path (not a
#    crash) on a copy whose .text was changed.
# ---------------------------------------------------------------------------------------------------
$vpntest = Join-Path $X64Dir 'vpntest.exe'
if (-not (Test-Path -LiteralPath $vpntest)) { throw "vpntest.exe is missing from $X64Dir" }

# The untampered, signed binary
$intact = Join-Path $OutDir 'vpntest-signed.exe'
Copy-Item -LiteralPath $vpntest -Destination $intact -Force
Protect-File $signtool $thumb $intact
$out = (& $intact selfintegrity 2>&1 | Out-String)
$code = $LASTEXITCODE
Write-Host $out
if ($code -ne 0) { throw "the signed binary exited with $code (a crash), not 0" }
if ($out -notmatch 'SELFINTEGRITY TEST OK') { throw 'the signed, intact binary did not pass the self-integrity check' }
Write-Host 'self-integrity: the signed, intact binary passed'

# A copy whose .text was changed. The binary is signed first, then one byte of .text is flipped, so the
# Authenticode signature no longer matches the file (the digest covers .text). A byte in the file padding
# past the section's virtual size is chosen, so it is never executed and the check degrades, never crashes.
$tampered = Join-Path $OutDir 'vpntest-tampered.exe'
Copy-Item -LiteralPath $vpntest -Destination $tampered -Force
Protect-File $signtool $thumb $tampered

$bytes = Get-FileBytes $tampered
$pe = Get-PeInfo $bytes
if (-not $pe.Text) { throw 'vpntest.exe has no .text section' }
$t = $pe.Text
if ($t.VirtualSize -lt $t.SizeOfRawData) {
	$flip = [int]$t.PointerToRawData + [int]$t.VirtualSize           # the first file-padding byte, never executed
} else {
	$flip = [int]$t.PointerToRawData + [int]$t.SizeOfRawData - 1     # no padding: the last raw byte
}
Write-Host "flipping .text file byte at offset $flip (raw $($t.PointerToRawData), virtual size $($t.VirtualSize), raw size $($t.SizeOfRawData))"
$bytes[$flip] = [byte]($bytes[$flip] -bxor 0xFF)
[System.IO.File]::WriteAllBytes($tampered, $bytes)

$out = (& $tampered selfintegrity tampered 2>&1 | Out-String)
$code = $LASTEXITCODE
Write-Host $out
if ($code -ne 0) { throw "the changed binary exited with ${code} (not 0): the check crashed instead of degrading" }
if ($out -notmatch 'SELFINTEGRITY TEST OK') { throw 'the changed binary did not take the degrade-or-deceive path' }
Write-Host 'self-integrity: the changed binary degraded without a crash'

# ---------------------------------------------------------------------------------------------------
# 3. Symbol stripping: the shipped C executables embed no COFF symbol table, the MSI holds no PDB, and
#    the Go sidecar built with -trimpath and -ldflags "-s -w" has no symbol table.
# ---------------------------------------------------------------------------------------------------
foreach ($pair in @(@{ Dir = $X64Dir; Arch = 'x64' }, @{ Dir = $Arm64Dir; Arch = 'arm64' })) {
	foreach ($exe in $shipped) {
		$path = Join-Path $pair.Dir $exe
		$pe = Get-PeInfo (Get-FileBytes $path)
		# A release executable keeps its symbols in a private PDB, so it embeds no COFF symbol table
		if ($pe.SymbolTablePtr -ne 0 -or $pe.NumSymbols -ne 0) {
			throw "$($pair.Arch) $exe embeds a COFF symbol table (pointer $($pe.SymbolTablePtr), count $($pe.NumSymbols))"
		}
		Write-Host "$($pair.Arch) $exe embeds no symbol table"
	}
}

# No public PDB in the MSI: the File table names no .pdb (the package is built from signing-proof.wxs,
# which declares only vpnserver.exe). The COM object is called directly; the InvokeMember reflection path
# mis-marshals the open-mode argument (DISP_E_TYPEMISMATCH).
$installer = New-Object -ComObject WindowsInstaller.Installer
$db = $installer.OpenDatabase($msi, 0)
$view = $db.OpenView('SELECT `FileName` FROM `File`')
$view.Execute()
$pdbInMsi = @()
while ($null -ne ($rec = $view.Fetch())) {
	$name = $rec.StringData(1)
	if ($name -match '\.pdb') { $pdbInMsi += $name }
}
if ($pdbInMsi.Count -gt 0) { throw "the MSI ships a PDB: $($pdbInMsi -join ', ')" }
Write-Host 'the MSI ships no PDB (the C PDB is kept private)'

# The Go sidecar: built with -trimpath and -ldflags "-s -w", go tool nm reports no symbol table
Push-Location $GoModuleDir
try {
	foreach ($goarch in @('amd64', 'arm64')) {
		$goexe = Join-Path $OutDir "ranz-bgp-$goarch.exe"
		$env:GOOS = 'windows'
		$env:GOARCH = $goarch
		$env:CGO_ENABLED = '0'
		go build -trimpath -ldflags '-s -w' -o $goexe ./cmd/ranz-bgp
		if ($LASTEXITCODE -ne 0) { throw "go build (-trimpath -ldflags '-s -w') failed for $goarch (exit $LASTEXITCODE)" }
		$nm = (go tool nm $goexe 2>&1 | Out-String)
		if ($nm -notmatch 'no symbols') { throw "ranz-bgp ($goarch) still has a symbol table after -ldflags '-s -w':`n$nm" }
		Write-Host "ranz-bgp ($goarch): -trimpath -ldflags '-s -w', no symbol table"
	}
} finally {
	Pop-Location
	Remove-Item Env:\GOOS, Env:\GOARCH, Env:\CGO_ENABLED -ErrorAction SilentlyContinue
}

Write-Host 'self-integrity.ps1: signing, the self-integrity check and symbol stripping all passed'
