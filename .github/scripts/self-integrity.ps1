param(
	[string] $X64Dir,       # The Binaries-x64 artifact: ranz-node.exe, vpntest.exe and the PDBs
	[string] $Arm64Dir,     # The Binaries-arm64 artifact (the same executables for arm64)
	[string] $Wxs,          # .github/signing/signing-proof.wxs
	[string] $LicenseFile,  # The LICENSE of the repository (unused payload, kept for parity with the release spec)
	[string] $GoModuleDir,  # The Go module, the repository root (ranz, the shipped Go executable, for the symbol-strip check)
	[string] $OutDir,       # Work directory: the signed copies and the MSI
	[string] $Rqlited,      # The rqlited.exe of the pinned rqlite release: the rqlite member that ranz.exe carries (ONE-4, #313)
	[string] $WintunX64,    # The folder that fetch-wintun.ps1 filled for x64: the wintun.dll that ranz.exe carries (ONE-3, #312)
	[string] $WintunArm64,  # ... and for arm64
	[string] $Xdp,          # The folder that fetch-xdp.ps1 filled: the files of the XDP runtime that the x64 ranz.exe carries (ONE-3, #312)
	[string] $WireGuardX64, # The folder that fetch-wireguard.ps1 filled for x64: the wireguard.dll of WireGuardNT that ranz.exe carries (SDN-80, #375)
	[string] $WireGuardArm64 # ... and for arm64
)

# SEC-3 (#281), ADR-0020 and ADR-0036 amendments of 2026-10-22. Three things, all provable in CI with a
# self-signed certificate (the production Authenticode certificate is bought near release):
#   1. sign every shipped executable and an MSI, and check a signature is present on each;
#   2. run the self-integrity check on a signed binary (it passes) and on a copy whose .text was changed
#      (it takes the degrade-or-deceive path of ADR-0036, not a crash);
#   3. check the shipped binaries carry no symbols and ship no public PDB: the C executables embed no
#      symbol table and the MSI holds no PDB (their symbols stay in a private PDB), and ranz, the one
#      Go executable (ONE-1, #310), built with -trimpath and -ldflags "-s -w" has no symbol table.
#
# ONE-2 (#311) adds the signed ranz.exe of each architecture, which carries the signed ranz-node.exe of
# that architecture as its Payload (controller/internal/payload) and is signed once, and a second one
# whose Payload has one byte changed, for the install job of windows.yml: ranz install must refuse it.
# They are written as $OutDir\<arch>\ranz.exe and $OutDir\<arch>-tampered\ranz.exe, and the SHA-256 of
# each signed ranz-node.exe goes to GITHUB_OUTPUT, so that the install job copies one ranz.exe to its
# runner and compares what ranz install wrote with a hash, not with a second file.
#
# ONE-4 (#313) adds the rqlite member of a Controller as a second Payload of each of those ranz.exe: a
# copy of the rqlited.exe of the pinned rqlite release, signed with the same certificate. rqlite
# publishes no Windows build for arm64, so the ranz.exe of both architectures carries the same x64
# file, which Windows 11 on ARM runs under emulation. Its SHA-256 goes to GITHUB_OUTPUT too, so that the
# install job compares the file that the Controller writes under its data directory with a hash.
#
# ONE-3 (#312) adds the drivers that ranz install carries, as Payloads of the same ranz.exe, none of them signed here
# again: the wintun.dll of the pinned Wintun release for each architecture, as WireGuard LLC signed it, and for x64 the
# files of the pinned XDP runtime, as Microsoft signed them, which the checks of ranz install need as they are. The
# SeLow package is in the repository (src/bin/hamcore, and its copy under controller/internal/payload). The SHA-256 of
# each of these files goes to GITHUB_OUTPUT too. A third x64 ranz.exe, in $OutDir\x64-xdpfail, has one byte of xdp.sys
# changed, so that the install job can read what ranz install does when the XDP runtime fails: it must install the Node
# all the same.
#
# SDN-80 (#375) adds the wireguard.dll of the pinned WireGuardNT SDK for each architecture, as WireGuard LLC signed it,
# which a gateway of WireGuard Devices loads and ranz install writes unless --no-wireguard; its SHA-256 goes to
# GITHUB_OUTPUT as well.

$ErrorActionPreference = 'Stop'
# Native exit codes are checked explicitly below (so "go tool nm", which exits 1 when a binary has no
# symbols, is read by its output, not treated as a failure). Without this, PowerShell 7.4 and later throw
# on any non-zero native exit.
$PSNativeCommandUseErrorActionPreference = $false

# The shipped C executable: the new-core node (ADR-0020), since the slim fork's vpnserver and vpncmd were
# retired (CORE-S8-1, #84). vpntest is a test tool, not shipped; it is signed only to run the self-integrity
# test against a signed binary.
$shipped = @('ranz-node.exe')

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# Absolute paths, so the Go build below (after a Push-Location into the module) still writes to the same
# output directory and reads the same inputs.
$OutDir = (Resolve-Path -LiteralPath $OutDir).Path
$X64Dir = (Resolve-Path -LiteralPath $X64Dir).Path
$Arm64Dir = (Resolve-Path -LiteralPath $Arm64Dir).Path
$Wxs = (Resolve-Path -LiteralPath $Wxs).Path
if (-not $Rqlited) { throw '-Rqlited names no rqlited.exe, which the ranz.exe of each architecture carries as a Payload (ONE-4, #313)' }
if (-not $WintunX64 -or -not $WintunArm64) { throw '-WintunX64 and -WintunArm64 name no folder with the wintun.dll that the ranz.exe of each architecture carries as a Payload (ONE-3, #312)' }
if (-not $Xdp) { throw '-Xdp names no folder with the XDP runtime that the x64 ranz.exe carries as a Payload (ONE-3, #312)' }
$wintunDlls = @{
	'x64'   = (Join-Path (Resolve-Path -LiteralPath $WintunX64).Path 'wintun.dll')
	'arm64' = (Join-Path (Resolve-Path -LiteralPath $WintunArm64).Path 'wintun.dll')
}
$xdpDir = (Resolve-Path -LiteralPath $Xdp).Path
# The files of the XDP runtime, named as controller/internal/payload/xdp holds them
$xdpNames = @('xdp.sys', 'xdpapi.dll', 'xdp.cat', 'xdp.inf', 'xdppcw.man')
foreach ($file in @($wintunDlls['x64'], $wintunDlls['arm64']) + @($xdpNames | ForEach-Object { Join-Path $xdpDir $_ })) {
	if (-not (Test-Path -LiteralPath $file)) { throw "$file is missing: fetch-wintun.ps1 and fetch-xdp.ps1 fill the folders of -WintunX64, -WintunArm64 and -Xdp" }
}
if (-not $WireGuardX64 -or -not $WireGuardArm64) { throw '-WireGuardX64 and -WireGuardArm64 name no folder with the wireguard.dll that the ranz.exe of each architecture carries as a Payload (SDN-80, #375)' }
$wireguardDlls = @{
	'x64'   = (Join-Path (Resolve-Path -LiteralPath $WireGuardX64).Path 'wireguard.dll')
	'arm64' = (Join-Path (Resolve-Path -LiteralPath $WireGuardArm64).Path 'wireguard.dll')
}
foreach ($file in $wireguardDlls.Values) {
	if (-not (Test-Path -LiteralPath $file)) { throw "$file is missing: fetch-wireguard.ps1 fills the folders of -WireGuardX64 and -WireGuardArm64" }
}

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

# ONE-2 (#311): the SHA-256 of the now-signed ranz-node.exe of each architecture, as an output of the
# step (GITHUB_OUTPUT). The install job checks that the ranz-node.exe that ranz install wrote is this
# file byte for byte, so that it needs no copy of the file.
if ($env:GITHUB_OUTPUT) {
	foreach ($pair in @(@{ Dir = $X64Dir; Arch = 'x64' }, @{ Dir = $Arm64Dir; Arch = 'arm64' })) {
		$hash = (Get-FileHash -LiteralPath (Join-Path $pair.Dir 'ranz-node.exe') -Algorithm SHA256).Hash
		Write-Host "signed ranz-node.exe ($($pair.Arch)): SHA-256 $hash"
		"node-sha256-$($pair.Arch)=$hash" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append
	}
}

# ONE-4 (#313): the rqlite member of a Controller. The rqlited.exe of the release has no signature, so
# a copy of it is signed with the same certificate before the ranz.exe below embeds it.
$member = Join-Path $OutDir 'rqlited.exe'
Copy-Item -LiteralPath (Resolve-Path -LiteralPath $Rqlited).Path -Destination $member -Force
Protect-File $signtool $thumb $member
$memberHash = (Get-FileHash -LiteralPath $member -Algorithm SHA256).Hash
Write-Host "signed rqlited.exe: SHA-256 $memberHash"
if ($env:GITHUB_OUTPUT) {
	"member-sha256=$memberHash" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append
}

# ONE-3 (#312): the SHA-256 of each driver file that ranz.exe carries and ranz install writes, so that the install job
# compares what it wrote with a hash, as it does for ranz-node.exe
if ($env:GITHUB_OUTPUT) {
	foreach ($arch in @('x64', 'arm64')) {
		$hash = (Get-FileHash -LiteralPath $wintunDlls[$arch] -Algorithm SHA256).Hash
		Write-Host "wintun.dll ($arch): SHA-256 $hash"
		"wintun-sha256-$arch=$hash" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append
		# The wireguard.dll of WireGuardNT (SDN-80, #375)
		$hash = (Get-FileHash -LiteralPath $wireguardDlls[$arch] -Algorithm SHA256).Hash
		Write-Host "wireguard.dll ($arch): SHA-256 $hash"
		"wireguard-sha256-$arch=$hash" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append
	}
	foreach ($pair in @(@{ File = 'xdp.sys'; Output = 'xdp-sys-sha256' }, @{ File = 'xdpapi.dll'; Output = 'xdp-api-sha256' })) {
		$hash = (Get-FileHash -LiteralPath (Join-Path $xdpDir $pair.File) -Algorithm SHA256).Hash
		Write-Host "$($pair.File): SHA-256 $hash"
		"$($pair.Output)=$hash" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append
	}
}

# ---------------------------------------------------------------------------------------------------
# 1 (continued). Build an MSI that packages the signed x64 ranz-node.exe, sign it and verify it.
# ---------------------------------------------------------------------------------------------------
$msi = Join-Path $OutDir 'ranz-vpn-signing-proof.msi'
$version = "0.0.0.$($env:GITHUB_RUN_NUMBER)"
if (-not $env:GITHUB_RUN_NUMBER) { $version = '0.0.0.1' }
wix build -arch x64 `
	-d "Version=$version" `
	-d "NodeExe=$(Join-Path $X64Dir 'ranz-node.exe')" `
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
# which declares only ranz-node.exe). The COM object is called directly; the InvokeMember reflection path
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

# ranz, the one Go executable (ONE-1, #310; ONE-2, #311), built as it ships: -trimpath and -ldflags "-s -w",
# so go tool nm reports no symbol table, and the run number as the build number of its one version. It
# carries the signed ranz-node.exe of its architecture as its Payload, and the signed rqlited.exe, the rqlite
# member of a Controller (ONE-4, #313). The committed controller/internal/payload/node_<arch>.exe and
# rqlited_<arch>.exe are empty placeholders, which this step overwrites in its own checkout before it
# builds, and writes empty again after. ranz.exe is then signed once, like every shipped executable. A
# second build carries a copy of the ranz-node.exe payload with one byte changed well inside it, never
# its MS-DOS or PE header, and is signed too: only its Payload is wrong, so ranz install must refuse it
# for that and for no other reason. The ranz.exe of each architecture also carries the wintun.dll of the
# pinned release and the wireguard.dll of the pinned WireGuardNT SDK (SDN-80, #375), and the x64 one the
# files of the XDP runtime (ONE-3, #312), written over the placeholders of controller/internal/payload
# (wintun_<arch>.dll, wireguard_<arch>.dll and xdp/) and emptied again after. A third x64 build,
# x64-xdpfail, carries the same Payloads with one byte of xdp.sys changed well inside it: ranz install must
# refuse the XDP runtime and nothing else, and the Node must still be installed.
$build = $env:GITHUB_RUN_NUMBER
if (-not $build) { $build = '0' }
Push-Location $GoModuleDir
try {
	foreach ($pair in @(@{ Dir = $X64Dir; Arch = 'x64'; Goarch = 'amd64' }, @{ Dir = $Arm64Dir; Arch = 'arm64'; Goarch = 'arm64' })) {
		$goarch = $pair.Goarch
		$placeholder = Join-Path (Get-Location).Path "controller/internal/payload/node_$goarch.exe"
		# Read by the .NET method itself: a function would hand the array over one byte at a time
		[byte[]] $nodeBytes = [System.IO.File]::ReadAllBytes((Join-Path $pair.Dir 'ranz-node.exe'))
		# The rqlite member, the same x64 file for both architectures (ONE-4, #313)
		[byte[]] $memberBytes = [System.IO.File]::ReadAllBytes($member)
		[System.IO.File]::WriteAllBytes((Join-Path (Get-Location).Path "controller/internal/payload/rqlited_$goarch.exe"), $memberBytes)
		# The Wintun DLL of this architecture, and for x64 the XDP runtime (ONE-3, #312), as they were fetched
		[byte[]] $wintunBytes = [System.IO.File]::ReadAllBytes($wintunDlls[$pair.Arch])
		[System.IO.File]::WriteAllBytes((Join-Path (Get-Location).Path "controller/internal/payload/wintun_$goarch.dll"), $wintunBytes)
		# The WireGuardNT DLL of this architecture (SDN-80, #375), as it was fetched
		[byte[]] $wireguardBytes = [System.IO.File]::ReadAllBytes($wireguardDlls[$pair.Arch])
		[System.IO.File]::WriteAllBytes((Join-Path (Get-Location).Path "controller/internal/payload/wireguard_$goarch.dll"), $wireguardBytes)
		$variants = @('', '-tampered')
		if ($pair.Arch -eq 'x64') {
			foreach ($name in $xdpNames) {
				[byte[]] $xdpBytes = [System.IO.File]::ReadAllBytes((Join-Path $xdpDir $name))
				[System.IO.File]::WriteAllBytes((Join-Path (Get-Location).Path "controller/internal/payload/xdp/$name"), $xdpBytes)
			}
			$variants += '-xdpfail'
		}
		$env:GOOS = 'windows'
		$env:GOARCH = $goarch
		$env:CGO_ENABLED = '0'
		foreach ($variant in $variants) {
			$payload = $nodeBytes.Clone()
			if ($variant -eq '-tampered') {
				$mid = [int]($payload.Length / 2)
				$payload[$mid] = [byte]($payload[$mid] -bxor 0xFF)
			}
			[System.IO.File]::WriteAllBytes($placeholder, $payload)
			# The XDP driver with one byte changed, for the third build only; the others carry it as it is
			if ($pair.Arch -eq 'x64') {
				[byte[]] $sysBytes = [System.IO.File]::ReadAllBytes((Join-Path $xdpDir 'xdp.sys'))
				if ($variant -eq '-xdpfail') {
					$mid = [int]($sysBytes.Length / 2)
					$sysBytes[$mid] = [byte]($sysBytes[$mid] -bxor 0xFF)
				}
				[System.IO.File]::WriteAllBytes((Join-Path (Get-Location).Path 'controller/internal/payload/xdp/xdp.sys'), $sysBytes)
			}
			$exeDir = Join-Path $OutDir "$($pair.Arch)$variant"
			New-Item -ItemType Directory -Force -Path $exeDir | Out-Null
			$goexe = Join-Path $exeDir 'ranz.exe'
			go build -trimpath -ldflags "-s -w -X main.build=$build" -o $goexe ./controller/cmd/ranz
			if ($LASTEXITCODE -ne 0) { throw "go build failed for $goarch$variant (exit $LASTEXITCODE)" }
			if ($variant -eq '') {
				$nm = (go tool nm $goexe 2>&1 | Out-String)
				if ($nm -notmatch 'no symbols') { throw "ranz ($goarch) still has a symbol table after -ldflags '-s -w':`n$nm" }
				Write-Host "ranz ($goarch): -trimpath -ldflags '-s -w', no symbol table, ranz-node.exe ($($nodeBytes.Length) bytes), rqlited.exe ($($memberBytes.Length) bytes), wintun.dll ($($wintunBytes.Length) bytes) and wireguard.dll ($($wireguardBytes.Length) bytes) as its Payloads"
			}
			Protect-File $signtool $thumb $goexe
		}
	}
} finally {
	foreach ($goarch in @('amd64', 'arm64')) {
		[System.IO.File]::WriteAllBytes((Join-Path (Get-Location).Path "controller/internal/payload/node_$goarch.exe"), [byte[]]@())
		[System.IO.File]::WriteAllBytes((Join-Path (Get-Location).Path "controller/internal/payload/rqlited_$goarch.exe"), [byte[]]@())
		[System.IO.File]::WriteAllBytes((Join-Path (Get-Location).Path "controller/internal/payload/wintun_$goarch.dll"), [byte[]]@())
		[System.IO.File]::WriteAllBytes((Join-Path (Get-Location).Path "controller/internal/payload/wireguard_$goarch.dll"), [byte[]]@())
	}
	foreach ($name in @('xdp.sys', 'xdpapi.dll', 'xdp.cat', 'xdp.inf', 'xdppcw.man')) {
		[System.IO.File]::WriteAllBytes((Join-Path (Get-Location).Path "controller/internal/payload/xdp/$name"), [byte[]]@())
	}
	Pop-Location
	Remove-Item Env:\GOOS, Env:\GOARCH, Env:\CGO_ENABLED -ErrorAction SilentlyContinue
}

Write-Host 'self-integrity.ps1: signing, the self-integrity check and symbol stripping all passed'

# The last native command above is "go tool nm" on a stripped binary, which exits 1 when it finds no
# symbols. That is the success case here, but the non-zero code lingers in $LASTEXITCODE, and the pwsh
# step wrapper returns $LASTEXITCODE as the step result. Every real failure throws above (ErrorAction is
# Stop), so reaching this line means success. Exit 0 so the step passes.
exit 0
