param([string] $Msi, [string] $Arch, [string] $LogDir)

# The shipped sidecar is stripped of symbols (SEC-3 #281, ADR-0036 amendment of 2026-10-22): the go build
# that fills build\msi\ranz-bgp.exe carries -trimpath and -ldflags "-s -w" (in .github/workflows/ranz-bgp.yml).
# .github/scripts/self-integrity.ps1 checks that the same flags leave no symbol table.

# The RanzBgp feature of the MSI (ranz-bgp/installer, CORE-S7-1 #82), installed on the runner of its
# architecture: a default install carries no ranz-bgp.exe, ADDLOCAL=RanzBgp adds the sidecar of the
# architecture of the package, REMOVE=RanzBgp takes it away and leaves the node feature, and an
# uninstall leaves nothing. External checks only: msiexec exit codes, files, the PE machine type and
# the output of ranz-bgp -version. The Windows Installer logs go to LogDir.

$ErrorActionPreference = 'Stop'

$dir = Join-Path $env:ProgramFiles 'Ranz VPN'
$exe = Join-Path $dir 'ranz-bgp.exe'
$gobgpLicense = Join-Path $dir 'ranz-bgp-GoBGP-LICENSE.txt'
$license = Join-Path $dir 'LICENSE.txt'
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# Run msiexec with the arguments and a verbose log; exit code 0 or 3010 (restart required) passes
function Invoke-Msi([string] $Name, [string[]] $Arguments) {
	$log = Join-Path $LogDir "$Name.log"
	$all = $Arguments + @('/qn', '/norestart', '/l*v', "`"$log`"")
	$p = Start-Process -FilePath 'msiexec.exe' -ArgumentList $all -Wait -PassThru
	Write-Host "msiexec $($Arguments -join ' '): exit code $($p.ExitCode)"
	if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) {
		Get-Content -LiteralPath $log -Tail 60 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
		throw "msiexec $Name exited with $($p.ExitCode)"
	}
}

# The machine type of a PE file: 0x8664 for x64, 0xAA64 for arm64
function Get-PeMachine([string] $Path) {
	$bytes = [System.IO.File]::ReadAllBytes($Path)
	$pe = [System.BitConverter]::ToInt32($bytes, 0x3C)
	return [System.BitConverter]::ToUInt16($bytes, $pe + 4)
}

function Assert-Files([string] $Step, [bool] $Sidecar) {
	if (-not (Test-Path -LiteralPath $license)) { throw "${Step}: $license is missing: the node feature is not installed" }
	foreach ($f in @($exe, $gobgpLicense)) {
		$present = Test-Path -LiteralPath $f
		if ($present -ne $Sidecar) { throw "${Step}: $f is $(if ($present) { 'present' } else { 'missing' })" }
	}
	Write-Host "${Step}: node feature installed, sidecar $(if ($Sidecar) { 'installed' } else { 'absent' })"
}

$msiPath = (Resolve-Path -LiteralPath $Msi).Path
$quoted = "`"$msiPath`""

# 1. A default install: the node feature only
Invoke-Msi 'install-default' @('/i', $quoted)
Assert-Files 'default install' $false

# 2. ADDLOCAL=RanzBgp: the sidecar of the architecture of the package
Invoke-Msi 'add-ranzbgp' @('/i', $quoted, 'ADDLOCAL=RanzBgp')
Assert-Files 'ADDLOCAL=RanzBgp' $true
$want = @{ 'x64' = 0x8664; 'arm64' = 0xAA64 }[$Arch]
$machine = Get-PeMachine $exe
if ($machine -ne $want) { throw ("ranz-bgp.exe has the machine type 0x{0:X4}, not 0x{1:X4} ({2})" -f $machine, $want, $Arch) }
$version = (& $exe -version | Out-String).Trim()
Write-Host "ranz-bgp -version: $version (machine type 0x$('{0:X4}' -f $machine))"
if ($LASTEXITCODE -ne 0 -or $version -notmatch '^ranz-bgp, GoBGP v') { throw "ranz-bgp -version: exit code $LASTEXITCODE, '$version'" }
if ((Get-Content -Raw -LiteralPath $gobgpLicense) -notmatch 'Apache License') { throw "$gobgpLicense is not the Apache License of GoBGP" }

# 3. REMOVE=RanzBgp: the sidecar goes, the node feature stays
Invoke-Msi 'remove-ranzbgp' @('/i', $quoted, 'REMOVE=RanzBgp')
Assert-Files 'REMOVE=RanzBgp' $false

# 4. The uninstall leaves nothing
Invoke-Msi 'uninstall' @('/x', $quoted)
if (Test-Path -LiteralPath $dir) { throw "uninstall: $dir is still there: $((Get-ChildItem -LiteralPath $dir -Recurse | ForEach-Object Name) -join ', ')" }
Write-Host "uninstall: $dir is gone"

Write-Host "RanzBgp feature ($Arch): optional, installed and removed on its own"
