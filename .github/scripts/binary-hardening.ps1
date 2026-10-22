param(
	# The shipped binaries of the new core: each carries every mitigation below, or an exception
	# of $exceptions names why it cannot
	[string[]] $Path = @(),
	# The gate's own check: binaries built without the mitigations, which the gate must fail. No
	# exception applies to them.
	[string[]] $Unhardened = @()
)

$ErrorActionPreference = 'Stop'

# The exploit-mitigation flags of ADR-0039 decision 1 (SEC-1, #279), read from the shipped binary
# with dumpbin /headers and dumpbin /loadconfig, so that a flag a toolchain change drops fails the
# build rather than the build script:
# - CFG: /guard:cf, the Guard DLL characteristic and the "CF instrumented" guard flag of the load
#   configuration
# - CET: /CETCOMPAT, the "CET compatible" extended DLL characteristic (x64 only: ARM64 has no CET)
# - ASLR: /DYNAMICBASE with /HIGHENTROPYVA, the "Dynamic base" and "High Entropy Virtual
#   Addresses" DLL characteristics
# - DEP: /NXCOMPAT, the "NX compatible" DLL characteristic
# - GS: /GS. link.exe writes a VC feature record (the "feat" debug directory) that counts the
#   compilands built with /GS and with /sdl; every C/C++ compiland must be counted. lld-link
#   writes no such record, so without it the security cookie of the load configuration stands for
#   /GS.
# - SDL: /sdl, every C/C++ compiland of the VC feature record. Without the record the binary does
#   not show it, and only an exception passes it.
# The job summary gets one table row per binary.

# Why a binary may lack a mitigation, by file name and mitigation
$goToolchain = 'built by the Go toolchain, whose compiler and linker have no CFG, CET, /GS or /sdl; Go code has bounds checks and no stack buffers of C'
$exceptions = @{
	'ranz-node.exe'       = @{
		SDL = 'clang-cl, the compiler of ADR-0024, accepts /sdl and ignores it, and lld-link writes no VC feature record; its /GS is the strong stack protector of /sdl'
	}
	'ranz-controller.exe' = @{ CFG = $goToolchain; CET = $goToolchain; GS = $goToolchain; SDL = $goToolchain }
	'ranz.exe'            = @{ CFG = $goToolchain; CET = $goToolchain; GS = $goToolchain; SDL = $goToolchain }
	'ranz-bgp.exe'        = @{ CFG = $goToolchain; CET = $goToolchain; GS = $goToolchain; SDL = $goToolchain }
}

$mitigations = @('CFG', 'CET', 'ASLR', 'DEP', 'GS', 'SDL')

# dumpbin of the newest MSVC toolset of the runner's Visual Studio, for the architecture of the
# runner when it has one
$vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -property installationPath
$hostArch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }
$dumpbin = @(Get-ChildItem -Path "$vs\VC\Tools\MSVC\*\bin\Host$hostArch\$hostArch\dumpbin.exe" -ErrorAction SilentlyContinue) +
	@(Get-ChildItem -Path "$vs\VC\Tools\MSVC\*\bin\*\*\dumpbin.exe" -ErrorAction SilentlyContinue) |
	Select-Object -First 1
if (-not $dumpbin) { throw "No dumpbin.exe under $vs\VC\Tools\MSVC" }
Write-Host "dumpbin: $($dumpbin.FullName)"

# The mitigations that the binary $file lacks, as a hashtable of mitigation to what dumpbin showed
function Get-Missing([string] $file) {
	$headers = (& $dumpbin.FullName /nologo /headers $file | Out-String)
	if ($LASTEXITCODE -ne 0) { throw "dumpbin /headers $file exited with code $LASTEXITCODE" }
	$load = (& $dumpbin.FullName /nologo /loadconfig $file | Out-String)
	if ($LASTEXITCODE -ne 0) { throw "dumpbin /loadconfig $file exited with code $LASTEXITCODE" }

	$machine = if ($headers -match '(?m)^\s*[0-9A-F]+ machine \(([^)]+)\)') { $Matches[1] } else { '?' }
	$missing = @{}

	$guard = $headers -match '(?m)^\s+Guard\s*$'
	$instrumented = $load -match '(?i)CF instrumented'
	if (-not ($guard -and $instrumented)) { $missing.CFG = "Guard characteristic $guard, CF instrumented $instrumented" }

	if ($machine -match '^x64$' -and $headers -notmatch '(?i)CET compatible') {
		# What the debug directories hold instead, for the log
		$debug = if ($headers -match '(?s)Debug Directories(.*?)(\r?\n\s*\r?\n\s*\r?\n|Summary)') { $Matches[1].Trim() } else { 'no debug directories' }
		$missing.CET = "no CET compatible extended DLL characteristic; debug directories: $debug"
	}

	$dynamic = $headers -match '(?m)^\s+Dynamic base\s*$'
	$high = $headers -match '(?m)^\s+High Entropy Virtual Addresses\s*$'
	if (-not ($dynamic -and $high)) { $missing.ASLR = "Dynamic base $dynamic, High Entropy Virtual Addresses $high" }

	if ($headers -notmatch '(?m)^\s+NX compatible\s*$') { $missing.DEP = 'no NX compatible DLL characteristic' }

	if ($headers -match 'Counts: Pre-VC\+\+ 11\.00=(\d+), C/C\+\+=(\d+), /GS=(\d+), /sdl=(\d+)') {
		$c = [int] $Matches[2]; $gs = [int] $Matches[3]; $sdl = [int] $Matches[4]
		if ($c -eq 0 -or $gs -ne $c) { $missing.GS = "/GS on $gs of $c C/C++ compilands" }
		if ($c -eq 0 -or $sdl -ne $c) { $missing.SDL = "/sdl on $sdl of $c C/C++ compilands" }
	} else {
		$cookie = if ($load -match '(?m)^\s*([0-9A-F]+) Security Cookie') { [Convert]::ToUInt64($Matches[1], 16) } else { 0 }
		if ($cookie -eq 0) { $missing.GS = 'no VC feature record and no security cookie in the load configuration' }
		$missing.SDL = 'no VC feature record: the binary does not show /sdl'
	}

	return @{ Machine = $machine; Missing = $missing }
}

$failures = @()
$summary = @('| Binary | Machine | ' + ($mitigations -join ' | ') + ' |', '|---|---|' + ('---|' * $mitigations.Count))

foreach ($file in $Path) {
	$name = Split-Path -Leaf $file
	$r = Get-Missing $file
	$excused = if ($exceptions.ContainsKey($name)) { $exceptions[$name] } else { @{} }
	$cells = @()
	Write-Host "${name} ($($r.Machine)):"
	foreach ($m in $mitigations) {
		if (-not $r.Missing.ContainsKey($m)) {
			Write-Host "  [PASS] $m"
			$cells += 'yes'
			if ($excused.ContainsKey($m)) { Write-Host "  note: $name carries $m, which its exception says it cannot: the exception can go" }
		} elseif ($excused.ContainsKey($m)) {
			Write-Host "  [EXCEPTION] ${m}: $($r.Missing[$m]); $($excused[$m])"
			$cells += 'exception'
		} else {
			Write-Host "  [FAIL] ${m}: $($r.Missing[$m])"
			$cells += '**missing**'
			$failures += "${name}: $m ($($r.Missing[$m]))"
		}
	}
	$summary += "| $name | $($r.Machine) | " + ($cells -join ' | ') + ' |'
}

foreach ($file in $Unhardened) {
	$name = Split-Path -Leaf $file
	$r = Get-Missing $file
	if ($r.Missing.Count -eq 0) {
		$failures += "${name}: built without the mitigations, but the gate passed it"
	} else {
		Write-Host "${name} ($($r.Machine)), built without the mitigations, fails the gate as it must: $(($r.Missing.Keys | Sort-Object) -join ', ')"
	}
}

if ($env:GITHUB_STEP_SUMMARY -and $Path.Count -gt 0) {
	@('### Binary hardening (ADR-0039)', '') + $summary + @('') | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Encoding utf8 -Append
}

if ($failures.Count -gt 0) {
	$failures | ForEach-Object { Write-Host "::error::$_" }
	throw "$($failures.Count) mitigations missing (ADR-0039 decision 1)"
}
Write-Host "Every binary carries CFG, CET, ASLR, DEP, /GS and /sdl, or an exception says why not"
