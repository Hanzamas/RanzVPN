# appverif.ps1
# The Application Verifier gate of ADR-0040 item 4: the tests of the new core (coretest, through
# .github/scripts/coretest.ps1) run with the Heaps, Handles and Locks layers of Application Verifier,
# the native Windows tool that stands in for ThreadSanitizer, which Windows does not have.
#
# 1. The planted fault (appverif-fault.exe, .github/scripts/appverif-fault.c) runs under the same
#    layers first. It must be reported, by a verifier stop that ends the process or by an error entry
#    in its log; otherwise the verifier is not working and the job fails.
# 2. coretest runs every test it lists under the layers, one process per test through coretest.ps1.
#    A test that fails, a process that a verifier stop ends, or an error entry in the verifier log
#    of any test fails the job.
# The verifier settings of both images are removed at the end. The logs are exported as XML to
# <BuildDir>\appverif (uploaded by the job).
#
# Application Verifier command line: https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/application-verifier-testing-applications
#
# Usage: pwsh -File .github/scripts/appverif.ps1 [-BuildDir build] [-FaultExe build\appverif-fault.exe]

param(
	[string] $BuildDir = 'build',
	[string] $FaultExe = ''
)

$ErrorActionPreference = 'Stop'
# A failing test must not stop the script before the verifier logs are read
$PSNativeCommandUseErrorActionPreference = $false

$Layers = @('Heaps', 'Handles', 'Locks')
$AppVerif = Join-Path $env:windir 'System32\appverif.exe'
$LogDir = Join-Path $env:USERPROFILE 'AppVerifierLogs'
$OutDir = Join-Path $BuildDir 'appverif'

if (-not (Test-Path -LiteralPath $AppVerif)) { throw "$AppVerif not found: Application Verifier is not installed" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Invoke-AppVerif([string[]] $Arguments) {
	$out = (& $AppVerif @Arguments 2>&1 | Out-String)
	$code = $LASTEXITCODE
	return @{ Code = $code; Text = $out.Trim() }
}

# Turn the layers on for one image name, with its old logs deleted
function Enable-Verifier([string] $Image) {
	Invoke-AppVerif @('-delete', 'logs', '-for', $Image) | Out-Null
	Get-ChildItem -LiteralPath $LogDir -Filter "$Image.*" -ErrorAction SilentlyContinue | Remove-Item -Force
	$r = Invoke-AppVerif (@('-enable') + $Layers + @('-for', $Image))
	Write-Host "appverif -enable $($Layers -join ' ') -for ${Image}: exit $($r.Code) $($r.Text)"
	if ($r.Code -ne 0) { throw "appverif could not turn the layers on for $Image" }
	$r = Invoke-AppVerif @('-query', '*', '-for', $Image)
	Write-Host $r.Text
}

function Disable-Verifier([string] $Image) {
	$r = Invoke-AppVerif @('-disable', '*', '-for', $Image)
	Write-Host "appverif -disable * -for ${Image}: exit $($r.Code)"
}

# The log of the image's last run exported as XML (appverif exports the last log, Log=0, of a
# process that ran with the layers; older logs are not addressable by index); returns its error
# entries, one line each
function Get-VerifierErrors([string] $Image, [string] $Run) {
	$logs = @(Get-ChildItem -LiteralPath $LogDir -Filter "$Image.*.dat" -ErrorAction SilentlyContinue)
	if ($logs.Count -eq 0) { throw "${Image} ($Run): no verifier log in $LogDir, so the layers did not run" }
	$xml = Join-Path (Resolve-Path $OutDir).Path "$Image.$Run.xml"
	$r = Invoke-AppVerif @('-export', 'log', '-for', $Image, '-with', "To=$xml", 'Log=0')
	if (-not (Test-Path -LiteralPath $xml)) {
		throw "appverif could not export the log of ${Image} ($Run): exit $($r.Code) $($r.Text)"
	}
	$errors = @()
	$text = Get-Content -Raw -LiteralPath $xml
	foreach ($m in [regex]::Matches($text, '(?s)<avrf:logEntry\b([^>]*)>(.*?)</avrf:logEntry>')) {
		if ($m.Groups[1].Value -notmatch 'Severity="Error"') { continue }
		$layer = if ($m.Groups[1].Value -match 'LayerName="([^"]*)"') { $Matches[1] } else { '?' }
		$stop = if ($m.Groups[1].Value -match 'StopCode="([^"]*)"') { $Matches[1] } else { '?' }
		$message = if ($m.Groups[2].Value -match '(?s)<avrf:message>(.*?)</avrf:message>') { $Matches[1].Trim() } else { '' }
		$errors += "$Run, layer $layer, stop $stop`: $message"
	}
	return $errors
}

$failed = @()

# 1. The planted fault
if ($FaultExe) {
	$image = Split-Path -Leaf $FaultExe
	Enable-Verifier $image
	try {
		$out = (& $FaultExe 2>&1 | Out-String)
		$code = $LASTEXITCODE
		Write-Host "${image}: exit code $code"
		Write-Host $out
		$errors = @(Get-VerifierErrors $image 'fault')
		$errors | ForEach-Object { Write-Host "  $_" }
		if ($code -eq 0 -and $errors.Count -eq 0) {
			$failed += "the planted fault of $image went unreported: Application Verifier does not work in this job"
		} else {
			Write-Host "The planted fault is reported (exit code $code, $($errors.Count) error entries): the verifier works"
		}
	} finally {
		Disable-Verifier $image
	}
}

# 2. The tests of the new core: every test that coretest lists (its usage, read before the layers
# are on), each through coretest.ps1 (RANZ_CORE_TESTS) in a process of its own, whose log is read
# right after it
$image = 'coretest.exe'
$usage = (& (Join-Path $BuildDir $image) 2>&1 | Out-String)
$tests = @([regex]::Matches($usage, "(?m)^ '(\w+)' :") | ForEach-Object { $_.Groups[1].Value })
if ($tests.Count -eq 0) { throw "coretest lists no test:`n$usage" }
Write-Host "coretest tests: $($tests -join ', ')"
Enable-Verifier $image
try {
	foreach ($test in $tests) {
		$env:RANZ_CORE_TESTS = $test
		$out = (cmd /c "pwsh -NoProfile -ExecutionPolicy Bypass -File .github/scripts/coretest.ps1 -BuildDir $BuildDir 2>&1") | Out-String
		$code = $LASTEXITCODE
		Write-Host $out
		if ($code -ne 0) { $failed += "coretest $test under Application Verifier failed (exit code $code): the test failed or a verifier stop ended it" }
		$errors = @(Get-VerifierErrors $image $test)
		$errors | ForEach-Object { Write-Host "  $_" }
		if ($errors.Count -gt 0) { $failed += "Application Verifier reported $($errors.Count) errors in coretest $test" }
	}
} finally {
	Remove-Item Env:RANZ_CORE_TESTS -ErrorAction SilentlyContinue
	Disable-Verifier $image
}

if ($failed.Count -gt 0) {
	$failed | ForEach-Object { Write-Host "::error::$_" }
	exit 1
}
Write-Host "coretest passed under Application Verifier ($($Layers -join ', ')) with no error"
