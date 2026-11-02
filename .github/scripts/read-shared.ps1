# Read-Shared, for the scripts that check a log of a Controller that is still running (AUD1-DT-18, #503; AUD1-DT-18-R2, #604).
# first-test.ps1, controller-service.ps1 and controller-frontdoor.ps1 dot-source this one: . (Join-Path $PSScriptRoot 'read-shared.ps1').
# controller-service.ps1 is run by ranz.yml and the other two by windows.yml, so both workflows read this file, and a change of it
# runs both.

# The text of a file that a process may still write to, always as one string. Get-Content -Raw is no stand-in for it on a log
# that a Controller writes: it reads until a read finds nothing and gives each read that found something as a string of its
# own, so a file that grows while it is read gives an array, and -notmatch on an array keeps the strings that do not hold the
# line, which an if takes for a miss. The step replace-certificate of first-test.ps1 has the runs and the measure. The file is
# opened to share with its writer, for reading and writing, as Get-Content opens it. Give it an absolute path: .NET opens a
# relative one from the folder of the process, which is not always the location of PowerShell.
function Read-Shared([string] $path) {
	if (-not (Test-Path -LiteralPath $path)) { return '' }
	$fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
	try {
		return (New-Object System.IO.StreamReader($fs)).ReadToEnd()
	} finally {
		$fs.Dispose()
	}
}
