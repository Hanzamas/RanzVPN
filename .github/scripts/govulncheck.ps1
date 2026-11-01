param(
	[Parameter(Mandatory = $true)] [string] $Govulncheck,
	[string[]] $Module = @('.')
)

$ErrorActionPreference = 'Stop'

# govulncheck on each Go module of the new core (ADR-0039 decision 4; SEC-1, #279), for the
# Windows of the runner. Since ONE-1 (#310) there is one module, at the repository root: it holds
# the controller, the BGP sidecar and the CLI, the one executable ranz. A known vulnerability of
# the Go vulnerability database that the code of a module reaches, a call path to an affected
# function of a required module or of the standard library of the Go that builds it, fails the job
# unless $accepted records why it does not apply. govulncheck prints its text report for the log;
# its JSON findings decide.

# Why a reachable vulnerability does not apply, by module directory and ID. An entry goes once the
# database names a fixed version that go.mod pins, or the module no longer reaches the
# vulnerability; the job notes an entry that nothing reaches any more.
$accepted = @{
	'.' = @{
		'GO-2026-4736' = 'the database names no fixed version, but the fix (osrg/gobgp 583080a7, "server: fix malformed nexthop attribute crash", 2026-03-05, issue 3305) is in v4.10.0, which go.mod pins'
		'GO-2026-5288' = 'the database names no fixed version and no symbol, but the advisory (GHSA-9fw6-xgg2-mq9q, reviewed, 2.8.1 the last affected version) is of the sniff of Hysteria, a RequestHook of the server of the library that ranz mimic never sets: the Hysteria part gives the library no RequestHook and DisableUDP, whatever its settings (controller/internal/mimic/hysteriaserver.go:124-133, TestTheHysteriaListenerNeverTurnsOnTheSniff), and go.mod pins v2.13.0'
	}
}

$failed = @()
foreach ($m in $Module) {
	Write-Host "=== govulncheck $m"
	Push-Location $m
	try {
		# The text report exits with 3 when it finds a vulnerability, which the JSON findings below
		# decide on
		& $Govulncheck ./...
		$json = (& $Govulncheck -format json ./... | Out-String)
		if ($LASTEXITCODE -ne 0) { throw "${m}: govulncheck -format json exited with code $LASTEXITCODE" }
	} finally {
		Pop-Location
	}

	# The JSON stream is one indented object after another, each closing with "}" alone on its line
	$objects = @([regex]::Matches($json, '(?ms)^\{.*?^\}') | ForEach-Object { $_.Value | ConvertFrom-Json })
	$summary = @{}
	foreach ($o in $objects) {
		if ($o.osv) { $summary[$o.osv.id] = $o.osv.summary }
	}
	# A finding whose innermost frame names a function is reached by a call path; the others are
	# imported packages or required modules only
	$reached = @($objects | Where-Object { $_.finding -and @($_.finding.trace).Count -gt 0 -and $_.finding.trace[0].function } |
		ForEach-Object { $_.finding.osv } | Sort-Object -Unique)

	$ok = if ($accepted.ContainsKey($m)) { $accepted[$m] } else { @{} }
	foreach ($id in $reached) {
		if ($ok.ContainsKey($id)) {
			Write-Host "  [ACCEPTED] $id ($($summary[$id])): $($ok[$id])"
		} else {
			Write-Host "  [FAIL] $id ($($summary[$id]))"
			$failed += "${m}: $id ($($summary[$id]))"
		}
	}
	foreach ($id in $ok.Keys) {
		if ($reached -notcontains $id) { Write-Host "  note: $id is accepted for $m, which no longer reaches it: the entry can go" }
	}
	Write-Host "${m}: $($reached.Count) reachable vulnerabilities, $(@($reached | Where-Object { -not $ok.ContainsKey($_) }).Count) not accepted"
}

if ($failed.Count -gt 0) {
	$failed | ForEach-Object { Write-Host "::error::govulncheck: $_" }
	throw "$($failed.Count) reachable vulnerabilities (govulncheck)"
}
