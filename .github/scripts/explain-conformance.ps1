param([string] $BuildDir = 'build')

$ErrorActionPreference = 'Stop'

# The explain conformance (SDN-15, #191; ADR-0031 decision 8): explain is checked against the real data plane. Each
# scenario of tests/explain, a topology, an intent and test packets with their verdicts, runs through explain in the
# controller (the Go tests of controller/internal/explain and controller/internal/controller, in ranz.yml) and through
# the data plane of real nodes in vpntest (src/vpntest/explaintest.c), here:
# - ranz-explainplan compiles the intent of each scenario as the controller does and writes its plan: the state of each
#   node as the control protocol carries it, and each packet with the verdict of explain. It fails when explain does
#   not give a packet the verdict of its scenario.
# - vpntest explain runs the plans of tests/explain: each node takes its state from a stand-in controller over its own
#   control stream, each packet goes in at the host of its node, and it must end where explain says, with the rules
#   that explain names. It must print EXPLAIN TEST OK and no leak.
# - vpntest explain runs the plans of tests/explain/broken, whose fault gives a node a state without one of its rules:
#   the suite must fail, on the packets that the fault of each scenario names and on nothing else.

$bin = (Resolve-Path $BuildDir).Path
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$planner = Join-Path $bin 'ranz-explainplan.exe'
$vpntest = Join-Path $bin 'vpntest.exe'
$scenarios = Join-Path $repo 'tests\explain'
$brokenScenarios = Join-Path $scenarios 'broken'
$plans = Join-Path $bin 'explain-plans'
$brokenPlans = Join-Path $bin 'explain-broken'

foreach ($pair in @(@($scenarios, $plans), @($brokenScenarios, $brokenPlans))) {
	if (Test-Path -LiteralPath $pair[1]) { Remove-Item -Recurse -Force -LiteralPath $pair[1] }
	& $planner -o $pair[1] $pair[0]
	if ($LASTEXITCODE -ne 0) { throw "ranz-explainplan exited with code $LASTEXITCODE for $($pair[0])" }
}

# vpntest explain over the plans of a directory: its output, which the log shows
function Invoke-Explain([string] $dir) {
	$out = @(Write-Output "q\n" | & $vpntest explain $dir)
	$out | % { Write-Host $_ }
	return $out
}

# The scenarios: the data plane gives every packet the verdict of explain
$out = Invoke-Explain $plans
if (@($out | ? { $_ -cmatch '^EXPLAIN TEST OK$' }).Count -ne 1) { throw 'vpntest explain: the data plane does not give every packet of tests/explain the verdict of explain' }
if (@($out | ? { $_ -cmatch 'NO MEMORY LEAKS' }).Count -ne 1) { throw 'vpntest explain leaked memory' }

# The broken scenarios: the suite fails on the packets that the fault of each names, and on nothing else
$breaks = @()
foreach ($file in Get-ChildItem -LiteralPath $brokenScenarios -Filter '*.json') {
	$s = Get-Content -Raw -LiteralPath $file.FullName | ConvertFrom-Json
	foreach ($b in @($s.fault.breaks)) { $breaks += "EXPLAIN DIFFER $($file.BaseName) $b" }
}
if ($breaks.Count -eq 0) { throw "no scenario of $brokenScenarios has a fault that breaks a packet" }
$out = Invoke-Explain $brokenPlans
$failed = @($out | ? { $_ -cmatch '^  \[FAIL\] ' })
$differ = @($failed | % { if ($_ -cmatch '^  \[FAIL\] (EXPLAIN DIFFER \S+ \S+):') { $Matches[1] } })
if (@($out | ? { $_ -cmatch '^EXPLAIN TEST FAILED' }).Count -ne 1) { throw 'vpntest explain passed the broken scenario: the suite did not see that the data plane and explain disagree' }
if ($differ.Count -ne $failed.Count) { throw 'vpntest explain failed the broken scenario on a check other than a packet whose verdicts differ' }
if ((@($differ | Sort-Object) -join ', ') -ne (@($breaks | Sort-Object) -join ', ')) { throw "the broken scenario failed on '$($differ -join ', ')', and its fault breaks '$($breaks -join ', ')'" }
if (@($out | ? { $_ -cmatch 'NO MEMORY LEAKS' }).Count -ne 1) { throw 'vpntest explain leaked memory on the broken scenario' }
Write-Host "the broken scenario fails the suite on $($differ -join ', '), the packets that its fault breaks"
Write-Host 'ok'
