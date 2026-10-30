# Run by vpntest.ps1 after the checks of the punchpath test (CORE-S5-7 #413), with the output of the test in $full: each step
# with the checks that it passed, and what it saw (the NAT and the prediction of each Node, how long ICE took to give the pair
# up, the probes of each attempt and the most punch messages within a second, the answer to the attacker, the time from the
# attempt after the backoff to the direct path, the Fallback, the punches that each Node exported, and the success rate and
# the time of each seed of the two loads), go into the job log, so that the log shows every behaviour that the acceptance
# criteria of #413 name
$full | ? { $_ -cmatch '^\[[a-g]\. |^  \[(PASS|INFO)\] |^PUNCHPATH SEEDS ' } | % { Write-Host $_ }
