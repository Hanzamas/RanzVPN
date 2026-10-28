# Run by vpntest.ps1 after the checks of the directpath test (CORE-S5-6 #412), with the output of the test in $full: each step
# with the checks that it passed, and what it saw (how long ICE took to move the pair and to give the direct path up, the
# candidates of each Node, the STUN messages of the capture, the public port that the gateway granted and the counts that each
# Node exported), go into the job log, so that the log shows every behaviour of the direct path that the acceptance criteria
# of #412 name
$full | ? { $_ -cmatch '^\[[a-f]\. |^  \[(PASS|INFO)\] ' } | % { Write-Host $_ }
