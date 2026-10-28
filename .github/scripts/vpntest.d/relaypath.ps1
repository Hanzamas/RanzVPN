# Run by vpntest.ps1 after the checks of the relaypath test (CORE-S5-5 #411), with the output of the test in $full: each step
# with the checks that it passed, and what the capture saw on the links of node-a and node-b with relay-1, go into the job
# log, so that the log shows every behaviour of the relay path that the acceptance criteria of #411 name
$full | ? { $_ -cmatch '^\[[a-g]\. |^  \[(PASS|INFO)\] ' } | % { Write-Host $_ }
