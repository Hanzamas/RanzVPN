# Run by vpntest.ps1 after the checks of the profile test (SDN-40 #233), with the output of the test in $full: each check that
# it passed, and what the rate cases sent, took and dropped, go into the job log, so that the log shows every limit and every
# flag of a session profile that the acceptance criteria of #233 name
$full | ? { $_ -cmatch '^  \[PASS\] |^  the (download|upload) of node-b limited' } | % { Write-Host $_ }
