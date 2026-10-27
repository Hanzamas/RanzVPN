# Run by vpntest.ps1 after the checks of the gateway test (SDN-19 #195), with the output of the test in $full: each check
# that passed, how the ECMP case spread its flows, and how long the probes took to find a silent and a stopped gateway down
# and to move their traffic go into the job log
$full | ? { $_ -cmatch '^  \[PASS\]|^  ECMP:|^  silent failure|^  stop of|^  recovery of|^  node-a:' } | % { Write-Host $_ }
