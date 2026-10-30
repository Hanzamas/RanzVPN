# Run by vpntest.ps1 after the checks of the gateway test (SDN-19 #195), with the output of the test in $full: each check
# that passed, how the ECMP case spread its flows, how long the probes took to find a silent and a stopped gateway down
# and to move their traffic, and what the dials that held the thread of the overlay of node-a left of the probes
# (SDN-19-R1 #507) go into the job log
$full | ? { $_ -cmatch '^  \[PASS\]|^  ECMP:|^  silent failure|^  stop of|^  recovery of|^  standby failover|^  node-a:|^  \d+ dials held|^  gw-2 froze' } | % { Write-Host $_ }
