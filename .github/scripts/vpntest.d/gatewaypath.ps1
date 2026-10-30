# Run by vpntest.ps1 after the checks of the gatewaypath test (SDN-19-R1 #507), with the output of the test in $full: each
# check that passed, how long node-a and the hub node-h took to find gw-1 down when its datagrams were lost and up again when
# they came back, and what node-h probed and sent on, go into the job log
$full | ? { $_ -cmatch '^  \[PASS\]|^  datagrams of gw-1|^  node-h:' } | % { Write-Host $_ }
