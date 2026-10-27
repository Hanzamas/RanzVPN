# Run by vpntest.ps1 after the checks of the hubspoke test (SDN-19 #195), with the output of the test in $full: each check
# that passed and the packets that the hub sent on from one spoke to another go into the job log
$full | ? { $_ -cmatch '^  \[PASS\]|^  node-h sent on' } | % { Write-Host $_ }
