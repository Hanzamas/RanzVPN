# Run by vpntest.ps1 after the checks of the hubspoke test (SDN-19 #195), with the output of the test in $full: each check
# that passed, the packets that the hub sent on from one spoke to another and the copies that its Mirror sent, and the
# packets that the policy of the VRF dropped at the hub (SDN-19-R2 #508) go into the job log
$full | ? { $_ -cmatch '^  \[PASS\]|^  node-h (sent on|dropped)' } | % { Write-Host $_ }
