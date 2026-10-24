# Run by vpntest.ps1 after the checks of the mirror test (SDN-23 #199), with the output of the test in $full: what the
# load offered the Mirror of 1 Mbit/s, what its rate limit allowed and what the sensor read go into the job log
$full | ? { $_ -cmatch '^\[the rate limit of a Mirror|^  \[INFO\] \d+ packets in' } | % { Write-Host $_ }
