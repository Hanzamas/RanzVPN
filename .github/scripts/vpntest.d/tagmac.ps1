# Run by vpntest.ps1 after the checks of the tagmac test (SDN-88 #387), with the output of the test in $full: the vectors of the
# MAC of the source group, which the golden file tests/golden/tagmac/tagmac_vectors.txt holds, and each check that the test passed
# go into the job log, as the acceptance criteria of #387 name them; vpntest.ps1 shows the BENCH lines of the cost of the MAC
$full | ? { $_ -cmatch '^  (\[|# |  )|^\[' } | % { Write-Host $_ }
