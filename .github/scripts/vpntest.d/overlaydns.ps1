# Run by vpntest.ps1 after the checks of the overlaydns test (SDN-11 #187), with the output of the test in $full: the
# NRPT rules read back, the names that the DNS client resolved and each check that passed go into the job log, under the
# name of each part of the test
$full | ? { $_ -cmatch '^  \[INFO\]|^  \[PASS\]|^\[' } | % { Write-Host $_ }
