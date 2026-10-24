# Run by vpntest.ps1 after the checks of the vrfadapter test (SDN-5 #181), with the output of the test in $full: the
# adapters of the VRFs with their GUIDs, the forwarding that Windows reads back and each check that passed go into the
# job log, under the name of each part of the test
$full | ? { $_ -cmatch '^  \[INFO\]|^  \[PASS\]|^\[' } | % { Write-Host $_ }
