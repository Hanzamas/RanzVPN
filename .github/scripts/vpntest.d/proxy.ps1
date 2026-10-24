# Run by vpntest.ps1 after the checks of the proxy test (SDN-61 #254), with the output of the test in $full: each check of
# the outbound path, the interfaces that the underlay was bound to and how long the dials along the system's proxy took
# go into the job log
$full | ? { $_ -cmatch '^\[|^  \[(PASS|FAIL)\] |^  (the dial|the cancelled dial|the loopback interface|a non-loopback interface|the machine has no other)' } | % { Write-Host $_ }
