# Run by vpntest.ps1 after the checks of the grouppolicy test (SDN-87 #386), with the output of the test in $full: each part
# and each check that it passed go into the job log, so that the log shows, over noise, vxlan and geneve, the rule written by
# tag that allows or denies a packet by the source group that it carries, the claims that node-b refused, counted and logged,
# the packets that the map of address to group judged, and the tag modes trusted-underlay and off, as the acceptance
# criteria of #386 name them
$full | ? { $_ -cmatch '^\[(the |frame version)|^  \[PASS\] ' } | % { Write-Host $_ }
