# Run by vpntest.ps1 after the checks of the trace test (SDN-89 #388), with the output of the test in $full: the encoding of
# the trace option in each carrier as the golden file holds it, and each check that the test passed, go into the job log,
# so that the log shows the bytes of the option, its critical bit clear, the node that does not know it, and the sizes with
# the trace off, as the acceptance criteria of #388 name them
$full | ? { $_ -cmatch '^  (trace 0x|  ranz frame|  geneve|  vxlan|  the critical bit|  a node that does not know|the trace of|  the packet of)|^  \[PASS\] ' } | % { Write-Host $_ }
