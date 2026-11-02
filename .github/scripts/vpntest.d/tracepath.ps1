# Run by vpntest.ps1 after the checks of the tracepath test (SDN-89 #388), with the output of the test in $full: each part
# and each check that it passed go into the job log, so that the log shows, over noise, vxlan and geneve, the records of a
# traced packet at the two nodes that it crosses, each with the group and the verdict, the node whose trace is off that
# forwards the packet with the option, and the datagrams on the wire with the trace off and on, as the acceptance criteria
# of #388 name them
$full | ? { $_ -cmatch '^\[the |^  \[PASS\] ' } | % { Write-Host $_ }
