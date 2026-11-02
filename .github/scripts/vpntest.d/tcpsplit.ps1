# Run by vpntest.ps1 after the checks of the tcpsplit test (CORE-P2-3 #94), with the output of the test in $full: each part and
# each check that it passed go into the job log, with the counters of the two nodes, so that the log shows the split Networks of
# a desired state from the wire and the Capability tcpSplit, splitting off by default and on per L3 Network, the connect, the
# data, the half-close, the refusal, the resets of either end and the timeout that map to the far side, and the UDP datagram and
# the Network without splitting that take the packet path, as the acceptance criteria of #94 name them
$full | ? { $_ -cmatch '^\[(control|connect|refused|untouched)|^  \[(PASS|INFO)\] ' } | % { Write-Host $_ }
