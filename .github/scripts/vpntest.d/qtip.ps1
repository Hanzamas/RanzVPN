# Run by vpntest.ps1 after the checks of the qtip test (CORE-S7-2 #83), with the output of the test in $full: each part
# with the checks that it passed, this host, the msquic release that ships QTIP and the lines of the transport log go into
# the job log, so that the log shows the default off, the rule of Windows Server x64 and the opt-in that the acceptance
# criteria of #83 name
$full | ? { $_ -cmatch '^\[|^  \[(PASS|LOG)\] |^  this host: |^  the msquic\.dll of vpntest |^  the XDP runtime ' } | % { Write-Host $_ }
