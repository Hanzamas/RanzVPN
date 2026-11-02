# Run by vpntest.ps1 after the checks of the pqtls test (CORE-P2-5 #382), with the output of the test in $full: what each step
# found goes into the job log, the Windows build, ML-KEM in CNG and the TLS group list in force, the groups that node-c's
# ClientHello offers, and the key exchange group that the stacks of the two Nodes reported for the session of each path,
# with the hybrid switched on and switched off
$full | ? { $_ -cmatch '^\[switched |^  \[GROUP\] ' } | % { Write-Host $_ }
