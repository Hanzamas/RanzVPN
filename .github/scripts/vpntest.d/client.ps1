# Run by vpntest.ps1 after the checks of the client test (CORE-S3-1 #71), with the output of the test in $full: what the
# client role measured goes into the job log, the transports, the Wintun driver and the status of the pipe, under the
# name of each part of the test
$full | ? { $_ -cmatch '^  \[INFO\]|^\[' } | % { Write-Host $_ }
