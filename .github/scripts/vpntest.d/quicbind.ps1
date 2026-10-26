# Run by vpntest.ps1 after the checks of the quicbind test (CORE-H5 #408), with the output of the test in $full: the cost
# of the binding to the exporter of the QUIC connection against the binding to the certificate goes into the job log
$full | ? { $_ -cmatch '^QUICBIND COST ' } | % { Write-Host $_ }
