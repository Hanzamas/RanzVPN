# Run by vpntest.ps1 after the checks of the lossylink test (CORE-S2-1 #69), with the output of the test in $full: the
# goodput of an inner TCP with CoDel and without goes into the job log
$full | ? { $_ -cmatch '^\[the lossy link|^  the (outer|inner) TCP|dropped at \(ms\)' } | % { Write-Host $_ }
