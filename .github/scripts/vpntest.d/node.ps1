# Run by vpntest.ps1 after the checks of the node test (CORE-F3 #63), with the output of the test in $full: how many swaps each
# round of the swap case did under the readers (#437). A busy runner does fewer in the same time, and the check of the
# generations waits for the rest, so the job log shows how busy the runner was
$full | ? { $_ -cmatch '^  \d+ swaps in \d+ ms under \d+ readers' } | % { Write-Host $_ }
