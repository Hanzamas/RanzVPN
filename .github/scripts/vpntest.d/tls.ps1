# Run by vpntest.ps1 after the checks of the tls test (CORE-S2-1 #69), with the output of the test in $full: what the TLS
# transport measured goes into the job log, the build, the Schannel group list and the version, suite and group of each
# handshake, and the ingress queue on TLS-443
$full | ? { $_ -cmatch "^  Windows build|^  the machine's list|^  client: |records sent: " } | % { Write-Host $_ }
