# Run by vpntest.ps1 after the checks of the exit node test (SDN-55 #248), with the output of the test in $full: each part of
# the test with the checks that passed, the answers of the pipe and the route that Windows took for each address go into the
# job log, which so shows that an IPv6 packet enters the adapter of an exit that carries no IPv6 and that no other interface
# takes it
$full | ? { $_ -cmatch '^  \[(PASS|INFO)\]|^\[' } | % { Write-Host $_ }
