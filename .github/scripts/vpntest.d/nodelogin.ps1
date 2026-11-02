# Run by vpntest.ps1 after the checks of the nodelogin test. The error of NodeLogin for each case is compared with the golden
# file nodelogin_errors.txt, the table of the errors of the SE-VPN login of the oracle that CORE-S8-3 (#577) retired, so the
# test must fail on a planted change of that file
Assert-FailsOnPlantedGolden 'nodelogin' 'nodelogin' 'nodelogin_errors.txt'
