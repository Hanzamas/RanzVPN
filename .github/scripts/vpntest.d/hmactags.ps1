# Run by vpntest.ps1 after the checks of the hmactags test (SDN-88 #387), with the output of the test in $full: each part and
# each check that it passed go into the job log, so that the log shows, over geneve in the tag mode hmac, the source group with
# a valid MAC that is honoured, the forged tag, the wrong key, the changed inner header, the timestamps outside the window and the
# option without a MAC that the injector sends and that are dropped as if the option were missing, and each step of the rotation
# of the key during which the open flow loses no packet, as the acceptance criteria of #387 name them
$full | ? { $_ -cmatch '^\[the |^  \[PASS\] ' } | % { Write-Host $_ }
