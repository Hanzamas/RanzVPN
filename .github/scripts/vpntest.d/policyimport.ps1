# Run by vpntest.ps1 after the checks of the policyimport test. The report of the frames through the new core is compared
# with the golden file policyimport_frames.txt, which holds what the fork did with them at the last run of its oracle, the
# server that CORE-S8-3 (#577) retired, so the test must fail on a planted change of that file
Assert-FailsOnPlantedGolden 'policyimport' 'policyimport' 'policyimport_frames.txt'
