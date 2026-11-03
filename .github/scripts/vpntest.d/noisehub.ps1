# Run by vpntest.ps1 after the checks of the noisehub test. The Hub output of its Noise path is compared with the golden file
# noisehub_frames.txt, the Hub output of the oracle that CORE-S8-3 (#577) retired, so the test must fail on a planted change
# of that file
Assert-FailsOnPlantedGolden 'noisehub' 'noisehub' 'noisehub_frames.txt'
