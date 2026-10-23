param([string] $BuildDir = 'build')

$ErrorActionPreference = 'Stop'

# Benchmark results: every "BENCH ..." line of the named tests is printed, also when the test passes, and
# saved to harness-out\bench-<arch>.txt (uploaded with the harness-out artifact). This script does not judge
# them; the performance regression gate of windows.yml (.github/scripts/bench-gate.py, ADR-0040 item 5)
# compares the file with the recorded medians. ARCHITECTURE (x64, arm64) names the file; without it the
# architecture of the machine does.
if ($env:ARCHITECTURE) {
	$benchArch = $env:ARCHITECTURE
} elseif ($env:PROCESSOR_ARCHITEW6432) {
	$benchArch = $env:PROCESSOR_ARCHITEW6432
} else {
	$benchArch = $env:PROCESSOR_ARCHITECTURE
}
switch ($benchArch) {
	'AMD64' { $benchArch = 'x64' }
	'ARM64' { $benchArch = 'arm64' }
}
if (-not $benchArch) { $benchArch = 'unknown' }
$benchDir = Join-Path $BuildDir 'harness-out'
$benchFile = Join-Path $benchDir ('bench-' + $benchArch.ToLower() + '.txt')
if (Test-Path $benchFile) { Remove-Item $benchFile }

# Start/stop smoke test: server mode must exit without leaks
('s') | % {

	[String] $mode = $_
	Write-Host "testing: $mode"

	$full = (Write-Output "q\n" | & "$BuildDir\vpntest.exe" $mode)
	$t = ($full | Select-String -Pattern 'NO MEMORY LEAKS' -CaseSensitive)

	if (($t).Count -ne 1) {
		$full
		Write-Error 'failed'
		return $false
	} else {
		Write-Host 'ok'
	}
}

# Named self-tests: must print their OK marker and no leak. RANZ_SMOKE_TESTS (comma list) overrides the list.
$named = @('nthash', 'crypto', 'stun', 'watermark', 'stress', 'harness', 'bench', 'tickorigin', 'timeenc', 'nullsafe', 'charset', 'fileio', 'resources', 'threadpool', 'dns', 'trace', 'eventlog', 'certdl', 'str', 'udpaccel', 'selow', 'listenerbind', 'dllsearch', 'machineid', 'vmdetect', 'tcpip', 'x509', 'bufbounds', 'keepalive', 'packcap', 'storepacket', 'consoleline', 'tempdir', 'adminaudit', 'logwriter', 'logbound', 'slog', 'eraser', 'authtype', 'acpassword', 'sigleak', 'listeners', 'pktparse', 'vlantpid', 'icmpv6ns', 'pack_decode_bounds', 'tablecache', 'registry', 'certsig', 'x509root', 'rsasig', 'ptrkey', 'chaincerts', 'tlsctx', 'endian', 'svcargs', 'osinfo', 'fifo', 'node', 'nodesvc', 'nodelogin', 'store', 'transport', 'httplistener', 'harden', 'quic', 'tls', 'lossylink', 'noisehub', 'vrf', 'vxlan', 'shape', 'switch', 'switchbench')
if ($env:RANZ_SMOKE_TESTS) { $named = $env:RANZ_SMOKE_TESTS -split ',' | % { $_.Trim() } | ? { $_ } }

# The TLS transport (CORE-S2-1 #69) puts its key exchange groups first in the machine's Schannel group list, which an
# ECC Curve Order policy overrides. The runner image sets one (NistP384, NistP256): a CI run takes it off, so the list
# that the transport sets governs, as on a node without that policy. Only on a runner, whose machine goes after the job.
if ($env:GITHUB_ACTIONS -eq 'true') {
	$eccPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
	$eccCurves = (Get-ItemProperty -LiteralPath $eccPolicy -Name 'EccCurves' -ErrorAction SilentlyContinue).EccCurves
	if ($eccCurves) {
		try {
			Remove-ItemProperty -LiteralPath $eccPolicy -Name 'EccCurves' -ErrorAction Stop
			Write-Host ('ECC Curve Order policy of the runner image (' + ($eccCurves -join ', ') + ') taken off for the TLS transport')
		} catch {
			Write-Host ('ECC Curve Order policy of the runner image (' + ($eccCurves -join ', ') + ') could not be taken off: ' + $_)
		}
	}

	# The congestion control of the outer TCP of the TLS transport (the TCP-over-TCP amendment of ADR-0022: BBR2 where
	# Windows offers it). Windows has no choice per socket: each TCP setting template of the machine has its provider.
	# What this runner's templates use, for the record of each CI run, and whether Windows offers BBR2: the
	# InternetCustom template, which no connection uses without a transport filter, takes it and then gets its own back.
	Get-NetTCPSetting -ErrorAction SilentlyContinue | % { Write-Host ('TCP setting template ' + $_.SettingName + ': congestion provider ' + $_.CongestionProvider) }
	$custom = (Get-NetTCPSetting -SettingName InternetCustom -ErrorAction SilentlyContinue).CongestionProvider
	$answer = (netsh int tcp set supplemental template=internetcustom congestionprovider=bbr2 | Out-String).Trim()
	$taken = (Get-NetTCPSetting -SettingName InternetCustom -ErrorAction SilentlyContinue).CongestionProvider
	Write-Host ('BBR2 on this runner: the InternetCustom template took "' + $taken + '" (netsh: ' + $answer + ')')
	if ($custom -and "$taken" -ne "$custom") {
		netsh int tcp set supplemental template=internetcustom congestionprovider=$custom | Out-Null
	}
}
$named | % {

	[String] $test = $_
	Write-Host "testing: $test"

	$full = (Write-Output "q\n" | & "$BuildDir\vpntest.exe" $test)
	$exit = $LASTEXITCODE

	# Benchmark lines before the result check, so a failed test still shows and saves them
	$bench = @($full | ? { $_ -cmatch '^BENCH ' -and $_ -cnotmatch '^BENCH TEST ' })
	if ($bench.Count -gt 0) {
		Write-Host "benchmark results of ${test}:"
		$bench | % { Write-Host $_ }
		New-Item -ItemType Directory -Force -Path $benchDir | Out-Null
		Add-Content -Path $benchFile -Value $bench -Encoding Ascii
	}

	$ok = ($full | Select-String -Pattern ($test.ToUpper() + ' TEST OK') -CaseSensitive)
	$leak = ($full | Select-String -Pattern 'NO MEMORY LEAKS' -CaseSensitive)

	if (($ok).Count -ne 1 -or ($leak).Count -ne 1) {
		$full
		Write-Host ('vpntest exit code of ' + $test + ': ' + $exit + ' (0x' + ('{0:X8}' -f $exit) + ')')
		Write-Error 'failed'
		return $false
	}

	# The harness must compare its golden files: a missing or empty golden directory switches a family to update
	# mode, which passes without comparing. RANZ_UPDATE_GOLDEN=1 is the deliberate way to record new files.
	if ($test -eq 'harness' -and $env:RANZ_UPDATE_GOLDEN -ne '1') {
		$missing = @('HARNESS GOLDEN MODE compare', 'HARNESS GOLDEN MODE pack compare', 'HARNESS GOLDEN MODE cmd compare') | ? {
			($full | Select-String -Pattern $_ -SimpleMatch -CaseSensitive).Count -ne 1
		}
		if ($missing) {
			$full
			Write-Error ("harness golden files not compared (missing: '" + ($missing -join "', '") + "')")
			return $false
		}
	}

	# The store test compares its golden dump of the fork configuration import in the same way (golden family "store")
	if ($test -eq 'store' -and $env:RANZ_UPDATE_GOLDEN -ne '1' -and ($full | Select-String -Pattern 'STORE GOLDEN MODE compare' -SimpleMatch -CaseSensitive).Count -ne 1) {
		$full
		Write-Error 'store golden files not compared (missing: STORE GOLDEN MODE compare)'
		return $false
	}

	# ... and the Noise-to-Hub test its Hub output, the oracle's (golden family "noisehub", CORE-S1-2 #68)
	if ($test -eq 'noisehub' -and $env:RANZ_UPDATE_GOLDEN -ne '1' -and ($full | Select-String -Pattern 'NOISEHUB GOLDEN MODE compare' -SimpleMatch -CaseSensitive).Count -ne 1) {
		$full
		Write-Error 'noisehub golden files not compared (missing: NOISEHUB GOLDEN MODE compare)'
		return $false
	}

	# The VRF test compares where the packets of its two VRFs on one range arrive with its golden file (golden family "vrf")
	if ($test -eq 'vrf' -and $env:RANZ_UPDATE_GOLDEN -ne '1' -and ($full | Select-String -Pattern 'VRF GOLDEN MODE compare' -SimpleMatch -CaseSensitive).Count -ne 1) {
		$full
		Write-Error 'vrf golden files not compared (missing: VRF GOLDEN MODE compare)'
		return $false
	}

	# ... and the switch test its frames, limits and counters (golden family "switch", CORE-S4-1 #74)
	if ($test -eq 'switch' -and $env:RANZ_UPDATE_GOLDEN -ne '1' -and ($full | Select-String -Pattern 'SWITCH GOLDEN MODE compare' -SimpleMatch -CaseSensitive).Count -ne 1) {
		$full
		Write-Error 'switch golden files not compared (missing: SWITCH GOLDEN MODE compare)'
		return $false
	}

	# The TLS transport and the lossy-link case (CORE-S2-1 #69) put what they measured into the job log: the build, the
	# Schannel group list and the version, suite and group of each handshake; the ingress queue on TLS-443; the goodput
	# of an inner TCP with CoDel and without
	if ($test -eq 'tls') {
		$full | ? { $_ -cmatch "^  Windows build|^  the machine's list|^  client: |records sent: " } | % { Write-Host $_ }
	}
	if ($test -eq 'lossylink') {
		$full | ? { $_ -cmatch '^\[the lossy link|^  the (outer|inner) TCP|dropped at \(ms\)' } | % { Write-Host $_ }
	}

	Write-Host 'ok'
}
