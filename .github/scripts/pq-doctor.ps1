param([string] $BuildDir = 'build')

$ErrorActionPreference = 'Stop'

# The post-quantum key exchange of the host and ranz doctor (CORE-P2-5, #382). ranz doctor must tell whether the host can
# negotiate the hybrid X25519MLKEM768 on QUIC and TLS-443 and, where it cannot, what to run to switch it on; and that
# command, run as it stands, must switch it on. Schannel takes a change of the machine's TLS group list at once, and a
# change of an ECC Curve Order policy only when Windows starts, which a runner cannot do within its job (vpntest pqtls). So
# for a host whose CNG has ML-KEM the script:
# - switches the hybrid off by the machine's list, which names the classical groups only, with no policy; checks that ranz
#   doctor says that the host cannot negotiate X25519MLKEM768 and prints one reg add command, for the machine's list, and
#   that the sessions of vpntest pqtls probe, which changes nothing, negotiate one classical group at both ends of each
#   path; runs that command as ranz doctor printed it; checks that ranz doctor now says that the host can negotiate it, and
#   that the sessions of the probe negotiate X25519MLKEM768 at both ends of TLS-443, and of QUIC where msquic.dll is next
#   to vpntest;
# - switches it off by an ECC Curve Order policy that names the classical groups only, over a machine's list that names the
#   hybrid first; checks that ranz doctor says that the host cannot negotiate it, prints one reg add command, for the list
#   of the policy, and tells to restart Windows; runs that command as ranz doctor printed it; checks that ranz doctor now
#   says that the host can negotiate it.
# A host whose CNG has no ML-KEM must be told so, with the update that brings it, and its probe negotiates one classical
# group at both ends. The script puts the two lists of the machine back as it found them.

$bin = (Resolve-Path $BuildDir).Path
$ranz = Join-Path $bin 'ranz.exe'
$vpntest = Join-Path $bin 'vpntest.exe'
$machineKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002'
$policyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
$classical = @('curve25519', 'NistP256', 'NistP384')
$heading = 'Post-quantum key exchange (X25519MLKEM768 on QUIC and TLS-443)'
$restart = 'Then restart Windows: Schannel takes a changed ECC Curve Order policy when Windows starts.'
$work = Join-Path $env:RUNNER_TEMP 'pq-doctor'
New-Item -ItemType Directory -Force -Path $work | Out-Null

# The value EccCurves of a key, $null when it is not there
function Get-List([string] $key) {
	$item = Get-ItemProperty -LiteralPath $key -Name 'EccCurves' -ErrorAction SilentlyContinue
	if ($item) { return ,([string[]] @($item.EccCurves)) }
	return $null
}

# Write the value EccCurves of a key, or take it away for $null
function Set-List([string] $key, $list) {
	if ($null -eq $list) {
		if (Test-Path -LiteralPath $key) { Remove-ItemProperty -LiteralPath $key -Name 'EccCurves' -ErrorAction SilentlyContinue }
		return
	}
	if (-not (Test-Path -LiteralPath $key)) { New-Item -Path $key -Force | Out-Null }
	New-ItemProperty -LiteralPath $key -Name 'EccCurves' -PropertyType MultiString -Value ([string[]] $list) -Force | Out-Null
}

function Show-List($list) {
	if ($null -eq $list) { return 'none' }
	return ($list -join ', ')
}

# ranz doctor, which passes its checks and reports the post-quantum key exchange; its report, from its heading on
function Invoke-Doctor {
	$out = (& $ranz doctor | Out-String)
	if ($LASTEXITCODE -ne 0) { Write-Host $out; throw "ranz doctor exited with code $LASTEXITCODE" }
	$at = $out.IndexOf($heading)
	if ($at -lt 0) { Write-Host $out; throw 'ranz doctor printed no report of the post-quantum key exchange' }
	$report = $out.Substring($at)
	Write-Host $report
	return $report
}

# vpntest pqtls probe: the groups that the client and the server of each path negotiated under the list in force, by path
function Invoke-Probe {
	$out = @(& $vpntest pqtls probe)
	$out | ? { $_ -cmatch '^PQTLS PROBE ' } | % { Write-Host "  $_" }
	$groups = @{}
	foreach ($line in $out) {
		if ($line -cmatch '^PQTLS PROBE (tls|quic) up client (\S+) 0x[0-9A-F]+ server (\S+) 0x[0-9A-F]+') {
			$groups[$Matches[1]] = @($Matches[2], $Matches[3])
		}
	}
	if (@($out | Select-String -SimpleMatch -Pattern 'PQTLS TEST OK').Count -ne 1 -or -not $groups.ContainsKey('tls')) {
		$out | % { Write-Host $_ }
		throw 'vpntest pqtls probe did not bring its sessions up'
	}
	if (-not $groups.ContainsKey('quic')) { Write-Host '  msquic.dll is not next to vpntest: the probe has no QUIC session' }
	return $groups
}

# Both ends of every path of the probe negotiated the group want
function Assert-Groups($groups, [string] $want, [string] $what) {
	foreach ($path in $groups.Keys) {
		$g = $groups[$path]
		if ($g[0] -ne $want -or $g[1] -ne $want) { throw "${what}: the $path session negotiated $($g[0]) at its client and $($g[1]) at its server, not $want" }
	}
	Write-Host "${what}: every session of the probe negotiated $want at both ends ($(@($groups.Keys | Sort-Object) -join ', '))"
}

# Both ends of every path of the probe negotiated one classical group, a known group without ML-KEM, which is not
# quantum-resistant
function Assert-Classical($groups, [string] $what) {
	foreach ($path in $groups.Keys) {
		$g = $groups[$path]
		if ($g[0] -ne $g[1] -or $g[0] -cmatch 'MLKEM' -or $g[0] -eq 'none' -or $g[0] -eq 'unknown') {
			throw "${what}: the $path session negotiated $($g[0]) at its client and $($g[1]) at its server, not one classical group"
		}
	}
	Write-Host "${what}: every session of the probe negotiated one classical group at both ends ($(@($groups.Keys | Sort-Object | % { "$_ $($groups[$_][0])" }) -join ', '))"
}

$savedMachine = Get-List $machineKey
$savedPolicy = Get-List $policyKey
Write-Host "this runner: the machine's list $(Show-List $savedMachine), the policy's $(Show-List $savedPolicy)"

try {
	foreach ($case in @('machine', 'policy')) {
		if ($case -eq 'machine') {
			Write-Host "--- switched off: the machine's list names the classical groups only, and no policy sets one"
			Set-List $policyKey $null
			Set-List $machineKey $classical
			$key = 'HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002'
		} else {
			Write-Host "--- switched off: an ECC Curve Order policy names the classical groups only, over a machine's list that names the hybrid first"
			Set-List $machineKey (@('x25519_mlkem768') + $classical)
			Set-List $policyKey $classical
			$key = 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
		}

		$report = Invoke-Doctor
		if ($report -match 'ML-KEM in CNG: no') {
			# A host whose CNG has no ML-KEM: nothing switches the hybrid on but the update of Windows that brings it
			if ($report -notmatch 'CNG of this Windows has no ML-KEM' -or $report -notmatch 'Windows Update') { throw 'ranz doctor does not say that CNG has no ML-KEM, and which update brings it' }
			Assert-Classical (Invoke-Probe) 'a host whose CNG has no ML-KEM'
			break
		}
		if ($report -notmatch 'This host cannot negotiate X25519MLKEM768') { throw "ranz doctor does not say that the host cannot negotiate X25519MLKEM768, with the hybrid switched off by the $case list" }
		$commands = @($report -split "`r?`n" | % { $_.Trim() } | ? { $_ -clike 'reg add *' })
		if ($commands.Count -ne 1) { throw "ranz doctor printed $($commands.Count) reg add commands, not one" }
		if (-not $commands[0].StartsWith("reg add `"$key`" /v EccCurves /t REG_MULTI_SZ /d `"x25519_mlkem768\0curve25519\0")) {
			throw "the command of ranz doctor does not put x25519_mlkem768 first, then X25519, in the list that decides: $($commands[0])"
		}
		if ($case -eq 'machine') {
			# Schannel took the machine's list without the hybrid at once
			Assert-Classical (Invoke-Probe) 'the hybrid switched off by the machine list'
		} elseif (-not $report.Contains($restart)) {
			throw "ranz doctor does not tell to restart Windows, which takes a changed ECC Curve Order policy when it starts"
		}

		# The command as ranz doctor printed it, as an administrator types it into cmd
		$file = Join-Path $work "switch-on-$case.cmd"
		Set-Content -LiteralPath $file -Value "@$($commands[0])" -Encoding ascii
		Write-Host "running what ranz doctor printed: $($commands[0])"
		& cmd.exe /c $file
		if ($LASTEXITCODE -ne 0) { throw "the command of ranz doctor exited with code $LASTEXITCODE" }

		$report = Invoke-Doctor
		if ($report -notmatch 'This host can negotiate X25519MLKEM768') { throw "ranz doctor does not say that the host can negotiate X25519MLKEM768 once its command for the $case list ran" }
		# Schannel takes the machine's list with the hybrid first at once; a policy waits for the start of Windows, which ranz
		# doctor told
		if ($case -eq 'machine') {
			Assert-Groups (Invoke-Probe) 'X25519MLKEM768' "the hybrid switched on by the command of ranz doctor for the $case list"
		}
	}
} finally {
	Set-List $policyKey $savedPolicy
	Set-List $machineKey $savedMachine
	Write-Host "the lists are back: the machine's $(Show-List (Get-List $machineKey)), the policy's $(Show-List (Get-List $policyKey))"
}
Write-Host 'ranz doctor tells whether the host can negotiate X25519MLKEM768, and the command that it prints switches the hybrid on'
