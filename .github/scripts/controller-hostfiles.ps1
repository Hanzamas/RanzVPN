# The files that the controller leaves on its host, checked on the Windows service that controller-service.ps1
# runs (AUD1-DT-10, #458; ST-3 and ST-4 of docs/threat-model.md). That script dot-sources this one, so the
# functions below read its variables: $data (the data directory), $ranz, $account and $serviceSid (the service
# account), $service, $work, $tokenFile and $api. What they show:
# - the data directory that install made is owned by the Administrators, and its access list is protected and has
#   no rule for any account but SYSTEM, the Administrators, the owner and the service account;
# - a backup that goes to a folder that the Users group may read is written for SYSTEM and the Administrators only,
#   holds the secret of a target sealed and not in clear, and the text that `ranz controller backup` prints names
#   what it holds; a restore of it on the same host, under the running service, brings the target back with its
#   secret;
# - the service does not start in a data directory that a standard user owns, says why in the Application log,
#   and starts again once the Administrators own the directory;
# - the install over the data directory that the service filled takes it over, and refuses it with a file of the Users
#   group in it, naming the file and its owner and changing nothing (AUD1-DT-18, #503);
# - the TLS fingerprint file that the service writes is owned by SYSTEM, the Administrators or the account of the
#   service, and no other account has a rule that writes it, so ranz takes it (AUD1-DT-14, #496; AP-2); the same file in
#   a folder that the Users group may write is refused by ranz, which sends no token and names the folder.

# The accounts that a protected access list of the data directory may name, as Get-Acl writes them
$dataDirAccounts = @('BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM', 'OWNER RIGHTS', 'S-1-3-4')

# The names that the rules of an access list are for
function Get-AclAccounts([string] $path) {
	return @((Get-Acl -LiteralPath $path).Access | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
}

# The data directory as install made it
function Test-DataDirOwner {
	$acl = Get-Acl -LiteralPath $data
	if ($acl.Owner -ne 'BUILTIN\Administrators') { throw "the data directory $data is owned by $($acl.Owner), not by BUILTIN\Administrators" }
	if (-not $acl.AreAccessRulesProtected) { throw "the access list of the data directory $data is not protected: it takes rules from its folder" }
	$who = Get-AclAccounts $data
	$others = @($who | Where-Object { ($dataDirAccounts + @($account, $serviceSid)) -notcontains $_ })
	if ($others.Count -gt 0) { throw "the access list of the data directory $data has rules for $($others -join ', ')" }
	Write-Host "the data directory $data is owned by $($acl.Owner), and its access list is protected, with rules for $($who -join ', ') only"
}

# The TLS fingerprint file that the service wrote (AUD1-DT-14, #496). The service writes it as its own account, which then
# owns it, in the data directory that install made, so it has the rules of that directory and no others. ranz takes the
# file only then: where another account may have written the file or its folder, a local user could have put its own key
# there, and listened on 127.0.0.1:443 for the token of whoever runs ranz. The same file in a folder that the Users group
# may write is not taken: ranz exits with an error that names the folder, and sends no token
function Test-FingerprintFile {
	$file = Join-Path $data 'tls.fingerprint'
	$acl = Get-Acl -LiteralPath $file
	if (@('BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM', $account, $serviceSid) -notcontains $acl.Owner) { throw "tls.fingerprint is owned by $($acl.Owner), not by SYSTEM, the Administrators or $account" }
	$who = Get-AclAccounts $file
	$others = @($who | Where-Object { ($dataDirAccounts + @($account, $serviceSid)) -notcontains $_ })
	if ($others.Count -gt 0) { throw "the access list of tls.fingerprint has rules for $($others -join ', ')" }
	Write-Host "tls.fingerprint is owned by $($acl.Owner), with rules for $($who -join ', ') only"

	$untrusted = Join-Path $work 'untrusted-controller'
	New-Item -ItemType Directory -Force -Path $untrusted | Out-Null
	Copy-Item -LiteralPath $file -Destination (Join-Path $untrusted 'tls.fingerprint') -Force
	& icacls $untrusted /grant 'BUILTIN\Users:(OI)(CI)W' | Out-Null
	if ($LASTEXITCODE -ne 0) { throw "icacls $untrusted exited with code $LASTEXITCODE" }
	$errFile = Join-Path $work 'ranz-untrusted.err'
	& $ranz -server $api -token-file $tokenFile -controller-dir $untrusted whoami 2> $errFile | Out-Null
	$exit = $LASTEXITCODE
	$said = Get-Content -LiteralPath $errFile -Raw
	if ($exit -eq 0 -or $said -notmatch 'sends no token' -or $said -notmatch 'does not trust that file' -or $said -notmatch [regex]::Escape($untrusted) -or $said -notmatch '-tls-fingerprint') {
		throw "ranz did not refuse the fingerprint file of a folder that the Users group may write (exit code $exit): $said"
	}
	Write-Host "ranz refused the fingerprint file of $untrusted, which the Users group may write: $($said.Trim())"
}

# The text of a file as a string of one character for each byte, which holds what a SQLite file holds in clear
function Get-FileBytesAsText([string] $path) {
	return [System.Text.Encoding]::GetEncoding('iso-8859-1').GetString([System.IO.File]::ReadAllBytes($path))
}

# A call of the API with the admin token, and a body of JSON when $json is not empty; the HTTP status it answers with
function Invoke-ApiWithBody([string] $method, [string] $path, [string] $json) {
	$token = (Get-Content -LiteralPath $tokenFile -Raw).Trim()
	$argv = @('-k', '-s', '-o', 'NUL', '-w', '%{http_code}', '-X', $method, '-H', "Authorization: Bearer $token")
	if ($json) {
		$body = Join-Path $work 'api-body.json'
		Set-Content -LiteralPath $body -Value $json -Encoding ascii
		$argv += @('-H', 'Content-Type: application/json', '--data-binary', "@$body")
	}
	return ((& curl.exe @argv "$api$path") -join '').Trim()
}

# The target $name as GET /api/v1/targets lists it, once the API lists it: after a restore the service takes the lease
# again and loads the restored store
function Wait-ApiTarget([string] $name) {
	$end = (Get-Date).AddSeconds($waitSeconds)
	while ($true) {
		$token = (Get-Content -LiteralPath $tokenFile -Raw).Trim()
		$body = ((& curl.exe -k -s -f -H "Authorization: Bearer $token" "$api/api/v1/targets") -join '').Trim()
		if ($LASTEXITCODE -eq 0 -and $body) {
			$target = @(($body | ConvertFrom-Json).targets | Where-Object { $_.name -eq $name })
			if ($target.Count -eq 1) { return $target[0] }
		}
		if ((Get-Date) -ge $end) { throw "the API did not list the target $name within $waitSeconds s: $body" }
		Start-Sleep -Milliseconds 500
	}
}

# A backup of the store of the running service
function Test-Backup {
	# A target with a secret, put through the API as an operator puts it: the service seals the secret with the key of
	# its own account
	$secret = 'ci-secret-of-a-target-6f1d9c04'
	$code = Invoke-ApiWithBody 'PUT' '/api/v1/targets/ci-target' (@{ kind = 'webhook'; url = 'https://192.0.2.10/ci'; secret = $secret } | ConvertTo-Json -Compress)
	if ($code -ne '200') { throw "the API did not take a webhook target with a secret: HTTP status $code" }

	# A folder that the Users group may read, and a file made in it, which takes that right
	$folder = Join-Path $work 'backups'
	New-Item -ItemType Directory -Force -Path $folder | Out-Null
	& icacls $folder /grant 'BUILTIN\Users:(OI)(CI)R' | Out-Null
	if ($LASTEXITCODE -ne 0) { throw "icacls $folder exited with code $LASTEXITCODE" }
	$plain = Join-Path $folder 'plain.txt'
	Set-Content -LiteralPath $plain -Value 'anyone' -Encoding ascii
	if ((Get-AclAccounts $plain) -notcontains 'BUILTIN\Users') { throw "a file made in $folder does not take the Users group from the folder, so this check shows nothing" }

	$file = Join-Path $folder 'store.backup'
	$errFile = Join-Path $work 'backup.err'
	& $ranz controller backup -o $file -data $data 2> $errFile
	$exit = $LASTEXITCODE
	$said = Get-Content -LiteralPath $errFile -Raw
	Write-Host $said
	if ($exit -ne 0) { throw "ranz controller backup exited with code $exit" }

	# The file is for SYSTEM and the Administrators, and not for the Users group of its folder
	$acl = Get-Acl -LiteralPath $file
	if (-not $acl.AreAccessRulesProtected) { throw "the access list of the backup is not protected: it takes the rules of its folder" }
	$who = Get-AclAccounts $file
	if (($who -join ',') -ne 'BUILTIN\Administrators,NT AUTHORITY\SYSTEM') { throw "the access list of the backup has rules for $($who -join ', '), not for SYSTEM and the Administrators only" }
	Write-Host "the backup $file, in a folder that the Users group may read, has rules for $($who -join ', ') only"

	# The secret is sealed in it, and the text names what a backup holds
	$text = Get-FileBytesAsText $file
	if ($text.Contains($secret)) { throw 'the backup holds the secret of the target in clear' }
	if (-not $text.Contains('ranz-sealed:1:')) { throw 'the backup holds no sealed secret of a target' }
	foreach ($want in 'for SYSTEM and the Administrators only', 'the Intent', 'the hashes', 'the licence key', 'the secrets of the targets') {
		if ($said -notmatch [regex]::Escape($want)) { throw "ranz controller backup does not say '$want':`n$said" }
	}
	Write-Host 'the backup holds the secret of the target sealed, and ranz controller backup names the Intent, the hashes, the licence key and the secrets of the targets'

	# The target is deleted, and a restore of the backup on the same host, under the running service, brings it back
	# with its secret: the service opens the sealed secret with the sealing key of its own account
	$code = Invoke-ApiWithBody 'DELETE' '/api/v1/targets/ci-target' ''
	if ($code -ne '200') { throw "the API did not delete the target: HTTP status $code" }
	$errFile = Join-Path $work 'restore.err'
	& $ranz controller restore -f $file -data $data 2> $errFile
	$exit = $LASTEXITCODE
	Get-Content -LiteralPath $errFile | ForEach-Object { Write-Host "  restore: $_" }
	if ($exit -ne 0) { throw "ranz controller restore exited with code $exit" }
	$target = Wait-ApiTarget 'ci-target'
	if (-not $target.hasSecret) { throw "after a restore on the same host the target has no secret: $($target | ConvertTo-Json -Compress)" }
	Write-Host "after a restore of the backup on the same host the target has its secret: $($target | ConvertTo-Json -Compress)"

	$code = Invoke-ApiWithBody 'DELETE' '/api/v1/targets/ci-target' ''
	if ($code -ne '200') { throw "the API did not delete the target: HTTP status $code" }
}

# The service stopped, and the data directory given to the Users group: it does not start, says why in the
# Application log, and starts once the Administrators own the directory again
function Test-ServiceRefusesDataDir {
	& icacls $data /setowner 'BUILTIN\Users' | Out-Null
	if ($LASTEXITCODE -ne 0) { throw "icacls $data /setowner exited with code $LASTEXITCODE" }
	$started = $true
	try {
		Start-Service -Name $service -ErrorAction Stop
	} catch {
		$started = $false
		Write-Host "Start-Service: $($_.Exception.Message)"
	}
	if ($started) { throw "$service started in a data directory that the Users group owns" }
	$failed = @(Get-ServiceEvents | Where-Object { $_.Id -eq 3 })
	if ($failed.Count -ne 1 -or $failed[0].Message -notmatch 'is owned by') { throw "expected one failure entry (event ID 3) that says who owns the data directory, found $($failed.Count): $($failed.Message -join ' | ')" }
	Write-Host "Application log: $($failed[0].Message)"

	& icacls $data /setowner 'BUILTIN\Administrators' | Out-Null
	if ($LASTEXITCODE -ne 0) { throw "icacls $data /setowner exited with code $LASTEXITCODE" }
	Start-Service -Name $service
	Wait-Api
	Stop-Service -Name $service
	Write-Host 'the service did not start in a data directory that the Users group owns, and starts again with the Administrators as its owner'
}

# The install over the data directory that the service filled (AUD1-DT-18, #503; ST-3), with the service stopped. The install
# takes the folder over as it takes any folder that the Administrators own, and looks at what it holds first: the service, its
# rqlited and the commands of an administrator made it, so SYSTEM, the Administrators, the service or this account own all of
# it, and the install goes on to the service, which exists already, and says so. With a file in it that the Users group owns,
# which a user would have made while the folder had the list of its parent, the install refuses the folder, names the file and
# its owner, and changes nothing: the owner and the access list of the folder, and the owner of the file, are what they were.
function Test-DataDirChildren {
	$errFile = Join-Path $work 'install-again.err'
	& $ranz controller install -data $data 2> $errFile | Out-Null
	$exit = $LASTEXITCODE
	$said = Get-Content -LiteralPath $errFile -Raw
	if ($exit -eq 0 -or $said -notmatch 'already exists') { throw "the install over the data directory that the service filled did not get as far as the service that exists (exit code $exit): $said" }
	Write-Host "the install over the data directory that the service filled took it over and went on to the service: $($said.Trim())"

	$planted = Join-Path $data 'planted'
	New-Item -ItemType Directory -Force -Path $planted | Out-Null
	$file = Join-Path $planted 'rqlited.exe'
	Set-Content -LiteralPath $file -Value 'a file that a user made' -Encoding ascii
	& icacls $file /setowner 'BUILTIN\Users' | Out-Null
	if ($LASTEXITCODE -ne 0) { throw "icacls $file /setowner exited with code $LASTEXITCODE" }
	$before = (Get-Acl -LiteralPath $data).Sddl
	& $ranz controller install -data $data 2> $errFile | Out-Null
	$exit = $LASTEXITCODE
	$said = Get-Content -LiteralPath $errFile -Raw
	if ($exit -eq 0 -or $said -notmatch [regex]::Escape($file) -or $said -notmatch 'BUILTIN\\Users' -or $said -notmatch 'did not take it over') {
		throw "the install over a data directory that holds a file of the Users group was not refused with the file and its owner named (exit code $exit): $said"
	}
	if ((Get-Acl -LiteralPath $data).Sddl -ne $before) { throw 'the refused install changed the owner or the access list of the data directory' }
	if ((Get-Acl -LiteralPath $file).Owner -ne 'BUILTIN\Users') { throw "the refused install changed the owner of $file" }
	Write-Host "the install refused the data directory with $file of the Users group in it, and changed nothing: $($said.Trim())"
	Remove-Item -LiteralPath $planted -Recurse -Force
}
