param([string] $Ranz = 'build\ranz\ranz.exe')

$ErrorActionPreference = 'Stop'

# The three tools of SDN-53 (#246), run as processes and read from outside, natively on this
# architecture:
# - ranz doctor runs the six checks of the vpncmd Check command, names each of them and must pass
#   them all;
# - ranz test throughput runs the test server and the test client as two processes of the runner,
#   which stand in for two nodes, and the client must report a rate in both directions and, for a
#   test of one direction, in that one;
# - ranz cert makes a CA and a certificate that it signs with their keys in the Microsoft Software
#   Key Storage Provider, the certificates in the My store of the user, linked to their keys. The
#   native side then judges them: certutil finds the key of each certificate in the provider and
#   makes its own test of it, a TLS handshake over Schannel serves with the certificate of the store,
#   and the client trusts nothing but the CA, whose certificate is the only root of its chain policy
#   in the chain engine of Windows (CryptoAPI). A client that trusts another CA must refuse it.

$Ranz = (Resolve-Path -LiteralPath $Ranz).Path
$work = Join-Path $env:RUNNER_TEMP 'ranz-tools'
New-Item -ItemType Directory -Force -Path $work | Out-Null

# Test ports, never one that a service holds: the traffic test server
$throughputPort = 19821

Write-Host '--- ranz doctor'
$doctor = (& $Ranz doctor | Out-String)
if ($LASTEXITCODE -ne 0) {
	Write-Host $doctor
	throw "ranz doctor exited with code $LASTEXITCODE"
}
Write-Host $doctor
foreach ($title in 'Kernel System', 'Memory Operation System', 'ANSI / Unicode string processing system', 'File system', 'Thread processing system', 'Network system') {
	if ($doctor -notmatch [regex]::Escape("Checking '$title'... Pass")) { throw "ranz doctor does not report the check '$title' as passed" }
}
if ($doctor -notmatch 'All checks passed') { throw 'ranz doctor does not report that all checks passed' }

Write-Host '--- ranz test throughput'
$serverOut = Join-Path $work 'throughput-server.out'
$serverErr = Join-Path $work 'throughput-server.err'
$server = Start-Process -FilePath $Ranz -PassThru -NoNewWindow -RedirectStandardOutput $serverOut -RedirectStandardError $serverErr -ArgumentList @(
	'test', 'throughput', '-listen', "127.0.0.1:$throughputPort")
# The handle keeps the exit code of the process
$null = $server.Handle
try {
	# The server serves once it takes a connection
	$end = (Get-Date).AddSeconds(30)
	while ($true) {
		if ($server.HasExited) { throw "the test server exited with code $($server.ExitCode)" }
		try {
			$probe = New-Object System.Net.Sockets.TcpClient
			$probe.Connect('127.0.0.1', $throughputPort)
			$probe.Close()
			break
		} catch {
			if ((Get-Date) -ge $end) { throw "the test server did not serve on port $throughputPort within 30 s" }
			Start-Sleep -Milliseconds 200
		}
	}
	$address = "127.0.0.1:$throughputPort"
	$text = (& $Ranz test throughput -connections 8 -span 3s $address | Out-String)
	if ($LASTEXITCODE -ne 0) { throw "ranz test throughput exited with code $LASTEXITCODE" }
	Write-Host $text
	if ($text -notmatch "Throughput test to $([regex]::Escape($address))") { throw 'the report does not name the server' }
	foreach ($row in 'Download', 'Upload', 'Total') {
		if ($text -notmatch "(?m)^\s+$row\s+\d+\s+[\d,]+ bytes\s+[\d.]+ [KMGT]?bps") { throw "the report has no rate for $row" }
	}
	$result = (& $Ranz test throughput -json -type upload -connections 2 -span 1s $address | Out-String | ConvertFrom-Json)
	if ($LASTEXITCODE -ne 0) { throw "ranz test throughput -json exited with code $LASTEXITCODE" }
	Write-Host "upload only: $($result | ConvertTo-Json -Compress -Depth 4)"
	if ($result.upload.connections -ne 2 -or $result.upload.bytes -le 0 -or $result.upload.bps -le 0 -or $result.download.connections -ne 0 -or $result.download.bytes -ne 0) {
		throw 'a test of one direction did not move data in that direction only'
	}
} finally {
	if (-not $server.HasExited) { Stop-Process -Id $server.Id -Force }
}

# The DER bytes of a certificate in a PEM file
function Read-Pem([string] $path) {
	$text = Get-Content -LiteralPath $path -Raw
	return [System.Convert]::FromBase64String(($text -replace '-----[^-]+-----', '' -replace '\s', ''))
}

# One call of ranz cert: it must succeed; its output is returned as text
function Invoke-Cert([string[]] $argv) {
	$out = & $Ranz cert @argv | Out-String
	if ($LASTEXITCODE -ne 0) { throw "ranz cert $($argv -join ' ') exited with code $LASTEXITCODE" }
	Write-Host $out
	return $out
}

# The thumbprint that ranz cert printed
function Get-Thumbprint([string] $out) {
	if ($out -notmatch '(?m)^Thumbprint   ([0-9A-F]{40})\s*$') { throw "ranz cert printed no thumbprint:`n$out" }
	return $Matches[1]
}

# Runs a TLS handshake over Schannel on the loopback interface: a server with $ServerCert, which has
# its key in a key storage provider, and a client that accepts the certificate only when its chain
# ends in $Trusted, the one root of the chain policy of the client. It returns $null when the
# handshake went through, and why it did not otherwise.
function Test-TlsHandshake($ServerCert, $Trusted, [string] $TargetHost) {
	$listener = New-Object System.Net.Sockets.TcpListener -ArgumentList ([System.Net.IPAddress]::Loopback), 0
	$listener.Start()
	$client = $null
	$serverSsl = $null
	$clientSsl = $null
	try {
		$acceptTask = $listener.AcceptTcpClientAsync()
		$client = New-Object System.Net.Sockets.TcpClient
		$client.Connect('127.0.0.1', $listener.LocalEndpoint.Port)
		if (-not $acceptTask.Wait(10000)) { return 'the server did not take the connection' }
		$serverStream = $acceptTask.Result.GetStream()
		$serverSsl = New-Object System.Net.Security.SslStream -ArgumentList $serverStream, $false
		$serverTask = $serverSsl.AuthenticateAsServerAsync($ServerCert)

		$policy = New-Object System.Security.Cryptography.X509Certificates.X509ChainPolicy
		$policy.TrustMode = [System.Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
		[void] $policy.CustomTrustStore.Add($Trusted)
		$policy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
		$options = New-Object System.Net.Security.SslClientAuthenticationOptions
		$options.TargetHost = $TargetHost
		$options.CertificateChainPolicy = $policy
		$clientStream = $client.GetStream()
		$clientSsl = New-Object System.Net.Security.SslStream -ArgumentList $clientStream, $false
		try {
			$clientSsl.AuthenticateAsClient($options)
		} catch {
			return "the client refused the certificate: $($_.Exception.Message) $($_.Exception.InnerException.Message)"
		}
		if (-not $serverTask.Wait(10000)) { return 'the server did not finish the handshake' }
		if ($clientSsl.RemoteCertificate.GetCertHashString() -ne $ServerCert.GetCertHashString()) { return 'the client saw another certificate than the one of the server' }

		# The keys of the session carry data both ways
		$bytes = [byte[]] (1..16)
		$clientSsl.Write($bytes, 0, $bytes.Length)
		$clientSsl.Flush()
		$got = New-Object byte[] $bytes.Length
		$n = 0
		while ($n -lt $got.Length) {
			$read = $serverSsl.Read($got, $n, $got.Length - $n)
			if ($read -le 0) { return 'the stream of the server ended' }
			$n += $read
		}
		if ((Compare-Object $bytes $got).Count -ne 0) { return 'the server read other bytes than the client wrote' }
		return $null
	} finally {
		foreach ($d in $clientSsl, $serverSsl, $client) {
			if ($d) { try { $d.Dispose() } catch { } }
		}
		$listener.Stop()
	}
}

Write-Host '--- ranz cert'
$suffix = [guid]::NewGuid().ToString('N').Substring(0, 12)
$caKey = "Ranz CI CA $suffix"
$nodeKey = "Ranz CI node $suffix"
$otherKey = "Ranz CI other $suffix"
$thumbprints = @()
try {
	# A CA, and a certificate that it signs, each with its key in the provider and its certificate in
	# the My store of the user, linked to the key
	$ca = Invoke-Cert @('-ca', '-cn', "Ranz CI CA $suffix", '-ksp', $caKey, '-savecert', (Join-Path $work 'ca.pem'))
	$caThumbprint = Get-Thumbprint $ca
	$thumbprints += $caThumbprint
	$node = Invoke-Cert @('-cn', 'localhost', '-signcert', (Join-Path $work 'ca.pem'), '-signksp', $caKey, '-ksp', $nodeKey, '-savecert', (Join-Path $work 'node.pem'))
	$nodeThumbprint = Get-Thumbprint $node
	$thumbprints += $nodeThumbprint
	# Another CA, with its own key in a file, and a certificate that it signs
	Invoke-Cert @('-ca', '-cn', "Ranz CI other CA $suffix", '-savecert', (Join-Path $work 'other-ca.pem'), '-savekey', (Join-Path $work 'other-ca.key')) | Out-Null
	$other = Invoke-Cert @('-cn', 'localhost', '-signcert', (Join-Path $work 'other-ca.pem'), '-signkey', (Join-Path $work 'other-ca.key'), '-ksp', $otherKey, '-savecert', (Join-Path $work 'other.pem'))
	$thumbprints += (Get-Thumbprint $other)

	# The store holds the certificates with their keys, and the provider is the one the node names
	foreach ($t in $caThumbprint, $nodeThumbprint) {
		$cert = Get-Item -LiteralPath "Cert:\CurrentUser\My\$t"
		if (-not $cert.HasPrivateKey) { throw "the certificate $t in the My store has no private key" }
		$store = (& certutil -user -store My $t | Out-String)
		if ($LASTEXITCODE -ne 0) { throw "certutil -store exited with code $LASTEXITCODE for $t`n$store" }
		if ($store -notmatch 'Provider = Microsoft Software Key Storage Provider') { throw "certutil does not find the key of $t in the Microsoft Software Key Storage Provider:`n$store" }
		if ($store -notmatch 'test passed') { throw "certutil's own test of the key of $t did not pass:`n$store" }
		Write-Host "certificate ${t}: its key is in the Microsoft Software Key Storage Provider, and certutil's test of it passed"
	}

	# The CA certificate that ranz cert wrote is the trust store of the client; the certificate that
	# it signed is the one that the Schannel server serves with
	$caCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]] (Read-Pem (Join-Path $work 'ca.pem')))
	$otherCa = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]] (Read-Pem (Join-Path $work 'other-ca.pem')))
	$nodeCert = Get-Item -LiteralPath "Cert:\CurrentUser\My\$nodeThumbprint"
	$why = Test-TlsHandshake $nodeCert $caCert 'localhost'
	if ($why) { throw "a TLS handshake with the certificate of ranz cert, a client that trusts its CA: $why" }
	Write-Host 'Schannel served with the certificate of the store, and a client whose only root is its CA accepted it'
	$why = Test-TlsHandshake $nodeCert $otherCa 'localhost'
	if (-not $why) { throw 'a client that trusts another CA accepted the certificate' }
	Write-Host "a client that trusts another CA refused it: $why"
	$why = Test-TlsHandshake $nodeCert $caCert 'other.example'
	if (-not $why) { throw 'a client accepted the certificate for another host name' }
	Write-Host "a client that asked for another host name refused it: $why"
	Write-Host 'ok'
} finally {
	foreach ($t in $thumbprints) {
		Remove-Item -LiteralPath "Cert:\CurrentUser\My\$t" -ErrorAction SilentlyContinue
	}
	foreach ($k in $caKey, $nodeKey, $otherKey) {
		& certutil -user -delkey -csp 'Microsoft Software Key Storage Provider' $k 2>&1 | Out-Null
	}
}
