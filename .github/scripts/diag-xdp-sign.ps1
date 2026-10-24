# Temporary (ONE-3, #312): reads, on a windows-latest runner, why Get-AuthenticodeSignature does not say Valid for the
# xdpapi.dll of the pinned XDP runtime while it does for xdp.sys, and what each check of Windows says for each file of
# the package, cold (as the runner is) and warm (after signtool had its say). Removed with its workflow when the check
# of fetch-xdp.ps1 is fixed.
$ErrorActionPreference = 'Continue'
$PSNativeCommandUseErrorActionPreference = $false

function Section([string] $title) {
	Write-Host ''
	Write-Host "===== $title ====="
}

function Show-Signature([string] $path) {
	$sig = Get-AuthenticodeSignature -LiteralPath $path
	Write-Host "$(Split-Path -Leaf $path): Status=$($sig.Status) SignatureType=$($sig.SignatureType) IsOSBinary=$($sig.IsOSBinary)"
	Write-Host "  StatusMessage: $($sig.StatusMessage)"
	$c = $sig.SignerCertificate
	if ($c) {
		Write-Host "  signer: $($c.Subject) | issuer: $($c.Issuer) | thumbprint $($c.Thumbprint) | $($c.NotBefore.ToString('u')) .. $($c.NotAfter.ToString('u'))"
	} else {
		Write-Host '  signer: none'
	}
	$t = $sig.TimeStamperCertificate
	if ($t) {
		Write-Host "  timestamper: $($t.Subject) | issuer: $($t.Issuer) | $($t.NotBefore.ToString('u')) .. $($t.NotAfter.ToString('u'))"
	} else {
		Write-Host '  timestamper: none'
	}
}

function Show-Chain([string] $path) {
	$c = (Get-AuthenticodeSignature -LiteralPath $path).SignerCertificate
	if (-not $c) { return }
	$chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
	$chain.ChainPolicy.RevocationMode = 'NoCheck'
	$ok = $chain.Build($c)
	Write-Host "$(Split-Path -Leaf $path): X509Chain.Build of the signer, no revocation check: $ok"
	foreach ($s in $chain.ChainStatus) { Write-Host "  chain status: $($s.Status) $($s.StatusInformation.Trim())" }
	foreach ($e in $chain.ChainElements) {
		Write-Host "  element: $($e.Certificate.Subject) | thumbprint $($e.Certificate.Thumbprint) | $($e.Certificate.NotBefore.ToString('u')) .. $($e.Certificate.NotAfter.ToString('u'))"
		foreach ($s in $e.ChainElementStatus) { Write-Host "    element status: $($s.Status) $($s.StatusInformation.Trim())" }
	}
	$cer = Join-Path $env:RUNNER_TEMP 'xdpapi-signer.cer'
	[IO.File]::WriteAllBytes($cer, $c.Export('Cert'))
	Write-Host 'certutil -verify -urlfetch of the signer:'
	& certutil.exe -verify -urlfetch $cer 2>&1 | ForEach-Object { Write-Host "  $_" }
}

function Get-SignTool {
	$roots = @("${env:ProgramFiles(x86)}\Windows Kits\10\bin", "${env:ProgramFiles}\Windows Kits\10\bin")
	$found = foreach ($r in $roots) {
		if (Test-Path -LiteralPath $r) {
			Get-ChildItem -LiteralPath $r -Recurse -Filter 'signtool.exe' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' }
		}
	}
	return ($found | Sort-Object FullName -Descending | Select-Object -First 1).FullName
}

function Invoke-GoCheck([string] $phase) {
	Section "the Go check of controller/internal/payload, $phase"
	& go test ./controller/internal/payload -run 'TestDiagVerifyEachFile' -count=1 -v 2>&1 | ForEach-Object { Write-Host $_ }
}

Section 'the machine'
Write-Host "PowerShell $($PSVersionTable.PSVersion)"
& cmd.exe /c ver
& reg.exe query 'HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot' 2>&1 | ForEach-Object { Write-Host "  $_" }
$roots = @(Get-ChildItem Cert:\LocalMachine\Root | Sort-Object Subject)
Write-Host "$($roots.Count) roots in LocalMachine\Root:"
foreach ($r in $roots) { Write-Host "  $($r.Thumbprint) $($r.Subject)" }

Section 'the package'
$version = '1.4.0'
$expected = '20f85306846e7bf18bf448cc68aee82ed0c490256d7d94d2bdbf6ac511204a361b1ae7de2642bd0e33235ad8cffa7df0de5efa2185d2c4345dadb527f7ec9172'
$id = 'microsoft.xdp-for-windows.runtime.x64'
$nupkg = Join-Path $env:RUNNER_TEMP "xdp-$version.nupkg"
Invoke-WebRequest -Uri "https://api.nuget.org/v3-flatcontainer/$id/$version/$id.$version.nupkg" -OutFile $nupkg
$hash = (Get-FileHash -Algorithm SHA512 -LiteralPath $nupkg).Hash.ToLower()
Write-Host "SHA-512 $hash, expected ${expected}: $(if ($hash -eq $expected) { 'match' } else { 'MISMATCH' })"
$extract = Join-Path $env:RUNNER_TEMP "xdp-$version-pkg"
if (Test-Path $extract) { Remove-Item -Recurse -Force $extract }
$zip = Join-Path $env:RUNNER_TEMP "xdp-$version.zip"
Copy-Item -LiteralPath $nupkg -Destination $zip -Force
Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force
$native = Join-Path $extract 'runtime\native'
foreach ($f in Get-ChildItem -LiteralPath $native -File) { Write-Host "  $($f.Name) $($f.Length) bytes, SHA-256 $((Get-FileHash -Algorithm SHA256 -LiteralPath $f.FullName).Hash)" }
$files = @('xdp.sys', 'xdpapi.dll', 'xdp.cat') | ForEach-Object { Join-Path $native $_ }
$env:DIAG_DIR = $native

Section 'Get-AuthenticodeSignature, cold'
foreach ($f in $files) { Show-Signature $f }

Invoke-GoCheck 'cold'

Section 'the chain of the signer of xdpapi.dll'
Show-Chain (Join-Path $native 'xdpapi.dll')

Section 'signtool'
$signtool = Get-SignTool
Write-Host "signtool: $signtool"
foreach ($case in @(@('/pa', 'xdpapi.dll'), @('/pa', 'xdp.cat'), @('/kp', 'xdp.sys'), @('/pa', 'xdp.sys'), @('/kp', 'xdpapi.dll'))) {
	$file = Join-Path $native $case[1]
	Write-Host "--- signtool verify $($case[0]) /v $($case[1])"
	& $signtool verify $case[0] /v $file 2>&1 | ForEach-Object { Write-Host "  $_" }
	Write-Host "  exit code $LASTEXITCODE"
}
Write-Host '--- signtool verify /pa /v /debug xdpapi.dll'
& $signtool verify /pa /v /debug (Join-Path $native 'xdpapi.dll') 2>&1 | ForEach-Object { Write-Host "  $_" }
Write-Host "  exit code $LASTEXITCODE"

Section 'Get-AuthenticodeSignature, warm (after signtool and the chain build)'
foreach ($f in $files) { Show-Signature $f }

Invoke-GoCheck 'warm'
