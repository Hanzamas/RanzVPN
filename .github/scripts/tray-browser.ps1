param(
	[Parameter(Mandatory = $true)] [string] $Page
)

$ErrorActionPreference = 'Stop'

# The browser of the tray tracer (tray-tracer.ps1), which ranz tray runs through RANZ_BROWSER with the authorization page of a
# browser login as its last argument: it opens the page and signs in on it as the user of RANZ_TRACER_USER with the password
# of RANZ_TRACER_PASSWORD, as a person does, posting the form of the page with the query of its address, and follows the
# redirect to the loopback port of ranz tray, which brings the tray its code. .NET follows no redirect from https to http,
# so the browser follows that one itself. What it did goes to the file of RANZ_TRACER_BROWSER_LOG. The controller of the
# tracer has a certificate of its own, which this browser does not check: the tray pins it.

$log = $env:RANZ_TRACER_BROWSER_LOG
try {
	$uri = [Uri]$Page
	$r = Invoke-WebRequest -Uri $Page -SkipCertificateCheck
	"the authorization page: $($r.StatusCode)" | Out-File -FilePath $log -Append -Encoding utf8

	$form = @{}
	foreach ($pair in $uri.Query.TrimStart('?').Split('&', [StringSplitOptions]::RemoveEmptyEntries)) {
		$kv = $pair.Split('=', 2)
		$value = if ($kv.Count -eq 2) { $kv[1] } else { '' }
		$form[[Uri]::UnescapeDataString($kv[0].Replace('+', ' '))] = [Uri]::UnescapeDataString($value.Replace('+', ' '))
	}
	$form['user'] = $env:RANZ_TRACER_USER
	$form['password'] = $env:RANZ_TRACER_PASSWORD

	$r = Invoke-WebRequest -Uri $uri.GetLeftPart([UriPartial]::Path) -Method Post -Body $form -SkipCertificateCheck -MaximumRedirection 0 -SkipHttpErrorCheck
	$location = @($r.Headers['Location']) | Select-Object -First 1
	"the form: $($r.StatusCode), to $location" | Out-File -FilePath $log -Append -Encoding utf8
	if ($r.StatusCode -lt 300 -or $r.StatusCode -ge 400 -or -not $location) { throw "the sign-in was not redirected to the tray: $($r.StatusCode)" }

	$r = Invoke-WebRequest -Uri $location
	"the redirect to the tray: $($r.StatusCode)" | Out-File -FilePath $log -Append -Encoding utf8
} catch {
	"the sign-in failed: $_" | Out-File -FilePath $log -Append -Encoding utf8
	exit 1
}
