param(
	[Parameter(Mandatory = $true)] [string] $Page
)

$ErrorActionPreference = 'Stop'

# The browser of the tray tracer (tray-tracer.ps1), which ranz tray runs through RANZ_BROWSER with the authorization page of a
# browser login as its last argument: it opens the page and signs in on it as the user of RANZ_TRACER_USER with the password
# of RANZ_TRACER_PASSWORD, as a person does, posting the form of the page with the query of its address, and follows the
# redirect to the loopback port of ranz tray, which brings the tray its code. PowerShell follows no redirect from https to
# http, so the browser posts the form with .NET, reads the redirect and follows that one itself. What it did goes to the file
# of RANZ_TRACER_BROWSER_LOG. The controller of the tracer has a certificate of its own, which this browser does not check:
# the tray pins it.

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

	# The form goes through .NET, which reads the redirect and follows none: Invoke-WebRequest refuses a Location that goes from
	# https to http, with -MaximumRedirection 0 too, and the sign-in redirects to the http port of ranz tray on loopback
	$handler = [System.Net.Http.HttpClientHandler]::new()
	$handler.AllowAutoRedirect = $false
	$handler.ServerCertificateCustomValidationCallback = [System.Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
	$client = [System.Net.Http.HttpClient]::new($handler)
	try {
		$fields = [System.Collections.Generic.Dictionary[string, string]]::new()
		foreach ($name in $form.Keys) { $fields[[string]$name] = [string]$form[$name] }
		$r = $client.PostAsync($uri.GetLeftPart([UriPartial]::Path), [System.Net.Http.FormUrlEncodedContent]::new($fields)).GetAwaiter().GetResult()
		$status = [int]$r.StatusCode
		$location = if ($r.Headers.Location) { $r.Headers.Location.OriginalString } else { '' }
	} finally {
		$client.Dispose()
	}
	"the form: $status, to $location" | Out-File -FilePath $log -Append -Encoding utf8
	if ($status -lt 300 -or $status -ge 400 -or -not $location) { throw "the sign-in was not redirected to the tray: $status" }

	$r = Invoke-WebRequest -Uri $location
	"the redirect to the tray: $($r.StatusCode)" | Out-File -FilePath $log -Append -Encoding utf8
} catch {
	"the sign-in failed: $_" | Out-File -FilePath $log -Append -Encoding utf8
	exit 1
}
