# Temporary (ONE-3, #312): gofmt of the files of controller/internal/payload and controller/internal/install that the lane
# changed, as the Linux job of ranz.yml runs it. Removed with its workflow.
$ErrorActionPreference = 'Continue'
$PSNativeCommandUseErrorActionPreference = $false

# The files as the index holds them (LF), not as this runner checked them out (CRLF)
$files = @()
foreach ($f in @('payload.go', 'payload_test.go', 'verify_other.go', 'verify_windows_test.go', 'verify_catalog_windows.go', 'verify_windows.go', 'xdp_amd64.go', 'xdp_none.go', 'drivers_windows_amd64_test.go')) {
	$files += "controller/internal/payload/$f"
}
foreach ($f in @('drivers.go', 'drivers_windows.go', 'install_windows.go')) {
	$files += "controller/internal/install/$f"
}
foreach ($f in $files) {
	$out = (& cmd.exe /c "git show HEAD:$f | gofmt -d" 2>&1 | Out-String)
	if ($out.Trim()) { Write-Host "needs gofmt: $f`n$out" } else { Write-Host "gofmt is content with $f" }
}
Write-Host 'gofmt done'
