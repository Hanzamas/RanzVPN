param(
	[Parameter(Mandatory = $true)] [string] $Sbom,
	[string] $InstallRoot = 'build\vcpkg_installed\x64-windows-static'
)

$ErrorActionPreference = 'Stop'

# The SBOM of the supply-chain workflow (ADR-0039 decision 4; SEC-1, #279) must name every port of
# vcpkg.json, which vcpkg installed at the builtin-baseline with an SPDX document of its own, and
# every module that the go.mod of the repository requires (the one Go module, which holds the
# controller and the BGP sidecar: ONE-1, #310), at the version go.mod pins. Prints what it found
# either way; fails when one is missing.

$doc = Get-Content -Raw -LiteralPath $Sbom | ConvertFrom-Json
$packages = @($doc.packages)
Write-Host "${Sbom}: $($doc.spdxVersion), $($packages.Count) packages, $(@($doc.files).Count) files"

# The versions of each package name
$have = @{}
foreach ($p in $packages) { $have["$($p.name)"] += @("$($p.versionInfo)") }

$missing = @()

# The ports of vcpkg.json, a string or an object with a name each, and the version vcpkg installed
$ports = @((Get-Content -Raw -LiteralPath vcpkg.json | ConvertFrom-Json).dependencies | ForEach-Object { if ($_ -is [string]) { $_ } else { $_.name } })
foreach ($port in $ports) {
	$spdx = Join-Path $InstallRoot "share\$port\vcpkg.spdx.json"
	$installed = if (Test-Path -LiteralPath $spdx) { (Get-Content -Raw -LiteralPath $spdx | ConvertFrom-Json).packages[0].versionInfo } else { '?' }
	if ($have.ContainsKey($port)) {
		Write-Host "vcpkg ${port} ${installed}: in the SBOM as $($have[$port] -join ', ')"
	} else {
		$missing += "vcpkg port $port $installed"
	}
}

# The modules that go.mod requires, direct and indirect, at its version
$mod = (go mod edit -json | Out-String) | ConvertFrom-Json
foreach ($r in @($mod.Require)) {
	if ($have.ContainsKey($r.Path) -and $have[$r.Path] -contains $r.Version) {
		Write-Host "go.mod: $($r.Path) $($r.Version)"
	} else {
		$found = if ($have.ContainsKey($r.Path)) { " (the SBOM has $($have[$r.Path] -join ', '))" } else { '' }
		$missing += "go.mod: Go module $($r.Path) $($r.Version)$found"
	}
}

if ($missing.Count -gt 0) {
	Write-Host 'The packages of the SBOM:'
	$packages | Sort-Object name | ForEach-Object { Write-Host "  $($_.name) $($_.versionInfo)" }
	$missing | ForEach-Object { Write-Host "::error::not in the SBOM: $_" }
	throw "$($missing.Count) dependencies are not in the SBOM"
}
Write-Host "The SBOM names every vcpkg port of vcpkg.json and every module that go.mod requires"
