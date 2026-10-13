# Builds bpf/ranz_xsk.c into a native eBPF driver (ranz_xsk.sys) the way
# xdp-for-windows test/bpf/bpf.vcxproj does: clang -target bpf, then the eBPF
# SDK's Convert-BpfToNative.ps1 (bpf2c + verifier + WDK NuGet kernel build).
# Runs after setup.ps1, because bpf2c reads the XDP program type from the eBPF
# store that xdpbpfexport.exe fills. Spike only.
param(
    [Parameter(Mandatory)] [string]$EbpfSdk,
    [Parameter(Mandatory)] [string]$XdpSdk,
    [Parameter(Mandatory)] [string]$OutDir,
    [Parameter(Mandatory)] [string]$LogDir
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force $LogDir, $OutDir | Out-Null
Start-Transcript -Path (Join-Path $LogDir 'build-bpf.txt') | Out-Null
function Section($t) { Write-Host "`n===== $t =====" }

$ebpfBin = Join-Path $EbpfSdk 'build\native\bin'
$ebpfInc = Join-Path $EbpfSdk 'build\native\include'
$xdpInc = Join-Path $XdpSdk 'build\native\include'

Section 'Toolchain'
$clang = (Get-Command clang.exe -ErrorAction SilentlyContinue).Source
if (-not $clang -and (Test-Path "$env:ProgramFiles\LLVM\bin\clang.exe")) { $clang = "$env:ProgramFiles\LLVM\bin\clang.exe" }
"clang: $clang"
& $clang --version
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$msbuild = & $vswhere -latest -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
"msbuild: $msbuild"
& $vswhere -latest -property catalog_productDisplayVersion
$env:PATH = "$(Split-Path $msbuild);$env:PATH"
Get-ChildItem $ebpfBin | Format-Table -AutoSize Name, Length
"ebpfhook.h present: $(Test-Path (Join-Path $xdpInc 'xdp\ebpfhook.h'))"

Section 'Export program types to the eBPF store'
# Same as test/bpf/bpf.vcxproj: eBPF's own types, then XDP's (xdpbpfexport needs ebpfapi.dll beside it).
& (Join-Path $ebpfBin 'export_program_info.exe')
"export_program_info exit=$LASTEXITCODE"
$xbe = Get-ChildItem $XdpSdk -Recurse -Filter xdpbpfexport.exe | Where-Object FullName -match 'x64' | Select-Object -First 1
if ($xbe) {
    Copy-Item (Join-Path $ebpfBin 'ebpfapi.dll') $xbe.DirectoryName -Force
    & $xbe.FullName
    "xdpbpfexport ($($xbe.FullName)) exit=$LASTEXITCODE"
}

Section 'clang -target bpf'
$src = Join-Path $PSScriptRoot 'bpf\ranz_xsk.c'
Copy-Item $src $OutDir -Force
Push-Location $OutDir
& $clang -g -target bpf -O2 -Werror -I $ebpfInc -I (Join-Path $ebpfInc 'uapi') -I $xdpInc -c ranz_xsk.c -o ranz_xsk.o
"clang exit=$LASTEXITCODE"

Section 'Convert-BpfToNative (bpf2c + WDK NuGet kernel build)'
$t0 = Get-Date
$full = Join-Path $LogDir 'convert-full.txt'
pwsh -NoProfile -File (Join-Path $ebpfBin 'Convert-BpfToNative.ps1') -FileName ranz_xsk -IncludeDir $ebpfInc -Platform x64 -Configuration Release *> $full
"Convert-BpfToNative exit=$LASTEXITCODE"
Get-Content $full | Select-String -Pattern 'error|warning MSB|Build succeeded|Build FAILED|verif|bpf2c|sign|\.sys|Restored|WDK' |
    ForEach-Object { $_.Line } | Select-Object -First 80
"Convert-BpfToNative took=$([int]((Get-Date) - $t0).TotalSeconds)s"
Pop-Location

$sys = Join-Path $OutDir 'ranz_xsk.sys'
if (Test-Path $sys) {
    $s = Get-AuthenticodeSignature $sys
    "ranz_xsk.sys built: $((Get-Item $sys).Length) bytes, signature=$($s.Status) signer=$($s.SignerCertificate.Subject)"
    if ($s.Status -eq 'NotSigned') {
        # Hosted runners boot with testsigning on; any certificate is accepted there.
        $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
            Where-Object FullName -match '\\x64\\' | Sort-Object FullName | Select-Object -Last 1
        $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=Ranz eBPF spike test' -CertStoreLocation Cert:\CurrentUser\My
        & $signtool.FullName sign /fd sha256 /sha1 $cert.Thumbprint $sys
        "test-sign exit=$LASTEXITCODE signature=$((Get-AuthenticodeSignature $sys).Status)"
    }
    'RESULT EBPF_BUILD PASS'
} else {
    Get-ChildItem $OutDir -Recurse | Format-Table -AutoSize FullName, Length
    'RESULT EBPF_BUILD FAIL reason=no-sys'
}
Stop-Transcript | Out-Null
exit 0
