# Medians and per-run values from one or more spbench results.csv files.
# Rows with run=0 are the diagnostic sequence and stay out of the tables.
# Works in Windows PowerShell 5.1 and pwsh 7.
param(
    [Parameter(Mandatory)] [string[]]$Csv,
    [Parameter(Mandatory)] [string]$Out
)
$all = @()
foreach ($c in $Csv) { $all += Import-Csv $c }
$diag = @($all | Where-Object { [int]$_.run -eq 0 })
$rows = @($all | Where-Object { [int]$_.run -gt 0 })
$ok = @($rows | Where-Object status -eq 'ok')

function Num($v) { if ($v -eq $null -or $v -eq '') { return $null }; return [double]::Parse($v, [Globalization.CultureInfo]::InvariantCulture) }
function Median([double[]]$v) {
    if ($null -eq $v -or $v.Count -eq 0) { return $null }
    $s = @($v | Sort-Object)
    $n = $s.Count
    if ($n % 2 -eq 1) { return $s[[int](($n - 1) / 2)] }
    return ($s[$n / 2 - 1] + $s[$n / 2]) / 2
}
function Vals($g, $col) { return @($g | ForEach-Object { Num $_.$col } | Where-Object { $_ -ne $null }) }
function Med($g, $col) { return Median (Vals $g $col) }
function Max($g, $col) { $v = Vals $g $col; if ($v.Count -eq 0) { return $null }; return ($v | Measure-Object -Maximum).Maximum }
function K($v) { if ($v -eq $null) { return 'n/a' }; return ('{0:N0}' -f ($v / 1000)) }
function F1($v) { if ($v -eq $null) { return 'n/a' }; return ('{0:N1}' -f $v) }
function F2($v) { if ($v -eq $null) { return 'n/a' }; return ('{0:N2}' -f $v) }
function F0($v) { if ($v -eq $null) { return 'n/a' }; return ('{0:N0}' -f $v) }
function Runs($g, $col) { return (($g | Sort-Object { [int]$_.run } | ForEach-Object { K (Num $_.$col) }) -join ' / ') }

$md = New-Object System.Collections.Generic.List[string]
$fails = @($rows | Where-Object status -ne 'ok')
foreach ($os in ($all | Select-Object -ExpandProperty os -Unique)) {
    $md.Add("### $os")
    $md.Add('')
    $md.Add('TX capture: frames the OS sends out of the adapter, read in user mode. kpps; Mbit/s = captured frames x frame length (no FCS).')
    $md.Add('')
    $md.Add('| Generator | Frame B | Backend | Gen sends/s (k) | Gen dgrams/s (k) | Captured kpps median | Captured kpps per run | Mbit/s | Loss % | Sys cores | Cores per Mpps | Gen CPU | Capture CPU | Dups |')
    $md.Add('|---|---|---|---|---|---|---|---|---|---|---|---|---|---|')
    $tx = $ok | Where-Object { $_.os -eq $os -and $_.dir -eq 'tx' }
    $groups = $tx | Group-Object gen, threads, len, backend
    $groups = $groups | Sort-Object @{ e = { [int]$_.Group[0].threads } }, @{ e = { $_.Group[0].gen } }, @{ e = { [int]$_.Group[0].len } }, @{ e = { $_.Group[0].backend } }
    foreach ($g in $groups) {
        $f = $g.Group[0]
        $label = "$($f.gen) x$($f.threads)"
        if ($f.pin -eq '1') { $label += ' pinned' }
        if ($f.gen -eq 'uso') { $label += " ($(Max $g.Group 'segs') segs/send)" }
        $md.Add("| $label | $($f.len) | $($f.backend) | $(K (Med $g.Group 'gen_calls_ps')) | $(K (Med $g.Group 'gen_pps')) | **$(K (Med $g.Group 'pps'))** | $(Runs $g.Group 'pps') | $(F0 (Med $g.Group 'mbps')) | $(F1 (Med $g.Group 'loss_pct')) | $(F2 (Med $g.Group 'cpu_sys')) | $(F2 (Med $g.Group 'cores_per_mpps')) | $(F2 (Med $g.Group 'cpu_gen')) | $(F2 (Med $g.Group 'cpu_cap')) | $(F0 (Max $g.Group 'dups')) |")
    }
    $md.Add('')
    $md.Add('RX inject: frames written in user mode that TCPIP delivers to UDP sockets on 10.99.0.1. Accepted = frames the backend took (XDP: TX completions; SeLow: frames written).')
    $md.Add('')
    $md.Add('| Frame B | Backend | Accepted kpps | Delivered kpps median | Delivered kpps per run | Mbit/s | Loss % | Sys cores | Cores per Mpps | Inject CPU | Sink CPU | Dups |')
    $md.Add('|---|---|---|---|---|---|---|---|---|---|---|---|')
    $rx = $ok | Where-Object { $_.os -eq $os -and $_.dir -eq 'rx' }
    $groups = $rx | Group-Object len, backend | Sort-Object @{ e = { [int]$_.Group[0].len } }, @{ e = { $_.Group[0].backend } }
    foreach ($g in $groups) {
        $f = $g.Group[0]
        $md.Add("| $($f.len) | $($f.backend) | $(K (Med $g.Group 'gen_pps')) | **$(K (Med $g.Group 'pps'))** | $(Runs $g.Group 'pps') | $(F0 (Med $g.Group 'mbps')) | $(F1 (Med $g.Group 'loss_pct')) | $(F2 (Med $g.Group 'cpu_sys')) | $(F2 (Med $g.Group 'cores_per_mpps')) | $(F2 (Med $g.Group 'cpu_gen')) | $(F2 (Med $g.Group 'cpu_cap')) | $(F0 (Max $g.Group 'dups')) |")
    }
    $md.Add('')
    $bad = @($rows | Where-Object { $_.os -eq $os -and $_.health_after -ne 'ok' })
    $md.Add("Health probe after each measured test: $(@($rows | Where-Object os -eq $os).Count - $bad.Count) ok, $($bad.Count) not ok.")
    $md.Add('')
    $osDiag = @($diag | Where-Object os -eq $os)
    if ($osDiag.Count -gt 0) {
        $md.Add('Diagnostic sequence (not in the tables), in order:')
        $md.Add('')
        foreach ($x in $osDiag) {
            $md.Add("- $($x.backend) $($x.dir) $($x.len) B $($x.gen) x$($x.threads): status=$($x.status) gen_pps=$($x.gen_pps) pps=$($x.pps) gen_errors=$($x.gen_errors) gen_err=$($x.gen_err) segs=$($x.segs); probe after: $($x.health_after)")
        }
        $md.Add('')
    }
    $osFails = @($fails | Where-Object os -eq $os)
    if ($osFails.Count -gt 0) {
        $md.Add("Failed measurements on ${os}: $($osFails.Count)")
        foreach ($x in ($osFails | Group-Object backend, dir, status)) { $md.Add("- $($x.Name): $($x.Count)") }
        $md.Add('')
    }
}
$md | Set-Content -Path $Out -Encoding utf8
