Write-Host "=== Suspicious Network Connection Analyzer ==="

$connections = netstat -ano | Select-String "ESTABLISHED"
$report = @()

foreach ($c in $connections) {
    $parts = ($c -replace '\s+', ' ').Trim().Split(' ')
    if ($parts.Count -lt 5) { continue }

    $local = $parts[1]
    $remote = $parts[2]
    $pid = $parts[-1]

    # Skip localhost connections
    if ($remote -like "127.*" -or $remote -like "[::1]*") { continue }

    try {
        $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
        $pname = $proc.Name
    } catch {
        $pname = "Unknown"
    }

    $report += [PSCustomObject]@{
        Process = $pname
        PID = $pid
        LocalAddress = $local
        RemoteAddress = $remote
    }
}

$report | Format-Table -AutoSize
$report | Export-Csv suspicious_connections.csv -NoTypeInformation

Write-Host "Report saved to suspicious_connections.csv"
