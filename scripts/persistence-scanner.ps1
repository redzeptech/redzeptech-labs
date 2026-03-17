Write-Host "=== Persistence Scanner ==="

$report = @()

# Startup registry entries
$startup = Get-CimInstance Win32_StartupCommand
foreach ($s in $startup) {
    $report += [PSCustomObject]@{
        Type = "Startup Entry"
        Name = $s.Name
        Command = $s.Command
        Location = $s.Location
    }
}

# Scheduled tasks outside Microsoft path
$tasks = Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft*"}
foreach ($t in $tasks) {
    $report += [PSCustomObject]@{
        Type = "Scheduled Task"
        Name = $t.TaskName
        State = $t.State
        Path = $t.TaskPath
    }
}

# Services running automatically outside system32
$services = Get-CimInstance Win32_Service |
Where-Object {$_.StartMode -eq "Auto" -and $_.PathName -notmatch "Windows\\System32"}

foreach ($svc in $services) {
    $report += [PSCustomObject]@{
        Type = "Service Persistence"
        Name = $svc.Name
        Path = $svc.PathName
        User = $svc.StartName
    }
}

$report | Format-Table -AutoSize
$report | Export-Csv persistence_findings.csv -NoTypeInformation

Write-Host "Report saved to persistence_findings.csv"
