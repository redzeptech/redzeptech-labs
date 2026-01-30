Write-Host "=== System Activity Timeline Builder ==="

$timeline = @()

# Boot time
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$timeline += [PSCustomObject]@{
    Time = $boot
    Event = "System Boot"
}

# Successful logons
$logons = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 20
foreach ($e in $logons) {
    $timeline += [PSCustomObject]@{
        Time = $e.TimeCreated
        Event = "User Logon"
    }
}

# Service start/stop
$services = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7036} -MaxEvents 20
foreach ($s in $services) {
    $timeline += [PSCustomObject]@{
        Time = $s.TimeCreated
        Event = "Service State Change"
    }
}

$timeline = $timeline | Sort-Object Time
$timeline | Format-Table -AutoSize
$timeline | Export-Csv timeline.csv -NoTypeInformation

Write-Host "Timeline saved to timeline.csv"
