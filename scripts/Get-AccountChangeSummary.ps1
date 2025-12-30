# ------------------------------------
# Windows Account & Security Change Monitoring
# ------------------------------------

$timestamp = Get-Date -Format "yyyy-MM-dd_HHmm"
$outputDir = Join-Path $PSScriptRoot "..\output"

if (!(Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

# Event IDs related to account & security changes
$eventIds = @(4720,4722,4725,4726,4728,4732,4740,1102)

Write-Host "[*] Collecting Windows Security Events..."

$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = $eventIds
} -ErrorAction SilentlyContinue

Write-Host "[+] Events collected:" $events.Count

# Remove duplicate events
$events = $events | Sort-Object TimeCreated, Id, MachineName, Message -Unique

# -------------------------------
# Detection Logic & Event Labeling
# -------------------------------

$results = foreach ($event in $events) {

    $changeType = switch ($event.Id) {
        4720 { "User Account Created" }
        4722 { "User Account Enabled" }
        4725 { "User Account Disabled" }
        4726 { "User Account Deleted" }
        4728 { "User Added to Security Group" }
        4732 { "User Added to Local Group" }
        4740 { "Account Lockout" }
        1102 { "Event Log Cleared" }
        Default { "Other" }
    }

    $severity = switch ($event.Id) {
        1102 { "HIGH" }
        4740 { "MEDIUM" }
        4728 { "MEDIUM" }
        4732 { "MEDIUM" }
        Default { "LOW" }
    }

    [pscustomobject]@{
        TimeCreated = $event.TimeCreated
        EventId     = $event.Id
        ChangeType  = $changeType
        Severity    = $severity
        Computer    = $event.MachineName
        Message     = $event.Message
    }
}

# -------------------------------
# Export Results
# -------------------------------

$outputFile = Join-Path $outputDir ("AccountChanges_{0}.csv" -f $timestamp)

$results | Export-Csv -Path $outputFile -NoTypeInformation

Write-Host "[+] Account change report exported to:" $outputFile
