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
