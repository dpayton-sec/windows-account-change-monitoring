# Windows Account & Security Change Monitoring

## Overview
PowerShell-based monitoring project focused on detecting Windows account changes, security group modifications, account lockouts, and event log clearing to improve security visibility and incident response.

## Features
- Monitors critical Windows Security Event IDs
- Detects user account creation, deletion, enable/disable actions
- Identifies group membership changes
- Flags account lockouts
- 🚨 Flags event log clearing (Event ID 1102) as HIGH severity
- Deduplicates events for clean reporting
- Exports structured CSV reports for analysis

## Event IDs Monitored
- 4720 – User account created  
- 4722 – User account enabled  
- 4725 – User account disabled  
- 4726 – User account deleted  
- 4728 / 4732 – Group membership changes  
- 4740 – Account lockout  
- 1102 – Event log cleared (High Risk)

## Output
The script generates a timestamped CSV report containing:
- TimeCreated
- EventId
- ChangeType
- Severity
- Computer
- Message

## Technologies Used
- PowerShell
- Windows Security Event Logs
- CSV Reporting

## Use Case
This project simulates SOC-style monitoring by identifying potentially suspicious account activity and producing analyst-ready reports for further investigation.
