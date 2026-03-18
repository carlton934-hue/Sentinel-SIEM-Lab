# Microsoft Sentinel SIEM Lab

## Project Overview
This project demonstrates a cloud-native Security Information and Event Management (SIEM) 
solution built on Microsoft Azure using Microsoft Sentinel. The lab captures and analyzes 
real-world security events from a live Windows Server VM, including actual brute force 
attacks detected from the internet.

## Technologies Used
- Microsoft Azure (Microsoft Sentinel, Log Analytics Workspace)
- Windows Server 2022 (AD-Server VM)
- KQL (Kusto Query Language)
- Azure Monitor Agent (AMA)
- Data Collection Rules (DCR)

## What Was Built
- Deployed Microsoft Sentinel and connected it to a Log Analytics Workspace
- Installed Windows Security Events data connector
- Created a Data Collection Rule (CarltonLab-DCR) to ingest logs from AD-Server VM
- Wrote KQL detection rules to identify brute force login attempts
- Detected real-world attacks from external IP addresses targeting the VM

## Real-World Attack Detection
Using KQL query for Event ID 4625 (Failed Logon), the SIEM detected active brute 
force attacks against the Administrator account from multiple external IP addresses:
- 194.165.16.167 — 37 failed login attempts
- 45.227.254.156 — 36 failed login attempts

## KQL Detection Query
```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(24h)
| summarize FailedAttempts = count() by Account, Computer, IpAddress
| where FailedAttempts > 3
| order by FailedAttempts desc
```

## Screenshots
All screenshots documenting the build and attack detection are included in this repository.

## Skills Demonstrated
- SIEM deployment and configuration
- KQL query writing for threat detection
- Real-world brute force attack identification
- Azure Monitor and Log Analytics
- Data Collection Rule configuration
- SOC analyst workflows