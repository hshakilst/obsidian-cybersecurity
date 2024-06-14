---
tags:
  - forensic
  - windows
  - event
  - log
  - resource
---

### Resources
+ Search Windows Events By ID [Netsurion](https://kb.eventtracker.com/)  
+ Windows Event Log Encyclopedia [Ultimate Windows Security](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx)
+ Microsoft Windows Defender Event Logs [Microsoft](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
+ Finding Microsoft Windows Group Policy Audit Configurations - [Subcategory](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d)
+ Investigating PowerShell by [Crowd Strike](https://www.crowdstrike.com/blog/investigating-powershell-command-and-script-logging/)

### PowerShell Events
**Microsoft-Windows-PowerShell Operational.evtx**
+ Event ID `400`: Engine Lifecycle State Change: Indicates a change in the PowerShell engine's lifecycle state.
+ Event ID `403`: Script Block Logging: Records the execution of PowerShell script blocks.
+ Event ID `600`: Module Logging: Captures information about the loading and unloading of PowerShell modules.
+ Event ID `4100`: Engine Error: Logs an error related to the PowerShell engine.
+ Event ID `4103`: Module Logging: Captures information about the loading and unloading of PowerShell modules.
+ Event ID `4104`: Script Block Execution: Logs the execution of PowerShell script blocks. Contains the contents of the invoked commands. Provides detailed information on script executions for analysis.
+ Event ID `40961` and `40962`: PowerShell Console is starting: Records the start time of the PowerShell console session

**Security.evtx**
+ Event ID `800`: Remote PowerShell Session Establishment: Indicates the establishment of a remote PowerShell session.

Reference: https://www.linkedin.com/pulse/windows-powershells-event-id-iz-lee-tkrmc/