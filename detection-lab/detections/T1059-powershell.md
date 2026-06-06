# T1059.001 - Command and Scripting Interpreter: PowerShell

## Overview
Adversaries abuse PowerShell to execute commands, download payloads, and run
scripts in memory. PowerShell is a default, signed, and trusted binary on
Windows, making it a common living-off-the-land tool.

- **Tactic:** Execution
- **Technique:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- **Platforms:** Windows

## Data Sources
- Windows PowerShell logs (Event ID 4103 - Module Logging)
- PowerShell Script Block Logging (Event ID 4104)
- Process creation (Sysmon Event ID 1 / Security Event ID 4688)
- Command-line auditing

## Detection Logic

### Suspicious encoded / obfuscated commands
Look for process creation where the command line contains:
- `-enc` / `-EncodedCommand`
- `-nop` / `-NoProfile`
- `-w hidden` / `-WindowStyle Hidden`
- `IEX` / `Invoke-Expression`
- `DownloadString`, `DownloadFile`, `Net.WebClient`
- `FromBase64String`

### Example (Splunk SPL)
```spl
index=windows (EventCode=4688 OR EventCode=1)
  (New_Process_Name="*\\powershell.exe" OR New_Process_Name="*\\pwsh.exe")
  (Process_Command_Line="*-enc*" OR Process_Command_Line="*-nop*"
   OR Process_Command_Line="*hidden*" OR Process_Command_Line="*IEX*"
   OR Process_Command_Line="*DownloadString*")
| stats count by host, user, Process_Command_Line, parent_process_name
| sort - count
```

### Example (Sigma)
```yaml
title: Suspicious PowerShell Encoded/Obfuscated Command
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_flags:
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
      - ' -nop '
      - ' -w hidden '
      - 'IEX'
      - 'DownloadString'
      - 'FromBase64String'
  condition: selection_img and selection_flags
level: high
```

## False Positives
- Legitimate administrative scripts and software deployment tools (SCCM, Intune)
- IT automation frameworks that use encoded commands

## Response
1. Capture the full decoded script block (Event ID 4104).
2. Identify the parent process and originating user.
3. Isolate the host if a download/execute chain is confirmed.

## References
- https://attack.mitre.org/techniques/T1059/001/
