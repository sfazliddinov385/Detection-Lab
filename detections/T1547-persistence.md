# T1547 - Boot or Logon Autostart Execution

## Overview
Adversaries configure system settings to automatically execute a program during
boot or logon to maintain persistence. The most common sub-technique is abuse of
the Registry Run keys and the Startup folder.

- **Tactic:** Persistence, Privilege Escalation
- **Technique:** [T1547](https://attack.mitre.org/techniques/T1547/)
- **Sub-technique:** [T1547.001 - Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- **Platforms:** Windows

## Data Sources
- Registry modification (Sysmon Event ID 12/13/14)
- File creation in Startup folders (Sysmon Event ID 11)
- Windows Security Event ID 4657 (registry value modified)

## Key Autostart Locations
```
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
```

## Detection Logic

### Example (Sigma)
```yaml
title: Registry Run Key Persistence
logsource:
  category: registry_set
  product: windows
detection:
  selection:
    TargetObject|contains:
      - '\CurrentVersion\Run\'
      - '\CurrentVersion\RunOnce\'
      - '\Policies\Explorer\Run\'
  filter_known:
    Details|contains:
      - 'C:\Program Files\'
      - 'C:\Windows\system32\'
  condition: selection and not filter_known
level: medium
```

### Example (Splunk SPL)
```spl
index=windows (EventCode=13 OR EventCode=12)
  (TargetObject="*\\CurrentVersion\\Run*"
   OR TargetObject="*\\Policies\\Explorer\\Run*")
| where NOT match(Details, "^C:\\\\(Program Files|Windows)\\\\")
| stats count by host, user, TargetObject, Details
```

## False Positives
- Legitimate software installers adding autostart entries
- Vendor agents (EDR, backup, VPN clients)

## Response
1. Validate the binary/script referenced by the autostart value.
2. Check the signing status and file reputation of the target.
3. Remove the malicious key and remediate the dropped payload.

## References
- https://attack.mitre.org/techniques/T1547/001/
