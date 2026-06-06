#  Mapping Table

Every technique in this lab, mapped to the **Lockheed Martin Cyber Kill Chain** (the attack narrative) and to **MITRE ATT&CK** (the technical labels), with the log source and the detection used to catch it.

| # | Technique | Kill Chain Phase | ATT&CK ID | Log Source | Detection (summary) | Writeup |
|---|-----------|------------------|-----------|------------|---------------------|---------|
| 1 | RDP Brute Force | Exploitation | [T1110](https://attack.mitre.org/techniques/T1110/) | Windows Security `4625` | Alert when one source produces more than 10 failed logins in a short window | [T1110-bruteforce.md](detections/T1110-bruteforce.md) |
| 2 | Encoded PowerShell | Execution | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Sysmon `EID 1` | Regex on the command line for `-e*` plus a base64 blob, which also catches the short `-E` form | [T1059-powershell.md](detections/T1059-powershell.md) |
| 3 | Run-Key Persistence | Installation | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Sysmon `EID 13` | Detect a registry write to a `...\CurrentVersion\Run` key and flag suspicious payload paths | [T1547-persistence.md](detections/T1547-persistence.md) |
| 4 | C2 Beaconing | Command & Control | [T1071](https://attack.mitre.org/techniques/T1071/) | Sysmon `EID 3` | Behavior based: many connections to one address at a regular interval (low jitter) | [T1071-c2.md](detections/T1071-c2.md) |

## The attack chain

The four techniques form one complete intrusion:

1. **Exploitation:** the attacker brute-forces RDP to gain access (T1110)
2. **Execution:** runs a hidden, base64-encoded PowerShell command (T1059.001)
3. **Installation:** establishes persistence with a registry Run key so access survives a reboot (T1547.001)
4. **Command & Control:** the implant beacons back to the C2 server at a regular interval (T1071)

Access, execution, persistence, command and control.

## Coverage by log source

| Log source | Techniques covered |
|------------|--------------------|
| Windows Security Log (`4625`) | T1110 |
| Sysmon Process Creation (`EID 1`) | T1059.001 |
| Sysmon Registry (`EID 13`) | T1547.001 |
| Sysmon Network Connection (`EID 3`) | T1071 |

Four distinct log sources and four distinct detection styles: volume threshold, command-line pattern, registry monitoring, and behavior based timing analysis.