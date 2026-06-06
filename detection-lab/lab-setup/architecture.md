# Detection Lab - Architecture

## Purpose
A small, self-contained lab for generating attack telemetry, collecting it, and
validating detection rules (Sigma) against the resulting logs.

## Topology
```
                +-----------------------------+
                |        Host / Hypervisor    |
                |        (VirtualBox/Hyper-V) |
                +--------------+--------------+
                               |
              Internal NAT network (192.168.56.0/24)
                               |
        +----------------------+----------------------+
        |                      |                      |
+---------------+    +-------------------+   +-------------------+
| Win10 Victim  |    | Windows Server DC |   |  SIEM / Collector |
| 192.168.56.10 |    |   192.168.56.5    |   |  192.168.56.20    |
| Sysmon +      |    | AD DS, DNS        |   | Splunk / ELK      |
| WinlogBeat    |    | Sysmon            |   | Sigma rules       |
+---------------+    +-------------------+   +-------------------+
        |                      |                      ^
        +----------- log forwarding (WEF/Beats) ------+

        +-------------------+
        | Attacker (Kali)   |
        | 192.168.56.100    |
        | Metasploit, etc.  |
        +-------------------+
```

## Components
| Role           | Host           | IP              | Key Software                         |
|----------------|----------------|-----------------|--------------------------------------|
| Victim         | Win10          | 192.168.56.10   | Sysmon, WinlogBeat, PowerShell logging |
| Domain Ctrl    | WinServer 2019 | 192.168.56.5    | AD DS, DNS, Sysmon                   |
| SIEM/Collector | Ubuntu/Win     | 192.168.56.20   | Splunk (or ELK), Sigma converter     |
| Attacker       | Kali Linux     | 192.168.56.100  | Metasploit, Impacket, custom scripts |

## Data Flow
1. Attacker executes a technique (T1110 / T1059 / T1547 / T1071) against victims.
2. Sysmon + Windows audit policy record process, registry, and network events.
3. WinlogBeat / Windows Event Forwarding ships logs to the SIEM.
4. Sigma rules (converted to SPL/EQL) run against the indexed data.
5. Findings + screenshots are captured under `detection-lab/screenshots/`.

## Logging Coverage
- Process creation (Security 4688 + Sysmon EID 1) with command line
- PowerShell Script Block Logging (4104) and Module Logging (4103)
- Registry modification (Sysmon EID 12/13)
- Network connections (Sysmon EID 3) + DNS queries (Sysmon EID 22)
- Authentication (Security 4624/4625)

## Mapped Techniques
| Technique | Name                                  | Rule file                         |
|-----------|---------------------------------------|-----------------------------------|
| T1110     | Brute Force                           | sigma-rules/T1110-bruteforce.yml  |
| T1059.001 | PowerShell                            | sigma-rules/T1059-powershell.yml  |
| T1547.001 | Registry Run Keys / Startup Folder    | sigma-rules/T1547-persistence.yml |
| T1071     | Application Layer Protocol (C2)       | sigma-rules/T1071-c2.yml          |

See [sysmon-config-notes.md](sysmon-config-notes.md) for the Sysmon configuration used.
