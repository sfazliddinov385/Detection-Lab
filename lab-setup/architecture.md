# Detection Lab - Architecture

## Purpose

A small, self-contained lab for generating attack telemetry, collecting it in a SIEM, and validating detection rules (Sigma and SPL) against the resulting logs.

## Topology

```mermaid
flowchart TB
    Host["Host / Hypervisor<br/>VMware Workstation"]

    subgraph NET["Host-only network (192.168.226.0/24, no internet)"]
        direction LR
        Kali["<b>Kali - Attacker</b><br/>192.168.226.130<br/>Hydra, Atomic Red Team, C2 server"]
        Victim["<b>Windows 11 - Victim</b><br/>192.168.226.128<br/>Sysmon + Splunk Universal Forwarder"]
        Splunk["<b>Ubuntu - SIEM / Defender</b><br/>192.168.226.129<br/>Splunk Enterprise (receiver :9997)"]
    end

    Host -->|"runs the 3 VMs"| NET
    Kali ==>|"attacks"| Victim
    Victim ==>|"forwards Sysmon + Security logs :9997"| Splunk
    Victim -.->|"C2 beacon"| Kali

    classDef attacker fill:#fdecea,stroke:#c0392b,color:#111;
    classDef victim fill:#fef9e7,stroke:#b7950b,color:#111;
    classDef defender fill:#eafaf1,stroke:#1e8449,color:#111;
    classDef host fill:#eef2f7,stroke:#34495e,color:#111;
    class Kali attacker;
    class Victim victim;
    class Splunk defender;
    class Host host;
```

## Components

| Role | Host | IP | Key Software |
|----------------|----------------|------------------|--------------------------------------|
| Victim / Endpoint | Windows 11 | 192.168.226.128 | Sysmon (SwiftOnSecurity config), Splunk Universal Forwarder |
| SIEM / Collector | Ubuntu | 192.168.226.129 | Splunk Enterprise, Sigma rules |
| Attacker | Kali Linux | 192.168.226.130 | Hydra, Atomic Red Team, Python (acts as C2 server) |

This lab has no domain controller. The victim is a standalone, non-domain-joined Windows 11 host, so authentication is local (NTLM over RDP) rather than Kerberos.

## Data Flow

1. The attacker runs a technique (T1110, T1059.001, T1547.001, or T1071) from Kali against the Windows victim. Hydra drives the brute force, Atomic Red Team runs the execution and persistence tests, and a Python `http.server` plus a PowerShell loop simulate the C2 beacon.
2. Sysmon and the Windows Security log on the victim record the activity: process creation, registry changes, network connections, and logon attempts.
3. The Splunk Universal Forwarder ships those logs to Splunk Enterprise on the Ubuntu box over port 9997.
4. Splunk searches (SPL) and the Sigma rules run against the indexed data to detect each technique.
5. Findings and screenshots are saved under `screenshots/`.

## Logging Coverage

- Authentication: Windows Security `4624` (success) and `4625` (failure)
- Process creation with full command line: Sysmon `EID 1`
- Registry value changes: Sysmon `EID 13`
- Network connections: Sysmon `EID 3`

The SwiftOnSecurity Sysmon config also captures other event types (such as DNS queries via `EID 22`) that are available for future detections.

Note: PowerShell here is detected through the command line captured in Sysmon `EID 1`, not through Script Block Logging (`4104`). Enabling Script Block Logging and Process Creation auditing (`4688`) would be a solid next addition to this lab.

## Mapped Techniques

| Technique | Name | Rule file |
|-----------|---------------------------------------|-----------------------------------|
| T1110 | Brute Force | ../sigma-rules/T1110-bruteforce.yml |
| T1059.001 | PowerShell | ../sigma-rules/T1059-powershell.yml |
| T1547.001 | Registry Run Keys / Startup Folder | ../sigma-rules/T1547-persistence.yml |
| T1071 | Application Layer Protocol (C2) | ../sigma-rules/T1071-c2.yml |

See [sysmon-config-notes.md](sysmon-config-notes.md) for the Sysmon configuration used.
