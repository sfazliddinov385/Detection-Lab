# Detection Lab: Blue-Team Detection Engineering Portfolio

![Splunk](https://img.shields.io/badge/SIEM-Splunk%20Enterprise-black.svg)
![Sysmon](https://img.shields.io/badge/telemetry-Sysmon-blue.svg)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red.svg)
![Kali](https://img.shields.io/badge/attacker-Kali%20Linux-purple.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

This lab simulates real attacker techniques against an isolated environment and detects each one in Splunk. Every detection is mapped to both the Lockheed Martin Cyber Kill Chain and MITRE ATT&CK.

The project covers the full SOC analyst workflow: generating attacker activity, finding it in a SIEM, writing a detection for it, documenting the result, and mapping it to the standard frameworks. All attacks are run against owned VMs on a closed network using established tools (Hydra, Atomic Red Team). No live malware is used.

**At a glance:**
- 3-VM lab: Windows victim, Kali attacker, Ubuntu Splunk defender
- 4 attack techniques, 4 log sources, 4 detection styles
- Full Cyber Kill Chain coverage: access, execution, persistence, command and control
- SPL detections plus portable Sigma rules for each technique

---

## Architecture

Three VMs on a closed host-only network with no internet access during testing.

| VM | Role | OS | Main software |
|----|------|----|---------------|
| **Victim / Endpoint** | Target of the attacks. Generates the logs. | Windows 11 (`Advanced.lab.local`) | Sysmon (SwiftOnSecurity config), Splunk Universal Forwarder |
| **Attacker** | Launches the attacks. Also serves as the C2 server. | Kali Linux | Hydra, Atomic Red Team, Python |
| **Defender / Analyst** | Collects logs. Hosts the detection work. | Ubuntu | Splunk Enterprise |

```
[ Kali Attacker ] --attacks--> [ Windows Victim ] --Sysmon + Security logs-->
     (also C2 server)                |
                                     +--Universal Forwarder :9997--> [ Splunk (Ubuntu) ]
                                                                        (hunt + detect)
```

See [lab-setup/architecture.md](lab-setup/architecture.md) for the full VM specs, IP addresses, and network isolation details.

---

## Detections

Four techniques, four log sources, four detection styles. Together they form one complete attack chain.

| # | Technique | Kill Chain | ATT&CK | Log Source | Writeup |
|---|-----------|------------|--------|------------|---------|
| 1 | RDP Brute Force | Exploitation | T1110 | Security `4625` | [link](detections/T1110-bruteforce.md) |
| 2 | Encoded PowerShell | Execution | T1059.001 | Sysmon `EID 1` | [link](detections/T1059-powershell.md) |
| 3 | Run-Key Persistence | Installation | T1547.001 | Sysmon `EID 13` | [link](detections/T1547-persistence.md) |
| 4 | C2 Beaconing | Command & Control | T1071 | Sysmon `EID 3` | [link](detections/T1071-c2.md) |

**The attack chain:** the attacker gains access through an RDP brute force, executes an encoded PowerShell command, establishes persistence with a registry Run key, then beacons back to a command-and-control server. Access, execution, persistence, command and control.

Full table: [mapping-table.md](mapping-table.md)

---

## What each detection covers

- **T1110 (volume):** alerts on a spike of failed logins. The `4625` sub-status code is used to distinguish password guessing against a known account from username enumeration.
- **T1059.001 (pattern):** identifies base64-encoded PowerShell, including the short `-E` form that a plain `-EncodedCommand` search would miss. It also flags PowerShell launched by WMI.
- **T1547.001 (registry):** detects autostart persistence in the registry and reduces installer noise by flagging suspicious payload paths.
- **T1071 (behavior):** identifies C2 by the regular timing of the connections rather than a known-bad address, so it can catch a beacon to a previously unseen destination.

---

## Tools and frameworks

**SIEM and logging:** Splunk Enterprise, Splunk Universal Forwarder, Sysmon (SwiftOnSecurity config)
**Attack tooling:** Hydra, Atomic Red Team
**Frameworks:** MITRE ATT&CK, Lockheed Martin Cyber Kill Chain
**Detection output:** SPL queries and portable Sigma rules

---

## Repository layout

```
detection-lab/
├── README.md                  this file
├── mapping-table.md           master table: technique to framework to detection
├── lab-setup/
│   ├── architecture.md        VM specs, network configuration, install order
│   └── sysmon-config-notes.md
├── detections/
│   ├── T1110-bruteforce.md
│   ├── T1059-powershell.md
│   ├── T1547-persistence.md
│   └── T1071-c2.md
├── sigma-rules/               portable .yml detection rules
├── diagrams/                  Kill Chain diagram, ATT&CK Navigator layer
└── screenshots/               evidence for each technique
```

---

## Safety and scope

All activity was performed in a closed host-only lab against owned VMs. No live malware was used. Attacks were simulated with Hydra and Atomic Red Team. Windows Defender was disabled on the victim only within the lab so it would not block the test activity. In a production environment, detection would rely on tuned exclusions rather than disabling antivirus.

---

## Author

**Beck (Sarvarbek)**, aspiring SOC Analyst
CompTIA Security+, A+, AWS Cloud Practitioner. Studying CySA+.
GitHub: [@sfazliddinov385](https://github.com/sfazliddinov385)

For educational purposes only.