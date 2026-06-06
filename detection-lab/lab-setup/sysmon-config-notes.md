# Sysmon Configuration Notes

Sysmon (System Monitor) is the endpoint telemetry source for three of the four detections in this lab. It logs detailed activity that the default Windows event log does not, and it is what makes process, network, and registry detection possible.

---

## What Sysmon is

Sysmon is a free Windows system service from Microsoft Sysinternals. Once installed, it writes rich event records to a dedicated log:

```
Applications and Services Logs > Microsoft > Windows > Sysmon > Operational
```

Those events are then forwarded to Splunk by the Universal Forwarder and land in the `sysmon` index.

---

## Configuration used

This lab uses the **SwiftOnSecurity** Sysmon configuration, a widely used community baseline. It is well tuned: it captures high-value activity while filtering out a large amount of routine Windows noise, so the logs stay useful instead of overwhelming.

Install (run from an admin prompt in the folder containing `Sysmon64.exe` and the config):

```cmd
Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

Confirm the service is running:

```cmd
sc query sysmon64
```

Update the configuration later without reinstalling:

```cmd
Sysmon64.exe -c sysmonconfig-export.xml
```

---

## Event IDs used in this lab

Sysmon assigns a numeric Event ID to each kind of activity. The four detections rely on three of them:

| Sysmon Event ID | Meaning | Used by detection |
|-----------------|---------|-------------------|
| `1` | Process Creation (image, command line, parent) | T1059.001 Encoded PowerShell |
| `3` | Network Connection (source, destination IP and port) | T1071 C2 Beaconing |
| `13` | Registry Value Set | T1547.001 Run-Key Persistence |

The fourth detection, T1110 Brute Force, uses the Windows Security log (`4625`) rather than Sysmon.

### Why each Event ID matters

- **EID 1 (Process Creation)** records the full command line and the parent process. The full command line is what exposes an encoded PowerShell command, and the parent process is what reveals PowerShell launched by WMI.
- **EID 3 (Network Connection)** records each outbound connection with its destination and a timestamp. The timestamps are what make beacon timing analysis possible.
- **EID 13 (Registry Value Set)** records the process that changed a registry value, the exact key, and the new value. That is exactly the information needed to catch autostart persistence.

---

## Why Sysmon over the default logs

The default Windows event log records that an event happened, but often without the detail an analyst needs. Sysmon adds the context that turns a log line into a detection:

- Full command lines (not just "a process started")
- Parent-child process relationships
- Outbound network connections per process
- Registry changes with the responsible process

Three of the four detections in this lab would not be possible from the default Windows logs alone.

---

## Verifying Sysmon data in Splunk

After install, confirm events are arriving:

```spl
index=sysmon
| stats count by EventCode
| sort - count
```

A healthy result shows counts for EventCodes 1, 3, and 13 (among others), which confirms process, network, and registry telemetry are all flowing to the SIEM.