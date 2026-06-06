# Investigation: RDP Brute Force That Led to a Compromised Host

| Field | Value |
|-------|-------|
| Incident ID | INV-2026-001 |
| Date | 2026-06-05 |
| Analyst | Beck (Tier 1) |
| Source alert | "RDP/Network Brute Force - Failed Logon Spike" |
| Affected host | `Advanced.lab.local` (192.168.226.128) |
| Source IP | 192.168.226.130 |
| Final severity | High (host compromise confirmed) |
| Status | Escalated to Tier 2 |

---

## What this is

This is me walking through how I worked the alert. I start when it shows up and go step by step. For each step I show what I saw, the question it raised, and what I did next. The detection rules live in the `detections/` folder. This file is about the decisions.

---

## The alert that fired

A Splunk search alerted on a burst of failed logins:

```spl
index=wineventlog EventCode=4625
| bin _time span=5m
| stats count AS failed_logons by _time, Account_Name, Source_Network_Address
| where failed_logons > 10
```

It found **249 failed logins** on the `sfazl` account. All from one IP, **192.168.226.130**, in a short window.

Failed-login alerts are noisy. So the first job is figuring out if this one is real.

---

## Decision 1: Is this real, or just noise?

Failed logins happen for boring reasons. A service account with an expired password. An app stuck in a loop. Someone with an old password saved on their phone. So I need to know if this is an attack or not.

**Check:** the sub-status code on the failed logins. It tells me why each one failed.

```spl
index=wineventlog EventCode=4625 Source_Network_Address="192.168.226.130"
| stats count by Sub_Status, Account_Name, Workstation_Name
```

**What I found:**
- Every event has sub-status `0xC000006A`. That means the username is real but the password is wrong. So whoever this is already knows `sfazl` is a real account and is guessing the password. (If the code were `0xC0000064`, that means the user does not exist. That would be someone guessing usernames, which is less urgent.)
- All 249 tries came from one IP in a short window. A person mistyping a password does not do that.
- The workstation name is `kali`. We do not have a machine called kali. Real failed logins come from named company computers.

**Decision:** this is someone trying to brute force a real account. Not noise. Keep going.

---

## Decision 2: Did they get in?

This is the big one. A failed brute force is just an attempt. A successful one means they are inside. I cannot stop until I know if any try worked.

**Check:** switch from failed logins (`4625`) to successful ones (`4624`) from the same IP, around the same time.

```spl
index=wineventlog EventCode=4624 Source_Network_Address="192.168.226.130"
| table _time, Account_Name, Logon_Type, Source_Network_Address, Workstation_Name
```

**Two ways this can go:**
- **No `4624` from that IP:** they did not get in. Lower priority. Make sure the account is not locked, block the IP, write it up, keep an eye out. Done.
- **A `4624` shows up:** they guessed the password. The account is compromised. Bump it to High and keep digging.

**What I found:** there is a `4624` (Logon Type 3, network login) from 192.168.226.130 for `sfazl`, right after the failed logins stop. The tries stopping the moment a login succeeds is a clear sign one of the guesses worked.

**Decision:** the host is compromised. Now the question is what they did once they were in.

---

## Decision 3: What did they run after logging in?

They are in, so now I need to find out what they did. Most attackers run something right after they get access. So I check what programs started on the box after the login.

**Check:** Sysmon Event ID 1 logs new processes. I looked for PowerShell after the login time.

```spl
index=sysmon EventCode=1 ComputerName="Advanced.lab.local" Image="*\\powershell.exe"
| rex field=CommandLine "(?i)\s-e[a-z]*\s+(?<b64>[A-Za-z0-9+/=]{15,})"
| where isnotnull(b64)
| table _time, ParentImage, Image, CommandLine
```

**What I found:**
- PowerShell ran with an encoded command (`-E` and then a base64 blob). Hiding a command like that is a choice. Normal admins do not usually hide what they run.
- It used the short `-E` instead of the full `-EncodedCommand`. Worth noting: a search that only looked for `-EncodedCommand` would have missed this.

**Decision:** this is bad. They are running code, not just sitting there (T1059.001). Next I check for persistence and any outbound connections.

---

## Decision 4: Did they set up a way to stay?

An attacker who wants to keep access plants something that survives a reboot. If I miss it, cleaning the box does nothing. They just come back at the next login. So I have to check before I call anything clean.

**Check:** Sysmon Event ID 13 logs registry changes. I looked at the Run keys, which launch programs at login.

```spl
index=sysmon EventCode=13 ComputerName="Advanced.lab.local" TargetObject="*\\CurrentVersion\\Run*"
| table _time, Image, TargetObject, Details
```

**What I found:**
- Something wrote a value to the user's Run key, pointing at an `.exe`. Anything in that key runs every time the user logs in.
- The log shows what wrote it and where the file is, so Tier 2 can grab it.

**Decision:** there is persistence here (T1547.001). Cleanup has to include removing this Run key, not just killing the process. I will call that out when I escalate.

---

## Decision 5: Is it phoning home?

Last thing to check: is the box beaconing to a command server? If it is, the attacker has a live line in. That makes it more urgent and changes how I contain it.

**Check:** Sysmon Event ID 3 logs network connections. I did not look for a known-bad IP. I looked at the timing of the connections.

```spl
index=sysmon EventCode=3 ComputerName="Advanced.lab.local" Image="*\\powershell.exe"
| sort 0 _time
| streamstats current=f last(_time) as prev by Image, DestinationIp
| eval interval=_time-prev
| stats count avg(interval) as avg_sec stdev(interval) as jitter by DestinationIp, DestinationPort
```

**What I found:**
- The box keeps connecting to one address at an almost perfect interval. People and normal apps do not connect that evenly. Steady, even connections like that are a sign of a beacon.
- Because I looked at the timing and not the address, this would catch it even if we had never seen that destination before.

**Decision:** it is beaconing to a C2 server (T1071). The attacker has an open channel. Containment needs to include pulling the box off the network, not just locking the account.

---

## Verdict

This is a full break-in, not one stray alert. Someone at 192.168.226.130 brute forced the `sfazl` account over RDP, got in, ran a hidden PowerShell command, set up a Run key to stay, and opened a C2 channel. The host is compromised.

---

## Timeline

| Phase | What happened | Evidence |
|-------|---------------|----------|
| Exploitation | 249 failed RDP logins, then one success | Security `4625` (0xC000006A), then `4624` |
| Execution | Hidden PowerShell ran | Sysmon `EID 1` |
| Installation | Run-key persistence written | Sysmon `EID 13` |
| Command & Control | Steady beaconing to a server | Sysmon `EID 3` |

## ATT&CK mapping

| Tactic | Technique |
|--------|-----------|
| Credential Access | T1110 Brute Force |
| Execution | T1059.001 PowerShell |
| Persistence | T1547.001 Registry Run Keys |
| Command and Control | T1071 Application Layer Protocol |

---

## What I recommend

1. **Pull the host off the network** to cut the C2 channel.
2. **Disable the `sfazl` account** and reset the password. The attacker knows it.
3. **Block 192.168.226.130** at the firewall.
4. **Remove the Run key** from Decision 4, or the box gets reinfected at the next login.
5. **Send it to Tier 2** with this timeline and the file path so they can analyze the payload and fully clean it.

---

## What would be different in the real world

I ran this in a closed lab. The steps after the break-in were done on the box directly, not pushed through a live RDP session. So I pieced the timeline together from separate detections instead of one clean attacker session.

In a real environment the steps are the same. I would also have EDR data showing the full process tree, I would tie the `4624` login session straight to the programs that ran, and I would pull the actual file to analyze it.

The part that carries over is the thinking. Check if the alert is real. Find out if they got in. Then look at what they ran, whether they set up a way to stay, and whether it is phoning out, before calling the box clean.
