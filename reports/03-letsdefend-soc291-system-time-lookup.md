# SOC291: System Time Lookup on a Workstation

**Platform:** LetsDefend (practice environment) | **Format:** Investigation, own work | **Tools:** Case Management, Endpoint Security, Log Management, Threat Intel, VirusTotal, AbuseIPDB | **Case worked:** 12 August 2026 (alert dated 10 June 2024 in the scenario) | **Verdict:** True Positive, host contained, playbook score 30 (100%)

## Scenario

An endpoint alert fired on the workstation **Campbell** (172.16.17[.]213, Windows 10, domain LetsDefend) after `net time \\EC2AMAZ-ILGVOIN` ran. That is a system time lookup, a recognised discovery action. The alert is typed Brute Force and carries a note from the first-line analyst: they could not tell whether an authorised user or an attacker ran the command, but they had seen brute-force activity from `37.19.221.238` minutes earlier.

## Investigation and confirmed findings

| Step | Finding |
|---|---|
| Alert record | Rule "System Time Lookup Detected", trigger reason "Possible System Time Discovery Attempt Detected", trigger command `net time \\EC2AMAZ-ILGVOIN` |
| Endpoint process view | `net.exe` (PID 6844) at 06:56:19, spawned by `cmd.exe` (PID 1616), running as `EC2AMAZ-ILGVOIN\LetsDefend`, resolved to `C:\Windows\system32\net1 time \\EC2AMAZ-ILGVOIN` |
| What that tells me | The `net` to `net1` hand-off is normal Windows behaviour. An interactive `cmd.exe` as parent means the command was typed or scripted at a shell, not emitted by a service |
| Browser history | 24 entries, all routine Windows-related sites |
| Network actions | 12 entries around the window, including Microsoft and Google infrastructure and the AWS metadata address 169.254.169.254. Nothing pointing to payload delivery or command and control |
| Log Management pivot | Searching the host address returned only **8 events** (DNS queries and EventID 4688 process creations). No sign of scanning or lateral movement |
| Outcome | Host Campbell placed in containment. Alert closed as True Positive |

## Threat intelligence on 37.19.221[.]238

| Source | Result |
|---|---|
| VirusTotal | 0 of 91 vendors flag it. AS212238 (Datacamp Limited), United States |
| AbuseIPDB | 72 reports, 24% abuse confidence, usage type Data Center / Web Hosting / Transit |
| WHOIS (RIPE) | No data. The lookup returned `ERROR:201 access denied` |
| LetsDefend Threat Intel | No data on this address |

The two reputation sources disagree, and that is the finding. A clean VirusTotal score is normal for shared hosting infrastructure, while AbuseIPDB shows a history of abuse without a consensus verdict. The usage type matters most: inbound authentication attempts from a hosting provider to an internal workstation have no legitimate business explanation. I assess, with **low confidence**, that the address is hostile infrastructure rather than a shared host used opportunistically.

## MITRE ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Discovery | T1124 System Time Discovery | `net time` on Campbell |
| Execution | T1059.003 Windows Command Shell | `net.exe` spawned by `cmd.exe` |

The alert tags eleven techniques. Those are what the scenario could involve, not what I observed, so I mapped only the two the evidence supports. I did not map Brute Force (T1110), because that activity appears only in the first-line analyst's note and I did not capture the records myself.

## What I could not establish

- **Who ran the command.** Host telemetry does not separate an administrator from an intruder using the same account.
- **Whether the brute force worked.** I did not examine authentication success or failure records.
- **Whether the brute force and the lookup are the same actor.** That link comes from the first-line note and was not independently corroborated.
- **What followed.** No lateral movement, persistence or exfiltration appeared in the data I had.
- **Timestamps.** The platform's modules show different offsets. The alert states `+03:00`, but Log Management shows `cmd.exe` PID 1616 at 05:56:18 while Endpoint Security shows the same process at 06:56:18, an hour apart for the same event. My UTC times use the alert's stated offset and should be read with that caveat.

## Recommendations

1. Block `37.19.221[.]238` at the perimeter and add it to a watchlist.
2. Review authentication logs for Campbell and the `LetsDefend` account to find out whether the brute force succeeded. Force a credential reset if any success from that address appears.
3. Hunt for the same source address against other internal hosts.
4. Tune the rule: `net time` alone is a weak signal with legitimate admin uses. Correlating it with a preceding authentication anomaly from an external address would raise confidence in the alert.

## Takeaway

The command alone proves very little, since `net time` is ordinary administration. The verdict leans on context from the alert record, and the report says so. The most useful thing I can add to a case like this is the missing evidence: pulling the brute-force records, with timestamps, would turn a sequence of events into a causal chain.
