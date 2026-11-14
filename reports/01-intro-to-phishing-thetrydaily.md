# Introduction to Phishing: Two Lures, One Page That Loaded

**Platform:** TryHackMe SOC Simulator (Elastic / Kibana edition) | **Format:** Investigation, own work | **Tools:** Kibana Discover (email and firewall logs) | **Date:** 21 September 2026 | **Verdict:** 3 true positives (1 escalated), 1 false positive closed, 1 false positive assessed

## Scenario

Five alerts fired at TheTryDaily over about eight minutes, all of them either an inbound email with an external link or a firewall block. The work was to decide which were real, find out whether anyone reached the links, and say what to do about it. Every piece of evidence in the report comes from Kibana searches. I did not use VirusTotal, a sandbox or any other analysis tool.

## Investigation and confirmed findings

| Alert | What it was | Verdict |
|---|---|---|
| 8814 | Onboarding email from `hrconnex.thm` to j.garcia | **False positive.** An internal email at 22:42:49 describes hrconnex.thm as the new third-party HR vendor, no one opened the link, no lookalike sender domains in the 25 email events |
| 8815 | Fake Amazon delivery notice from `urgents@amazon.biz` to h.harris, shortened `bit.ly` link, 48-hour deadline | **True positive** |
| 8816 | Firewall blocked 10.20.2.17 from that same `bit.ly` link, 74 seconds after the email arrived | **True positive.** The control worked |
| 8817 | Fake Microsoft sign-in warning from `no-reply@m1crosoftsupport.co` (digit 1 for the letter i) to c.allen | **True positive, escalated** |
| 8818 | Second hrconnex.thm email, same sender and subject as 8814 | Assessed false positive. Not formally closed, because the scenario ended when the last true positive closed |

The two phishing emails had different outcomes. The Amazon link was blocked. The Microsoft login page was **allowed**: host 10.20.2.25 loaded `https://m1crosoftsupport.co/login` (45.148.10.131:443) 69 seconds after the email reached c.allen. The host's next event was a Google search at 22:48:57, and nothing further went to that address. The logs show the page loading, not whether anyone typed a password into it, so I rated the incident **High** until c.allen's account has been checked.

The firewall URL field is what tied the alerts together. A search on `URL:*m1crosoft* or URL:*bit.ly*` returned exactly two events, the allowed login page and the blocked short link.

## Indicators

| Type | Indicator |
|---|---|
| Domain | `amazon.biz` (lookalike), `m1crosoftsupport.co` (lookalike) |
| Sender | `urgents@amazon.biz`, `no-reply@m1crosoftsupport.co` |
| URL | `http://bit.ly/3sHkX3da12340` (blocked), `https://m1crosoftsupport.co/login` (allowed) |
| IP | `45.148.10.131` (443), `67.199.248.11` (80) |
| Internal hosts | 10.20.2.25 opened the phishing page, 10.20.2.17 attempted the short link |

`hrconnex.thm` is not an indicator. I assessed it as a legitimate vendor, pending confirmation from HR or procurement.

## MITRE ATT&CK mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1566.002 – Phishing: Spearphishing Link |

## What I got wrong and what I could not establish

- I spent the first part of the investigation believing the firewall logs recorded no websites, because I only looked at the IP and port columns. The `URL` field was in the list of available fields the whole time. It only changed the picture once the Microsoft lookalike alert made me look.
- The logs do not link IP addresses to people, so I could not confirm whose machines 10.20.2.17 and 10.20.2.25 are. The simulator's own feedback pointed at the same gap: connecting affected users to their hosts.
- My call on the HR email rests on a single internal message, so it should be confirmed with HR or procurement.

## Result

Simulator result: security breach prevented, 330 points, four alerts closed, all four classifications marked correct.

## Takeaway

When the evidence says "the page loaded", the honest report says exactly that and no more. I escalated on a loaded page, not on a stolen password, and I said which of the two I could prove. The biggest improvement is a detection one: map hosts to users in the same place as the logs, and put the firewall URL in the default view so the next analyst finds it in minutes instead of half an hour.
