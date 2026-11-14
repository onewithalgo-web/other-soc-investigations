# SOC Investigations on Other Platforms

Analyst write-ups for hands-on SOC investigations completed **outside** [SOC Simulator](https://www.socsimulator.com). The scenarios are training exercises, not live incidents. The scenario text is platform-authored. The investigation, verdicts, evidence and wording are my own, and each write-up says what I could not establish as well as what I could.

For the operations completed on SOC Simulator, see the [SOC Simulator Incident Reports](https://github.com/onewithalgo-web/SOC-Simulator-Incident-Reports) repository.

## Investigations

| # | Investigation | Platform | What happened | Result |
|---|---|---|---|---|
| 1 | [Introduction to Phishing](reports/01-intro-to-phishing-thetrydaily.md) | TryHackMe SOC Simulator (Elastic / Kibana) | Two phishing lures at TheTryDaily, one blocked and one allowed through to a credential page | 4 alerts closed, all marked correct. [Full report (PDF)](Mbanjwa_Zaio_Phishing_Report1_Introduction_to_Phishing.pdf) |
| 2 | [Phishing Unfolding](reports/02-phishing-unfolding-tryhatme.md) | TryHackMe SOC Simulator (Elastic / Kibana) | Invoice zip, reverse shell, finance share copied, data sent out over DNS | 15 true positives closed, all marked correct. [Full report (PDF)](Mbanjwa_Zaio_Phishing_Report2_Phishing_Unfolding.pdf) |
| 3 | [SOC291: System Time Lookup](reports/03-letsdefend-soc291-system-time-lookup.md) | LetsDefend (practice) | Discovery command on a workstation after reported brute force | True Positive, host contained, playbook 100% |

## How these are written

- **Evidence first.** Every claim traces to a log, a screenshot or a console view. Where I inferred something, the report says it is an inference.
- **Limits stated.** Each write-up lists what the evidence could not show, such as whether a password was typed or who ran a command.
- **Mistakes kept in.** The reports record what I got wrong, for example misreading the firewall logs for half an hour and filing a true positive with the routine alerts.
- **MITRE ATT&CK mapping** covers behaviour I observed, not every technique a scenario might involve.
