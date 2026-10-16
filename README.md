# Capstone Project 3: Splunk SIEM Deployment & Attack Simulation

![Splunk Enterprise](https://img.shields.io/badge/Splunk-10.4.3-green.svg)
![OS-Windows](https://img.shields.io/badge/OS-Windows_11-blue.svg)
![OS-Linux](https://img.shields.io/badge/OS-Kali_Linux-dragon.svg)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-v13-red.svg)

## 📌 EXECUTIVE SUMMARY

This repository documents the end-to-end deployment of a *Security Information and Event Management (SIEM)* environment using *Splunk Enterprise 10.4.3*, designed to address zero-visibility risks across Windows and Linux endpoints.

The lab demonstrates centralized log ingestion, continuous telemetry processing, multi-platform threat detection, and formal incident response mapped to the *MITRE ATT&CK Framework*. A key security finding confirmed during testing is that off-host log forwarding successfully preserves forensic evidence even after local event log wiping.

---

## 🏗️ Architecture & Network Topology

The architecture consists of a central Splunk Manager hosted on a Windows endpoint (PAPUS) receiving telemetry over TCP port 9997 from Universal Forwarders deployed on both Windows and Kali Linux hosts.

+-----------------------------------------------------------------------------------+
|                              ANALYST BROWSER                                      |
|                           http://localhost:8000                                   |
+------------------------------------------+----------------------------------------+
|
v
+------------------------------------------+----------------------------------------+
| PAPUS (Windows Host - Splunk Manager)                                             |
| - Splunk Enterprise 10.4.3 (Indexer & Search Head) [pid: 2192]                    |
| - Universal Forwarder: WinEventLog (Security, System, Application)               |
| - IP Addresses: 192.168.0.111 (Wi-Fi) | 192.168.100.1 (VMnet8) | 172.28.144.1 (WSL)    |
+------------------------------------------+----------------------------------------+
^
| TCP 9997 (Forwarded Logs)
|
+------------------------------------------+----------------------------------------+
| kali (Kali Linux Endpoint)                                                       |
| - Universal Forwarder: /var/log/auth.log, /var/log/syslog                         |
| - IP Addresses: 10.0.2.15 (eth0 - NAT) | 192.168.10.50 (eth1)                       |
+-----------------------------------------------------------------------------------+

Windows Universal Forwarder Configuration
⁠inputs.conf⁠:
[WinEventLog://Security]
disabled = 0
index = main

[WinEventLog://System]
disabled = 0
index = main

[WinEventLog://Application]
disabled = 0
index = main

outputs.conf:
[tcpout]
defaultGroup = lab

[tcpout:lab]
server = 192.168.0.111:9997

Linux Universal Forwarder Configuration
⁠inputs.conf⁠:
[monitor:///var/log/auth.log]
sourcetype = linux_auth
index = main

[monitor:///var/log/syslog]
sourcetype = syslog
index = main

⚔️ Attack Simulations & Detections
Controlled adversarial activities were executed in the isolated environment to validate log generation, forwarding pipelines, and search queries.

 # ATTACK VECTOR                     TARGET PLATFORM           MITTRE ATT&CK ID         PRIMARY TELEMETRY GENERATED
 1 SSH Localized Brute-force          Kali Linux                T1110.001               auth.log:Failed password for root
 2 Unauthorized Hidden Local Admin     Windows                  T1136.001              WinEventLog:Security: EventCode
 3 Security Event Log Clearing         Windows                  T1070.001              wevtutil cl Security (Event ID 1102)
 Bonus UID=0 Backdoor Account          Kali Linux               T1136.001              auth.log: useradd / passwd entries

 EXECUTED ATTACK COMMANDS
 :: Windows Account Creation & Log Evasion (PAPUS)
net user "SupportAdmin$" "P@ssword123!" /add
net localgroup Administrators "SupportAdmin$" /add
net user support_temp palosky /add && net localgroup Administrators support_temp /add
wevtutil cl Security

# Linux SSH Brute Force (Kali)
hydra -l root -P pass.txt ssh://127.0.0.1 -t 4

# Linux UID-0 Backdoor Account Creation
sudo useradd -m -u 0 -o backdoor_admin
sudo passwd backdoor_admin

🔍 Detection Engineering & SPL Queries
Cross-Platform Triage Query
Single search bar query surfacing active account creation and brute-force attempts across both Windows and Linux endpoints simultaneously:
index=* (EventCode=4720 OR EventCode=4728 OR "Failed password")

Production Detection Rules & Tuning
Rule 1: SSH Brute-Force Threshold Alert
index=main sourcetype=linux_auth "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| bin _time span=5m
| stats count by _time, host, src_ip
| where count >= 3

Rule 2: Suspicious Local Administrator Creation
index=main sourcetype=WinEventLog:Security (EventCode=4720 OR EventCode=4728 OR EventCode=4732)

Rule 3: Hidden Machine-Style Account Creation (⁠$⁠)
index=main sourcetype=WinEventLog:Security EventCode=4720
| where like(Account_Name, "%$")

Rule 4: Windows Security Audit Log Cleared
index=main sourcetype=WinEventLog:Security EventCode=1102

📝 Formal Incident Report (IR-2026-1003-01)
 Incident Title: Unauthorized Local Administrator Account Creation (⁠SupportAdmin$⁠ / ⁠support_temp⁠)
 Severity Rating: HIGH
 Status: Contained (Laboratory Simulation)
 Affected Host: PAPUS (Windows Endpoint)

Incident Summary
On October 3, 2026, two local accounts (⁠SupportAdmin$⁠ and ⁠support_temp⁠) were created on host ⁠PAPUS⁠ and immediately added to the local ⁠Administrators⁠ group. The trailing ⁠$⁠ was appended to mimic machine account naming conventions. Following account creation, ⁠wevtutil cl Security⁠ was executed to erase local event logs. Because logs were actively shipped to Splunk via TCP ⁠9997⁠, forensically complete records of ⁠EventCode 4720⁠ and ⁠4728⁠ were retained in the SIEM index.

Evidence (Raw Log Snippet)
10/03/2026 11:03:46.428 PM LogName=Security EventCode=4720 ComputerName=PAPUS
Account_Name=SupportAdmin$ Message=A user account was created.

10/03/2026 11:03:46.423 PM LogName=Security EventCode=4728 ComputerName=PAPUS
Target_Group_Name=Administrators Account_Name=SupportAdmin$ Message=A member was added to a security-enabled global group.

Remediation & Recommendations
1. Containment: Immediately disable/delete accounts ⁠SupportAdmin$⁠ and ⁠support_temp⁠. Audit local ⁠Administrators⁠ group membership.
2. Detection Hardening: Convert the SPL queries into saved correlation rules triggering real-time alerts upon ⁠EventCode 4720⁠, ⁠4728⁠, ⁠4732⁠, and ⁠1102⁠.
3. Log Protection: Enforce Group Policy Objects (GPO) restricting ⁠wevtutil⁠ execution rights and enable process command-line logging (⁠Event ID 4688⁠).
4. Linux Hardening: Restrict direct root SSH authentication (⁠PermitRootLogin no⁠ in ⁠/etc/ssh/sshd_config⁠), implement key-based authentication, and monitor for non-root accounts with ⁠UID 0⁠.
📜 Deliverables Traceability
 [x] Splunk Manager & Forwarder Deployments
 [x] Architecture Diagram with Network IPs
 [x] Continuous Ingestion Proof (157+ events verified)
 [x] Attack Simulations (SSH Brute Force, Local Admin Creation, Log Clearing)
 [x] Detection Rules & Tuning Matrix
 [x] Formal Incident Report (IR-2026-1003-01)
