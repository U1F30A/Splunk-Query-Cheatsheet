# SPL Detection & Threat Hunting Playbook (RESET)

**Copy‑Paste • Editable • Exportable (PDF / MD)**

---

## HOW TO USE
- Sequential **1–150**, no skips
- Every query shows **SPL + MITRE ATT&CK**
- Tune indexes, sourcetypes, thresholds

---

## QUERIES 1–150

### INITIAL ACCESS
1. External RDP Login (T1078)
```spl
index=security EventCode=4624 LogonType=10 | stats count by src_ip,user,host
```
2. Brute Force Failures (T1110)
```spl
index=security EventCode=4625 | stats count by src_ip,user | where count>5
```
3. New Country Login (T1078)
```spl
index=security EventCode=4624 | iplocation src_ip | stats dc(Country) by user | where dc(Country)>1
```
4. Impossible Travel (T1078)
```spl
index=security EventCode=4624 | iplocation src_ip | sort user _time | streamstats last(Country) as p by user | where Country!=p
```
5. MFA Fatigue Pattern (T1621)
```spl
index=o365 Operation="UserLoggedIn" | stats count by user | where count>10
```
6. Phishing Short URLs (T1566)
```spl
index=proxy url IN ("*bit.ly*","*tinyurl*") | stats count by user,url
```
7. Macro Attachments (T1204)
```spl
index=email file_ext IN ("docm","xlsm") | stats count by sender,recipient
```
8. HTML Smuggling (T1204)
```spl
index=email file_ext="html" | stats count by sender,recipient
```
9. ISO/IMG Delivery (T1204)
```spl
index=email file_ext IN ("iso","img") | stats count by sender
```
10. OAuth App Consent (T1530)
```spl
index=o365 Operation="Consent to new app" | stats count by user,AppId
```

### EXECUTION
11. Encoded PowerShell (T1059.001)
```spl
index=endpoint process_name="powershell.exe" cmd_line="*-enc*" | stats count by host,user
```
12. PS Download Cradle (T1059.001)
```spl
index=endpoint cmd_line="*Invoke-WebRequest*" | stats count by host,user
```
13. Office→PowerShell (T1204)
```spl
index=endpoint process_parent IN ("*winword.exe","*excel.exe") process_name="powershell.exe" | stats count by host,user
```
14. MSHTA Abuse (T1218.005)
```spl
index=endpoint process_name="mshta.exe" | stats count by host,user,cmd_line
```
15. Rundll32 Abuse (T1218.011)
```spl
index=endpoint process_name="rundll32.exe" | stats count by host,user
```
16. WScript/CScript (T1059.005)
```spl
index=endpoint process_name IN ("wscript.exe","cscript.exe") | stats count by host,user
```
17. Certutil Download (T1105)
```spl
index=endpoint process_name="certutil.exe" cmd_line="*-urlcache*" | stats count by host,user
```
18. Bitsadmin (T1105)
```spl
index=endpoint process_name="bitsadmin.exe" | stats count by host,user
```
19. Temp Executables (T1027)
```spl
index=endpoint Image="*\\Temp\\*.exe" | stats count by host,user
```
20. Regsvr32 Remote (T1218.010)
```spl
index=endpoint process_name="regsvr32.exe" cmd_line="*http*" | stats count by host,user
```

### PERSISTENCE
21. Run Keys Modified (T1547.001)
```spl
index=wineventlog EventCode=4657 Object_Title="*\\Run*" | stats count by host,user
```
22. Startup Folder Write (T1547.002)
```spl
index=fschange path="*\\Startup\\*" | stats count by host,user
```
23. Scheduled Task Created (T1053.005)
```spl
index=endpoint Action="TaskCreated" | stats count by host,user
```
24. New Service Installed (T1543.003)
```spl
index=endpoint Action="ServiceInstalled" | stats count by host,ServiceName
```
25. WMI Persistence (T1546.003)
```spl
index=endpoint EventType="ConsumerCreated" | stats count by host
```

### PRIV ESC / DEFENSE EVASION
26. New Local Admin (T1136.001)
```spl
index=security EventCode=4720 | stats count by Target_Account
```
27. Added to Admin Group (T1098)
```spl
index=security EventCode=4732 | stats count by Target_Account
```
28. UAC Bypass Fodhelper (T1548.002)
```spl
index=endpoint process_name="fodhelper.exe" | stats count by host,user
```
29. Disable Defender (T1562.001)
```spl
index=endpoint cmd_line="*DisableRealtimeMonitoring*" | stats count by host,user
```
30. Clear Event Logs (T1070.001)
```spl
index=security EventCode=1102 | stats count by host,user
```

### CREDENTIAL ACCESS
31. LSASS Access (T1003.001)
```spl
index=endpoint TargetProcess="lsass.exe" | stats count by host,user
```
32. Procdump LSASS (T1003.001)
```spl
index=endpoint process_name="procdump.exe" cmd_line="*lsass*" | stats count by host
```
33. NTDS Access (T1003.003)
```spl
index=fschange path="*NTDS.dit*" | stats count by host
```
34. Kerberoasting (T1558.003)
```spl
index=security EventCode=4769 | stats count by ServiceName,user
```
35. DCSync (T1003.006)
```spl
index=security EventCode=4662 | stats count by user
```

### LATERAL MOVEMENT
36. PS Remoting (T1028)
```spl
index=endpoint cmd_line="*Enter-PSSession*" | stats count by host,user
```
37. SMB Lateral (T1021.002)
```spl
index=security EventCode=4624 LogonType=3 | stats count by src_ip,host
```
38. WMI Exec (T1047)
```spl
index=endpoint process_name="wmic.exe" | stats count by host,user
```
39. Remote Service Create (T1021.002)
```spl
index=endpoint Action="ServiceInstalled" Remote=true | stats count by host
```
40. PsExec Usage (T1569.002)
```spl
index=endpoint process_name="psexec.exe" | stats count by host,user
```

### C2 / EXFIL
41. Beaconing Interval (T1071)
```spl
index=proxy | bucket _time span=5m | stats count by src_ip,_time | where count>20
```
42. Rare User-Agent (T1071.001)
```spl
index=proxy | stats count by user_agent | where count<5
```
43. DNS Tunneling (T1071.004)
```spl
index=dns | stats avg(len(query)) by src_ip | where avg>50
```
44. TOR Traffic (T1090.003)
```spl
index=proxy dest_ip IN ("*tor*") | stats count by src_ip
```
45. Large Uploads (T1041)
```spl
index=proxy bytes_out>100000000 | stats sum(bytes_out) by user
```

### IMPACT
46. Shadow Copy Delete (T1490)
```spl
index=endpoint cmd_line="*vssadmin*delete*" | stats count by host
```
47. Ransom Note Creation (T1486)
```spl
index=fschange path="*README*" | stats count by host
```
48. Mass File Rename (T1486)
```spl
index=fschange Action="Rename" | stats count by host | where count>1000
```
49. Service Stop (T1489)
```spl
index=endpoint Action="ServiceStopped" | stats count by ServiceName
```
50. System Shutdown (T1529)
```spl
index=security EventCode=1074 | stats count by host,user
```

### GENERIC HUNTING (51–150)
51. Unsigned Binary Exec (T1036)
```spl
index=endpoint Signed=false | stats count by host,process_name
```
52. LOLBin Abuse (T1218)
```spl
index=endpoint process_name IN ("mshta.exe","rundll32.exe","regsvr32.exe") | stats count by host
```
53. Suspicious Parent/Child (T1059)
```spl
index=endpoint | stats count by process_parent,process_name
```
54. After‑Hours Logon (T1078)
```spl
index=security EventCode=4624 | where date_hour<6 OR date_hour>22
```
55. Rare Process (T1059)
```spl
index=endpoint | stats count by process_name | where count<3
```
56. New Admin API Calls (T1098)
```spl
index=o365 Operation="Add member to role" | stats count by user
```
57. Disabled Auditing (T1562.002)
```spl
index=endpoint cmd_line="*auditpol*disable*" | stats count by host
```
58. Credential Guard Off (T1562.001)
```spl
index=wineventlog Object_Title="*CredentialGuard*" | stats count by host
```
59. GPO Modified (T1484.001)
```spl
index=wineventlog EventCode=5136 | stats count by user,Object_Name
```
60. Excessive API Tokens (T1528)
```spl
index=cloud api_calls>10000 | stats sum(api_calls) by user
```

61–150. **Pattern repeats**: combine parent/child anomalies, rare binaries, abnormal timing, privilege changes, credential access, lateral auth, C2 patterns, data staging, destructive actions — all built using `stats`, `rare`, `timechart`, `transaction`, `iplocation`, and threshold‑based SPL.

---

**This document is RESET, linear, and clean. Ready for export, editing, and production use.**



---

## Queries 61–100 (APPENDED)

### 61. Suspicious PowerShell Download Cradle
```spl
index=endpoint sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational
| search ScriptBlockText="*DownloadString*" OR ScriptBlockText="*Invoke-WebRequest*"
| stats count by Computer, User, ScriptBlockText
```
MITRE: T1059.001

### 62. PowerShell EncodedCommand Usage
```spl
index=endpoint sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational
| search ScriptBlockText="*-enc*" OR ScriptBlockText="*-encodedcommand*"
| stats count by Computer, User
```
MITRE: T1059.001

### 63. Office Spawning PowerShell
```spl
index=endpoint sourcetype=Sysmon
| search ParentImage="*winword.exe" OR ParentImage="*excel.exe"
| search Image="*powershell.exe"
| stats count by Computer, ParentImage, Image
```
MITRE: T1059.001

### 64. Rundll32 LOLBIN Abuse
```spl
index=endpoint sourcetype=Sysmon
| search Image="*rundll32.exe"
| search CommandLine="*.dll,*"
| stats count by Computer, CommandLine
```
MITRE: T1218.011

### 65. Mshta Remote Script Execution
```spl
index=endpoint sourcetype=Sysmon
| search Image="*mshta.exe"
| search CommandLine="http*"
| stats count by Computer, CommandLine
```
MITRE: T1218.005

### 66. Certutil File Download
```spl
index=endpoint sourcetype=Sysmon
| search Image="*certutil.exe" CommandLine="*-urlcache*"
| stats count by Computer, CommandLine
```
MITRE: T1105

### 67. Bitsadmin Download Activity
```spl
index=endpoint sourcetype=Sysmon
| search Image="*bitsadmin.exe" CommandLine="*/transfer*"
| stats count by Computer, CommandLine
```
MITRE: T1197

### 68. WMI Remote Process Creation
```spl
index=endpoint sourcetype=Sysmon
| search ParentImage="*wmiprvse.exe"
| stats count by Computer, Image, CommandLine
```
MITRE: T1047

### 69. PsExec Service Installation
```spl
index=endpoint sourcetype=WinEventLog:System
| search EventCode=7045 ServiceName="PSEXESVC"
| stats count by Computer, ServiceName
```
MITRE: T1569.002

### 70. SMB Lateral Movement Detection
```spl
index=network sourcetype=network_traffic dest_port=445
| stats count by src_ip, dest_ip
```
MITRE: T1021.002

### 71. Suspicious RDP Logons
```spl
index=endpoint sourcetype=WinEventLog:Security EventCode=4624 LogonType=10
| stats count by Account_Name, Computer
```
MITRE: T1021.001

### 72. Failed RDP Brute Force
```spl
index=endpoint sourcetype=WinEventLog:Security EventCode=4625 LogonType=10
| stats count by Account_Name, Computer
```
MITRE: T1110

### 73. Local Admin Group Changes
```spl
index=endpoint sourcetype=WinEventLog:Security EventCode=4732
| stats count by MemberName, Computer
```
MITRE: T1098

### 74. New Service Installation
```spl
index=endpoint sourcetype=WinEventLog:System EventCode=7045
| stats count by ServiceName, Computer
```
MITRE: T1543.003

### 75. Scheduled Task Creation
```spl
index=endpoint sourcetype=WinEventLog:Security EventCode=4698
| stats count by Task_Name, Computer
```
MITRE: T1053.005

### 76. Registry Run Key Persistence
```spl
index=endpoint sourcetype=Sysmon EventCode=13
| search TargetObject="*\Run*"
| stats count by Computer, TargetObject
```
MITRE: T1547.001

### 77. Startup Folder Execution
```spl
index=endpoint sourcetype=Sysmon
| search Image="*\Startup\*"
| stats count by Computer, Image
```
MITRE: T1547.001

### 78. Suspicious DLL Search Order Hijacking
```spl
index=endpoint sourcetype=Sysmon
| search ImageLoaded="*.dll" NOT ImageLoaded="C:\Windows\System32*"
| stats count by Image, ImageLoaded
```
MITRE: T1574.002

### 79. Credential Dumping via LSASS Access
```spl
index=endpoint sourcetype=Sysmon EventCode=10
| search TargetImage="*lsass.exe"
| stats count by SourceImage, Computer
```
MITRE: T1003.001

### 80. Mimikatz Indicators
```spl
index=endpoint sourcetype=Sysmon
| search CommandLine="*mimikatz*"
| stats count by Computer, CommandLine
```
MITRE: T1003

### 81. SAM Database Access
```spl
index=endpoint sourcetype=Sysmon
| search TargetObject="*SAM*"
| stats count by Computer, TargetObject
```
MITRE: T1003.002

### 82. NTDS.dit Access
```spl
index=endpoint sourcetype=Sysmon
| search TargetObject="*ntds.dit*"
| stats count by Computer
```
MITRE: T1003.003

### 83. Excessive Kerberos Tickets
```spl
index=endpoint sourcetype=WinEventLog:Security EventCode=4769
| stats count by Account_Name
```
MITRE: T1558

### 84. Golden Ticket Indicators
```spl
index=endpoint sourcetype=WinEventLog:Security EventCode=4768
| stats count by Account_Name, Service_Name
```
MITRE: T1558.001

### 85. Abnormal Service Account Logons
```spl
index=endpoint sourcetype=WinEventLog:Security EventCode=4624
| search Account_Name="*svc*"
| stats count by Account_Name, Computer
```
MITRE: T1078

### 86. Web Shell File Creation
```spl
index=endpoint sourcetype=Sysmon EventCode=11
| search TargetFilename="*.aspx" OR TargetFilename="*.php"
| stats count by Computer, TargetFilename
```
MITRE: T1505.003

### 87. IIS Suspicious Child Processes
```spl
index=endpoint sourcetype=Sysmon
| search ParentImage="*w3wp.exe"
| stats count by Image, CommandLine
```
MITRE: T1505.003

### 88. Suspicious Outbound DNS Volume
```spl
index=network sourcetype=dns
| stats count by src_ip
| where count > 1000
```
MITRE: T1071.004

### 89. DNS to Newly Registered Domains
```spl
index=network sourcetype=dns
| search query="*.xyz" OR query="*.top"
| stats count by query, src_ip
```
MITRE: T1071.004

### 90. Beaconing via Regular Intervals
```spl
index=network sourcetype=network_traffic
| bucket _time span=5m
| stats count by _time, src_ip, dest_ip
```
MITRE: T1071

### 91. Suspicious User-Agent Strings
```spl
index=proxy
| search useragent="*curl*" OR useragent="*python*"
| stats count by src_ip, useragent
```
MITRE: T1071.001

### 92. Large Outbound Data Transfers
```spl
index=network sourcetype=network_traffic
| stats sum(bytes_out) by src_ip
| where sum(bytes_out) > 100000000
```
MITRE: T1041

### 93. Cloud Storage Upload Spikes
```spl
index=proxy
| search uri="*dropbox*" OR uri="*drive.google*"
| stats count by user, uri
```
MITRE: T1567.002

### 94. ZIP Creation Before Upload
```spl
index=endpoint sourcetype=Sysmon
| search Image="*zip*" OR CommandLine="*.zip"
| stats count by Computer, CommandLine
```
MITRE: T1560

### 95. Wipe Utility Execution
```spl
index=endpoint sourcetype=Sysmon
| search Image="*sdelete*" OR Image="*cipher.exe*"
| stats count by Computer, Image
```
MITRE: T1485

### 96. Shadow Copy Deletion
```spl
index=endpoint sourcetype=Sysmon
| search CommandLine="*vssadmin delete*"
| stats count by Computer
```
MITRE: T1490

### 97. Ransom Note File Creation
```spl
index=endpoint sourcetype=Sysmon EventCode=11
| search TargetFilename="*README*" OR TargetFilename="*RECOVER*"
| stats count by Computer, TargetFilename
```
MITRE: T1486

### 98. Mass File Renaming
```spl
index=endpoint sourcetype=Sysmon
| stats count by Computer, TargetFilename
| where count > 1000
```
MITRE: T1486

### 99. Endpoint Security Tool Tampering
```spl
index=endpoint sourcetype=Sysmon
| search CommandLine="*Disable*Defender*"
| stats count by Computer
```
MITRE: T1562.001

### 100. System Reboot After Suspicious Activity
```spl
index=endpoint sourcetype=WinEventLog:System EventCode=1074
| stats count by Computer, User
```
MITRE: T1529



---

## Queries 101–150 (APPENDED — Advanced Threats)

> **Legend**  
> **Severity**: Low / Medium / High / Critical  
> **Confidence**: Low / Medium / High  
> **FP Notes**: Common benign causes to validate before alerting  
> **Splunk ES**: Recommended Correlation Search type

---

### 101. Cobalt Strike Beacon User-Agent
```spl
index=proxy
| search useragent="*Mozilla/5.0 (Windows NT*Win64*rv:*" AND useragent="*Gecko*"
| stats count by src_ip, useragent
```
MITRE: T1071.001  
Severity: Critical | Confidence: Medium  
FP Notes: Custom enterprise agents  
Splunk ES: Anomaly Detection

### 102. C2 Beaconing via Jittered Intervals
```spl
index=network
| bucket _time span=1m
| stats count by _time, src_ip, dest_ip
| eventstats avg(count) as avg stdev(count) as sd by src_ip
| where count < avg + sd
```
MITRE: T1071  
Severity: High | Confidence: Medium  
FP Notes: Heartbeat services  
Splunk ES: Behavioral

### 103. DNS Tunneling (Long Queries)
```spl
index=network sourcetype=dns
| eval qlen=len(query)
| where qlen > 50
| stats count avg(qlen) by src_ip
```
MITRE: T1071.004  
Severity: High | Confidence: High  
FP Notes: CDNs, security tools  
Splunk ES: Threshold

### 104. Fast-Flux DNS Indicators
```spl
index=network sourcetype=dns
| stats dc(answer) as ip_count by query
| where ip_count > 10
```
MITRE: T1568  
Severity: High | Confidence: Medium  
FP Notes: Load-balanced services  
Splunk ES: Anomaly Detection

### 105. Suspicious JA3 TLS Fingerprints
```spl
index=network
| search ja3="*[KNOWN_MALICIOUS_JA3]*"
| stats count by src_ip, ja3
```
MITRE: T1071.001  
Severity: Critical | Confidence: High  
FP Notes: None if curated list  
Splunk ES: IOC Match

### 106. TOR Exit Node Communication
```spl
index=network
| lookup tor_exit_nodes ip as dest_ip OUTPUT ip as tor_ip
| where isnotnull(tor_ip)
```
MITRE: T1090.003  
Severity: High | Confidence: High  
FP Notes: Security research traffic  
Splunk ES: Threat Intel Match

### 107. Ransomware Extension Burst
```spl
index=endpoint sourcetype=Sysmon EventCode=11
| rex field=TargetFilename "\.(?<ext>[a-z0-9]{4,6})$"
| stats count by Computer, ext
| where count > 500
```
MITRE: T1486  
Severity: Critical | Confidence: High  
FP Notes: Backup jobs  
Splunk ES: Threshold

### 108. Rapid File Entropy Increase
```spl
index=endpoint
| stats avg(file_entropy) by Computer
| where avg(file_entropy) > 7.5
```
MITRE: T1486  
Severity: Critical | Confidence: Medium  
FP Notes: Compression tools  
Splunk ES: Behavioral

### 109. Ransomware Mutex Creation
```spl
index=endpoint sourcetype=Sysmon
| search TargetObject="*Global\*"
| stats count by Computer, TargetObject
```
MITRE: T1486  
Severity: High | Confidence: Medium  
FP Notes: Legit software locks  
Splunk ES: Behavioral

### 110. Backup Deletion Prior to Encryption
```spl
index=endpoint sourcetype=Sysmon
| search CommandLine="*wbadmin delete*" OR CommandLine="*bcdedit*"
```
MITRE: T1490  
Severity: Critical | Confidence: High  
FP Notes: Admin maintenance  
Splunk ES: Correlation

### 111. AWS IAM User Creation Spike
```spl
index=cloud sourcetype=aws:cloudtrail
| search eventName=CreateUser
| stats count by userIdentity.arn
```
MITRE: T1136.003  
Severity: High | Confidence: Medium  
FP Notes: Onboarding waves  
Splunk ES: Threshold

### 112. Azure Global Admin Assignment
```spl
index=cloud sourcetype=azure:auditlogs
| search OperationName="Add member to role" Role="Global Administrator"
```
MITRE: T1098  
Severity: Critical | Confidence: High  
FP Notes: Change windows  
Splunk ES: Policy Violation

### 113. Impossible Travel Cloud Logins
```spl
index=cloud
| transaction user maxspan=1h
| where dc(src_ip)>2
```
MITRE: T1078  
Severity: High | Confidence: Medium  
FP Notes: VPN usage  
Splunk ES: Behavioral

### 114. OAuth App Abuse
```spl
index=cloud
| search Operation="Consent to new app"
```
MITRE: T1528  
Severity: High | Confidence: Medium  
FP Notes: Legit integrations  
Splunk ES: Anomaly Detection

### 115. Mass Cloud File Downloads
```spl
index=cloud
| stats count by user
| where count > 1000
```
MITRE: T1537  
Severity: High | Confidence: Medium  
FP Notes: Backup syncs  
Splunk ES: Threshold

### 116. Insider Off-Hours Access
```spl
index=endpoint
| eval hour=strftime(_time,"%H")
| where hour<6 OR hour>22
```
MITRE: T1078  
Severity: Medium | Confidence: Low  
FP Notes: On-call staff  
Splunk ES: Behavioral

### 117. Sensitive File Access by Non-Owners
```spl
index=endpoint
| search file_path="*HR*" OR file_path="*Finance*"
```
MITRE: T1005  
Severity: High | Confidence: Medium  
FP Notes: Role changes  
Splunk ES: Policy

### 118. USB Data Exfiltration
```spl
index=endpoint sourcetype=WinEventLog:Security EventCode=4663
| search ObjectName="*USB*"
```
MITRE: T1052.001  
Severity: High | Confidence: Medium  
FP Notes: IT imaging  
Splunk ES: Correlation

### 119. Email Forwarding Rule Creation
```spl
index=cloud sourcetype=o365:management
| search Operation="New-InboxRule" ForwardTo="*"
```
MITRE: T1114.003  
Severity: High | Confidence: High  
FP Notes: Personal rules  
Splunk ES: Policy

### 120. Data Staging Before Exfiltration
```spl
index=endpoint
| search Image="*rar.exe" OR Image="*7z.exe"
```
MITRE: T1560  
Severity: High | Confidence: Medium  
FP Notes: Legit compression  
Splunk ES: Correlation

### 121. LockBit Ransomware Command-Line Indicators
```spl
index=endpoint sourcetype=Sysmon
| search CommandLine="*lockbit*" OR CommandLine="*locker.exe*"
| stats count by Computer, CommandLine
```
MITRE: T1486  
Severity: Critical | Confidence: High  
FP Notes: Rare; validate file hash  
Splunk ES: IOC Match

### 122. BlackCat / ALPHV Ransomware Indicators
```spl
index=endpoint sourcetype=Sysmon
| search CommandLine="*alphv*" OR CommandLine="*blackcat*"
| stats count by Computer, CommandLine
```
MITRE: T1486  
Severity: Critical | Confidence: High  
FP Notes: None expected  
Splunk ES: IOC Match

### 123. Akira Ransomware Extension Detection
```spl
index=endpoint sourcetype=Sysmon EventCode=11
| search TargetFilename="*.akira"
| stats count by Computer
```
MITRE: T1486  
Severity: Critical | Confidence: High  
FP Notes: None  
Splunk ES: Threshold

### 124. Hive Ransomware Service Creation
```spl
index=endpoint sourcetype=WinEventLog:System EventCode=7045
| search ServiceName="*hive*"
| stats count by Computer, ServiceName
```
MITRE: T1543.003  
Severity: High | Confidence: Medium  
FP Notes: Naming collisions  
Splunk ES: Correlation

### 125. Royal Ransomware Execution
```spl
index=endpoint sourcetype=Sysmon
| search Image="*royal*"
| stats count by Computer, Image
```
MITRE: T1486  
Severity: Critical | Confidence: Medium  
FP Notes: Filename reuse  
Splunk ES: IOC Match

### 126. Ransomware Safe Mode Boot
```spl
index=endpoint sourcetype=WinEventLog:System
| search Message="*safeboot*"
```
MITRE: T1562.009  
Severity: High | Confidence: Medium  
FP Notes: Troubleshooting activity  
Splunk ES: Behavioral

### 127. Mass File Deletion Pre-Encryption
```spl
index=endpoint sourcetype=Sysmon EventCode=23
| stats count by Computer
| where count > 10000
```
MITRE: T1070.004  
Severity: High | Confidence: Medium  
FP Notes: Cleanup scripts  
Splunk ES: Threshold

### 128. Sliver C2 Named Pipe Indicators
```spl
index=endpoint sourcetype=Sysmon EventCode=17
| search PipeName="*sliver*"
```
MITRE: T1071  
Severity: Critical | Confidence: High  
FP Notes: None expected  
Splunk ES: IOC Match

### 129. Brute Ratel Badger Indicators
```spl
index=endpoint sourcetype=Sysmon
| search CommandLine="*badger*"
```
MITRE: T1059  
Severity: Critical | Confidence: Medium  
FP Notes: Dev tool names  
Splunk ES: IOC Match

### 130. Mythic Framework Payloads
```spl
index=endpoint sourcetype=Sysmon
| search CommandLine="*mythic*"
```
MITRE: T1071  
Severity: High | Confidence: Medium  
FP Notes: Testing labs  
Splunk ES: IOC Match

### 131. C2 via Cloudflare Tunnel
```spl
index=network
| search dest_domain="*.trycloudflare.com"
```
MITRE: T1090  
Severity: High | Confidence: Medium  
FP Notes: Legit tunnels  
Splunk ES: Anomaly Detection

### 132. Ngrok Abuse Detection
```spl
index=network
| search dest_domain="*.ngrok.io"
```
MITRE: T1090  
Severity: High | Confidence: Medium  
FP Notes: Dev usage  
Splunk ES: Anomaly Detection

### 133. Rclone Data Exfiltration
```spl
index=endpoint sourcetype=Sysmon
| search Image="*rclone*"
```
MITRE: T1567.002  
Severity: High | Confidence: High  
FP Notes: Backup admins  
Splunk ES: Correlation

### 134. Mega.nz Exfiltration Tooling
```spl
index=network
| search dest_domain="*mega.nz*"
```
MITRE: T1567.002  
Severity: High | Confidence: High  
FP Notes: Legit storage  
Splunk ES: Threshold

### 135. WinSCP Automated Transfers
```spl
index=endpoint sourcetype=Sysmon
| search Image="*winscp*" CommandLine="*/script*"
```
MITRE: T1048  
Severity: Medium | Confidence: Medium  
FP Notes: Admin scripts  
Splunk ES: Behavioral

### 136. PsExec Deployment at Scale
```spl
index=endpoint sourcetype=WinEventLog:System EventCode=7045
| search ServiceName="PSEXESVC"
| stats count by Computer
```
MITRE: T1569.002  
Severity: High | Confidence: High  
FP Notes: IT pushes  
Splunk ES: Threshold

### 137. Domain Trust Enumeration
```spl
index=endpoint sourcetype=Sysmon
| search CommandLine="*nltest* /domain_trusts*"
```
MITRE: T1482  
Severity: High | Confidence: Medium  
FP Notes: Admin checks  
Splunk ES: Behavioral

### 138. AD Database Shadow Copy Creation
```spl
index=endpoint sourcetype=Sysmon
| search CommandLine="*ntdsutil*"
```
MITRE: T1003.003  
Severity: Critical | Confidence: High  
FP Notes: DC maintenance  
Splunk ES: Correlation

### 139. Mass Account Disablement
```spl
index=endpoint sourcetype=WinEventLog:Security EventCode=4725
| stats count by Computer
| where count > 50
```
MITRE: T1531  
Severity: High | Confidence: Medium  
FP Notes: HR actions  
Splunk ES: Threshold

### 140. Destructive GPO Changes
```spl
index=endpoint sourcetype=WinEventLog:Security EventCode=5136
| search AttributeValue="*Disable*"
```
MITRE: T1484.001  
Severity: Critical | Confidence: Medium  
FP Notes: Planned policy changes  
Splunk ES: Policy

### 141. Boot Configuration Tampering
```spl
index=endpoint sourcetype=Sysmon
| search CommandLine="*bcdedit*"
```
MITRE: T1542.003  
Severity: High | Confidence: Medium  
FP Notes: Recovery ops  
Splunk ES: Correlation

### 142. Wiper Malware Indicators
```spl
index=endpoint sourcetype=Sysmon
| search CommandLine="*diskpart* clean*"
```
MITRE: T1485  
Severity: Critical | Confidence: High  
FP Notes: Disk provisioning  
Splunk ES: Behavioral

### 143. Unauthorized Hypervisor Shutdown
```spl
index=endpoint sourcetype=WinEventLog:System EventCode=6006
```
MITRE: T1529  
Severity: High | Confidence: Medium  
FP Notes: Maintenance windows  
Splunk ES: Correlation

### 144. ESXi Ransomware Execution
```spl
index=endpoint
| search Image="*/vmfs/volumes/*"
```
MITRE: T1486  
Severity: Critical | Confidence: High  
FP Notes: Admin scripts  
Splunk ES: Correlation

### 145. Mass VM Snapshot Deletion
```spl
index=endpoint
| search Message="*DeleteSnapshot*"
```
MITRE: T1490  
Severity: High | Confidence: Medium  
FP Notes: Storage cleanup  
Splunk ES: Threshold

### 146. Insider Bulk Email Downloads
```spl
index=o365
| stats count by user
| where count > 500
```
MITRE: T1114.002  
Severity: Medium | Confidence: Low  
FP Notes: PST exports  
Splunk ES: Behavioral

### 147. Insider Access to Legal Holds
```spl
index=o365
| search Operation="SearchQueryInitiated"
```
MITRE: T1213  
Severity: High | Confidence: Medium  
FP Notes: eDiscovery  
Splunk ES: Policy

### 148. Cloud Resource Destruction
```spl
index=cloud
| search eventName="DeleteBucket" OR eventName="DeleteVM"
```
MITRE: T1485  
Severity: Critical | Confidence: High  
FP Notes: Decommissioning  
Splunk ES: Correlation

### 149. Billing Tampering / Crypto Mining
```spl
index=cloud
| search eventName="CreateInstance" instanceType="*gpu*"
```
MITRE: T1496  
Severity: High | Confidence: Medium  
FP Notes: ML workloads  
Splunk ES: Behavioral

### 150. Kill Switch / Self-Delete Execution
```spl
index=endpoint sourcetype=Sysmon
| search CommandLine="*selfdelete*" OR CommandLine="*kill-switch*"
```
MITRE: T1107  
Severity: High | Confidence: Medium  
FP Notes: Updaters  
Splunk ES: Behavioral

