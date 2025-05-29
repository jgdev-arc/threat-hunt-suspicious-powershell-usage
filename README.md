<img src="https://github.com/user-attachments/assets/4ac17d08-85c4-4fbb-98fc-4444167f60c6" width="400"/>

# Threat Hunt Report: Suspicious PowerShell Usage (T1059.001)
This threat hunt investigates the use of suspicious or obfuscated PowerShell commands on a Windows endpoint to simulate attacker behavior, such as executing Base64-encoded commands or remote download cradles, for credential theft, malware staging, or persistence.

## Platforms and Tools Used
- **Microsoft Azure** (Virtual Machine)
- **Microsoft Defender for Endpoint** (EDR telemetry)
- **Kusto Query Language (KQL)**
- **PowerShell** (Simulation of malicious commands)
- *(Optional)* **Sysinternals** or **Atomic Red Team** tools if used

---

## Scenario Overview

This scenario simulates attacker behavior involving the use of encoded PowerShell commands. Such techniques are often used to bypass basic detection mechanisms, hide intent, or perform system reconnaissance without being immediately flagged by security tools. The goal of this hunt is to identify obfuscated PowerShell activity, verify visibility within Microsoft Defender for Endpoint, and evaluate if such actions are being logged or blocked.

---

## 🔍 IoC-Based Threat Hunting Plan

- **Encoded or Obfuscated PowerShell Commands**
  - Look for `-EncodedCommand`, `IEX`, `FromBase64String`, `New-Object Net.WebClient`, etc.
- **Remote Download Cradles**
  - Detect URLs in command lines or scripts pointing to external hosts.
- **Process Ancestry**
  - Identify if PowerShell is launched from suspicious parent processes.
- **Unusual User Context or Paths**
  - Commands run from temp folders, odd hours, or as SYSTEM may be indicators of compromise.

---

## 🔍 Investigation Steps

### 🧪 PowerShell Encoded Command Execution Observed

A recurring pattern of PowerShell executions was detected on **vm-test-zedd** under the **SYSTEM** account, leveraging Base64-encoded commands. These commands were executed using the `-EncodedCommand` flag—commonly used to obfuscate intent in script-based attacks.

The encoded payload used in each instance was:
```
[Environment]::OSVersion.Version
```
This command, while benign, is commonly used by malware and scripts for environment reconnaissance.

#### Example Execution Details:
- **Device:** vm-test-zedd  
- **Account:** SYSTEM  
- **Command Line:**  
  `"powershell.exe" -noninteractive -outputFormat xml -NonInteractive -encodedCommand IABbAEUAbgB2AGkAcgBvAG4AbQBlAG4AdABdADoAOgBPAFMAVgBlAHIAcwBpAG8AbgAuAFYAZQByAHMAaQBvAG4AIAA=`
- **Timestamps:** Multiple from May 27–29, 2025

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "vm-test-zedd"
| where ProcessCommandLine has "encodedCommand"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```
![intro](https://github.com/user-attachments/assets/00a91f9c-8d6c-4f33-9fb4-c4a276d23399)

---

### 🧾 Script Block Logging – No Results Found

A check for corresponding script block logging events to capture decoded script content revealed no results. This may indicate that:
- **Script Block Logging is disabled**, or
- The script was blocked before execution was fully logged.

**KQL Query Used:**
```kql
DeviceEvents
| where DeviceName == "vm-test-zedd"
| where ActionType == "ScriptBlockLogged"
| order by Timestamp desc
```
![noresults](https://github.com/user-attachments/assets/8bdedbc3-33a4-4952-b68b-51c5257e0343)

---

### 🚨 Defender Alerts – No Detection Triggered

Despite repeated encoded PowerShell executions, **no alerts were triggered** in Microsoft Defender for Endpoint. This suggests the command's behavior was not classified as malicious by Defender's threat intelligence, or the activity was considered low risk.

**KQL Query Used:**
```kql
AlertEvidence
| where DeviceName == "vm-test-zedd"
| where EntityType == "Process"
| where ProcessCommandLine has "encodedCommand"
| project Timestamp, DeviceName, AlertId, EntityType, EvidenceRole, FileName, ProcessCommandLine
| order by Timestamp desc
```
![noresults](https://github.com/user-attachments/assets/8bdedbc3-33a4-4952-b68b-51c5257e0343)

---

### 📁 File Creation Activity – None Detected

A review of file events revealed **no file creation or modification** as a result of the PowerShell executions. This implies the command may have been strictly informational or reconnaissance in nature.

**KQL Query Used:**
```kql
DeviceFileEvents
| where DeviceName == "vm-test-zedd"
| where InitiatingProcessCommandLine has "encodedCommand"
| order by Timestamp desc
```
![2](https://github.com/user-attachments/assets/a1257558-2057-40dc-8a25-99aead697567)

---

## 🕒 Chronological Timeline of Events – Encoded PowerShell Reconnaissance  
**Device:** `vm-test-zedd`  
**Date Range:** May 26–29, 2025  

| **Time**           | **Event**                  | **Details** |
|--------------------|----------------------------|-------------|
| *Multiple times*   | 🧪 Encoded PowerShell Runs  | `powershell.exe` executed with `-encodedCommand` flag. Command decodes to `[Environment]::OSVersion.Version`. Run under SYSTEM account. |
| *(none)*           | 🧾 Script Block Logging     | No corresponding script block logs found. Script block logging may be disabled or events were not captured. |
| *(none)*           | 🚨 Alerts                   | No Defender for Endpoint alerts were generated in response to the PowerShell executions. |
| *(none)*           | 📄 File Creation            | No files were created or modified as a result of these encoded PowerShell executions. |

---

## 🧾 Summary of Findings

Between **May 26 and May 29, 2025**, the virtual machine **vm-test-zedd** exhibited repeated execution of PowerShell commands using the `-encodedCommand` parameter. These were executed under the **SYSTEM** account, a potential indicator of unauthorized or automated system-level scripting.

- The encoded command decoded to `[Environment]::OSVersion.Version`, commonly used in reconnaissance.
- Despite multiple executions, no script block logs or alerts were triggered by Microsoft Defender for Endpoint.
- No artifacts such as file creation or memory manipulation were detected.
- Activity is consistent with adversary simulation or environment profiling, but not indicative of active compromise.

---

## ✅ Containment and Remediation

- **Reviewed activity scope**: No harmful behavior was detected beyond basic environment queries.
- **Verified no persistence or impact**: No indicators of persistence, lateral movement, or credential access were found.
- **Monitoring recommended**: Continued observation of the system for elevated use of encoded PowerShell or SYSTEM-level scripting is advised.
- **Consider enabling logging**: Enable Script Block Logging and PowerShell transcription logging for improved future detection and visibility into obfuscated script behavior.

No further containment or remediation steps required at this time.
