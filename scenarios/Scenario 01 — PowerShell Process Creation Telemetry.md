````

## 1. Objective

The objective of this scenario was to verify that the SOC lab could successfully collect and detect PowerShell process execution from the Windows 11 endpoint.

PowerShell is widely used for legitimate system administration. However, it is also frequently abused by attackers to execute commands, scripts, and malicious payloads. Monitoring PowerShell process creation is therefore an important capability for a Security Operations Center (SOC).

---

## 2. Threat Background

PowerShell is a legitimate Windows command-line and scripting utility that can be used to automate administrative tasks.

Attackers may abuse PowerShell to:

- Execute malicious commands
- Run scripts
- Download payloads
- Execute encoded commands
- Perform post-exploitation activities

Monitoring process creation provides analysts with important forensic information about what was executed on an endpoint.

---

## 3. MITRE ATT&CK Mapping

| Field              | Value                                         |
|--------------------|-----------------------------------------------|
| Tactic             | Execution                                     |
| Technique          | Command and Scripting Interpreter: PowerShell |
| MITRE Technique ID | T1059.001                                     |

---

## 4. Detection Logic

This scenario relies on **Sysmon Event ID 1**, which records process creation activity.

The Windows endpoint generates the Sysmon event when a new process is created. The Wazuh Agent collects the event from the Windows Event Channel and forwards it to the Wazuh Manager for analysis.

In this lab, the PowerShell activity matched the following Wazuh rule:

| Field            | Value                                          |
|------------------|------------------------------------------------|
| Rule ID          | 92027                                          |
| Rule Description | Powershell process spawned powershell instance |
| Alert Level      | 4                                              |
| MITRE Technique  | T1059.001                                      |

The rule information was verified directly from the generated Wazuh alert.

---

## 5. Attack Simulation

The following PowerShell command was executed on the monitored Windows 11 endpoint:

```powershell
powershell.exe -c "Write-Host 'WAZUH SYSMON TEST'"
````

The command successfully executed and produced the following output:

```
WAZUH SYSMON TEST
```

This activity generated a Sysmon process creation event.

---

## 6. Telemetry and Alert Flow

The following flow was successfully verified during the scenario:

```
PowerShell Execution
        ↓
Sysmon Event ID 1 — Process Creation
        ↓
Windows Event Channel
        ↓
Wazuh Agent
        ↓
Wazuh Manager
        ↓
Wazuh Rule Analysis
        ↓
Rule 92027 Matched
        ↓
Alert Generated
        ↓
alerts.json
        ↓
Wazuh Dashboard
```

This confirms that the SOC lab can collect endpoint telemetry and generate a centralized security alert.

---

## 7. Detection Results

The simulated PowerShell activity successfully generated an alert in:

```
/var/ossec/logs/alerts/alerts.json
```

The alert was generated from the monitored Windows endpoint and contained the following information:

|Field|Value|
|---|---|
|Event Source|Microsoft-Windows-Sysmon|
|Sysmon Event ID|1|
|Event Type|Process Creation|
|Wazuh Rule ID|92027|
|Alert Description|Powershell process spawned powershell instance|
|MITRE ATT&CK|T1059.001|

The event confirmed that Wazuh successfully received and analyzed the PowerShell process telemetry.

---

## 8. Key Forensic Evidence

The generated alert contained several important forensic fields.

### Command Line

The command line showed the exact PowerShell command that was executed:

```
powershell.exe -c "Write-Host 'WAZUH SYSMON TEST'"
```

This allows a SOC analyst to understand exactly what activity occurred.

### Image

The image field identified the executable responsible for the activity:

```
powershell.exe
```

### Parent Image

The parent image identified the process responsible for launching the PowerShell process.

In this test, PowerShell was launched from another PowerShell process.

### User

The event also contained the user context associated with the process execution.

This information is important for attributing suspicious activity to a user account during an investigation.

---

## 9. SOC Analyst Interpretation

The alert confirms that PowerShell process activity occurred on the monitored Windows endpoint.

In this scenario, the executed command was benign and was intentionally used to test the telemetry pipeline.

However, the same monitoring capability could help detect and investigate suspicious PowerShell activity such as:

- Encoded PowerShell commands
- Downloading files from the internet
- Execution of malicious scripts
- Suspicious parent-child process relationships
- Commands executed with elevated privileges

The key benefit of Sysmon Event ID 1 is that it provides detailed process execution telemetry that can be centrally analyzed by the SOC.

---

## 10. Evidence Collected

The following evidence was collected during this scenario:

1. Successful PowerShell command execution on the Windows endpoint
2. Sysmon Event ID 1 process creation telemetry
3. Wazuh alert generated by Rule ID 92027
4. Alert recorded in `alerts.json`
5. Event visibility in the Wazuh monitoring environment

---

## 11. Screenshots

The following screenshots should be included for this scenario:

### Screenshot 1 — PowerShell Simulation

![[s1_03.png]]
### Screenshot 2 — Wazuh Alert

![[s1_01.png]]
### Screenshot 3 — Alert Details

![[s1_02.png]]


```

---

## 12. Conclusion

This scenario successfully demonstrated end-to-end PowerShell process monitoring in the SOC lab.

The Windows endpoint generated a Sysmon Event ID 1 process creation event after executing a PowerShell command. The Wazuh Agent collected the event, the Wazuh Manager analyzed it, and Wazuh Rule ID 92027 generated a security alert.

This confirmed that the lab is capable of collecting Windows endpoint telemetry and detecting PowerShell execution activity.

The next scenario focuses on detecting suspicious PowerShell commands that use encoded command arguments.