
## 1. Objective

The objective of this scenario was to detect PowerShell being used to download content from the internet.

Attackers and malicious scripts commonly use PowerShell download functionality to retrieve additional payloads, tools, or scripts. Detecting this activity provides visibility into potential ingress tool transfer and suspicious endpoint behavior.

---

## 2. MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| Ingress Tool Transfer | T1105 |

---

## 3. Detection Strategy

The Windows endpoint generates Sysmon Event ID 1 telemetry when a process is created.

When PowerShell executes a command containing download-related functionality such as `Invoke-WebRequest` or `iwr`, the command-line information is recorded by Sysmon.

The Wazuh agent collects the Sysmon event and forwards it to the Wazuh Manager.

A custom Wazuh rule analyzes the PowerShell command line and generates an alert when suspicious download activity is detected.

---

## 4. Custom Detection Rule

The following custom rule was configured in:

```text
/var/ossec/etc/rules/local_rules.xml
````

```
<rule id="100101" level="10">
  <if_sid>92027</if_sid>

  <field name="win.eventdata.commandLine" type="pcre2">(?i)(invoke-webrequest|\biwr\b)</field>

  <description>SOC Lab: PowerShell used to download content from the internet</description>

  <mitre>
    <id>T1105</id>
  </mitre>

  <group>powershell,download,suspicious_activity,</group>
</rule>
```

---

## 5. Detection Logic

The rule performs the following detection process:

1. The event first matches the parent PowerShell detection rule `92027`.
2. Wazuh examines the `CommandLine` field.
3. The rule searches for:
    - `Invoke-WebRequest`
    - `iwr`
4. If a match is found, Custom Rule `100101` generates an alert.

---

## 6. Attack Simulation

The following controlled PowerShell command was executed on the Windows endpoint:

```
powershell.exe -c "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml' -OutFile 'C:\SOC-Lab\temp_download.xml'"
```

The command downloaded a publicly available Sysmon configuration XML file to the local SOC Lab directory.

The downloaded file was saved as:

```
C:\SOC-Lab\temp_download.xml
```

---

## 7. Telemetry Generated

The activity generated a Sysmon Event ID 1 process creation event.

Important telemetry included:

- `Image`
- `CommandLine`
- `ParentImage`
- `User`

The most important field for this detection was:

```
data.win.eventdata.commandLine
```

This field contained the `Invoke-WebRequest` command used during the simulation.

---

## 8. Wazuh Detection

The custom Wazuh Rule `100101` successfully detected the PowerShell download activity.

|Field|Value|
|---|---|
|Rule ID|100101|
|Alert Level|10|
|Description|SOC Lab: PowerShell used to download content from the internet|
|MITRE ATT&CK|T1105|
|Telemetry Source|Sysmon Event ID 1|

---

## 9. Alert Verification

The alert was monitored on the Wazuh Manager using:

```
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep --line-buffered '"id":"100101"'
```

The PowerShell download simulation successfully triggered Custom Rule `100101`.

This confirmed the following telemetry pipeline:

```
PowerShell Execution
        ↓
Sysmon Event ID 1
        ↓
Wazuh Agent
        ↓
Wazuh Manager
        ↓
Custom Rule 100101
        ↓
Security Alert
```

---

## 10. Detection Flow

The complete detection flow for this scenario was:

1. PowerShell was used to execute `Invoke-WebRequest`.
2. The command downloaded a file from the internet.
3. Sysmon generated Event ID 1 for the PowerShell process.
4. The Wazuh agent collected the Sysmon event.
5. The event was forwarded to the Wazuh Manager.
6. The event matched the PowerShell detection rule.
7. The custom Rule `100101` detected the download command.
8. Wazuh generated a Level 10 security alert.

---

## 11. Screenshots

### Screenshot 1 — PowerShell Download Simulation and Downloaded File Verification
![[s3_01.png]]


### Screenshot 2 — Wazuh Alert
![[s3_02.png]]
### Screenshot 3 — Alert Details
![[s3_03.png]]
---

## 12. Conclusion

This scenario successfully demonstrated the detection of PowerShell-based download activity.

The controlled simulation generated Sysmon process creation telemetry containing the PowerShell download command. The Wazuh agent forwarded this telemetry to the Wazuh Manager, where Custom Rule `100101` detected the use of `Invoke-WebRequest`.

This scenario demonstrates how SOC detection rules can provide visibility into potentially suspicious download activity and help analysts investigate possible payload delivery or ingress tool transfer attempts.