
## 1. Objective

The objective of this scenario was to detect the execution of a PowerShell command using the `-EncodedCommand` parameter.

PowerShell encoded commands are commonly used to obfuscate command content. Monitoring encoded PowerShell execution helps SOC analysts identify potentially suspicious activity that may require further investigation.

---

## 2. MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| Command and Scripting Interpreter: PowerShell | T1059.001 |

---

## 3. Detection Strategy

The Windows endpoint generates Sysmon Event ID 1 events for process creation.

The Wazuh agent collects the Sysmon Operational event logs and forwards them to the Wazuh Manager.

A custom Wazuh rule detects PowerShell process creation events where the command line contains either:

- `-EncodedCommand`
- `-enc`

The custom detection rule uses Rule ID `100100`.

---

## 4. Custom Detection Rule

The following rule was configured in:

```text
/var/ossec/etc/rules/local_rules.xml
````

```
<rule id="100100" level="12">
  <if_group>sysmon_eid1_detections</if_group>

  <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe$</field>

  <field name="win.eventdata.commandLine" type="pcre2">(?i)(-encodedcommand|-enc)\s+</field>

  <description>SOC Lab: PowerShell executed an encoded command</description>

  <group>sysmon,powershell,</group>

  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>
```

---

## 5. Detection Logic

The detection rule checks the following conditions:

1. The event belongs to the Sysmon Event ID 1 detection group.
2. The process image is `powershell.exe`.
3. The PowerShell command line contains either `-EncodedCommand` or `-enc`.
4. If the conditions match, Wazuh generates an alert using Rule ID `100100`.

---

## 6. Attack Simulation

The following PowerShell command was executed on the Windows endpoint:

```
powershell.exe -EncodedCommand dwBoAG8AYQBtAGkA
```

The encoded payload represents:

```
whoami
```

The command was used as a controlled simulation to test whether the Wazuh detection rule could identify encoded PowerShell execution.

---

## 7. Telemetry Generated

The execution generated a Sysmon Event ID 1 event.

Important telemetry fields included:

- `Image`
- `CommandLine`
- `ParentImage`
- `User`

The `CommandLine` field contained the PowerShell encoded command and was used by the Wazuh custom rule for detection.

---

## 8. Wazuh Detection

After the custom rule was loaded and the Wazuh Manager was restarted, the encoded PowerShell command triggered the custom detection rule.

Expected alert details:

|Field|Value|
|---|---|
|Rule ID|100100|
|Alert Level|12|
|Description|SOC Lab: PowerShell executed an encoded command|
|MITRE Technique|T1059.001|
|Data Source|Sysmon Event ID 1|

---

## 9. Alert Verification

The alert was verified from the Wazuh Manager using:

```
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep --line-buffered '"id":"100100"'
```

The detection confirmed that the Wazuh Manager successfully processed the Sysmon process creation telemetry and matched it against the custom detection rule.

---

## 10. Detection Flow

The complete detection flow for this scenario was:

1. A PowerShell encoded command was executed on the Windows endpoint.
2. Sysmon generated Event ID 1 for process creation.
3. The Wazuh agent collected the Sysmon event.
4. The event was forwarded to the Wazuh Manager.
5. Wazuh analyzed the `CommandLine` field.
6. Custom Rule `100100` detected the encoded PowerShell parameter.
7. A Level 12 alert was generated.
8. The alert was available for investigation in the Wazuh monitoring environment.

---

## 11. Screenshots

The following screenshots should be included for this scenario.

### Screenshot 1 — PowerShell Encoded Command Simulation
![[s2_01.png]]
### Screenshot 2 — Wazuh Alert
![[s2_02.png]]
### Screenshot 3 — Alert Details
![[s2_03.png]]
---

## 12. Conclusion

This scenario successfully demonstrated the detection of PowerShell commands executed using encoded command-line arguments.

The Windows endpoint generated Sysmon process creation telemetry, which was collected by the Wazuh agent and forwarded to the Wazuh Manager. The custom Rule ID `100100` identified the suspicious PowerShell parameters and generated a Level 12 security alert.

This scenario demonstrates how custom detection rules can be used to identify potentially suspicious command execution techniques and improve visibility into endpoint activity.