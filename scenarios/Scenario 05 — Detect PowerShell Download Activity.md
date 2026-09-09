## 1. Objective

The objective of this scenario was to detect PowerShell being used to download content from the internet using `Invoke-WebRequest`.

PowerShell download activity can be legitimate, but it is also commonly associated with suspicious activity such as downloading tools, scripts, or other payloads onto an endpoint. Monitoring this behavior helps SOC analysts identify activity that may require further investigation.

---

## 2. MITRE ATT&CK Mapping

|Technique ID|Technique|
|---|---|
|T1105|Ingress Tool Transfer|

---

## 3. Detection Strategy

The Windows endpoint generates Sysmon telemetry related to PowerShell activity.

The Wazuh agent collects the Sysmon Operational event logs and forwards them to the Wazuh Manager.

A custom Wazuh rule detects PowerShell activity where the command line contains either:

- `Invoke-WebRequest`
- `iwr`

The custom detection rule uses Rule ID `100101`.

---

## 4. Custom Detection Rule

The following rule was configured in:

```
/var/ossec/etc/rules/local_rules.xml
```

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

The detection rule checks the following conditions:

1. The event matches the parent Wazuh PowerShell detection rule with Rule ID `92027`.
2. The PowerShell command line is inspected.
3. The command line is checked for either:
    - `Invoke-WebRequest`
    - `iwr`
4. If the conditions match, Wazuh generates an alert using Rule ID `100101`.

---

## 6. Attack Simulation

A controlled PowerShell web request was executed on the Windows endpoint to generate download-related telemetry.

The activity involved PowerShell communicating with an external web resource using `Invoke-WebRequest`.

This was performed as a controlled SOC lab simulation to test whether the Wazuh custom detection rule could identify PowerShell-based download activity.

No malicious payload was required for this scenario.

---

## 7. Telemetry Generated

The PowerShell activity generated Sysmon telemetry from the Windows endpoint.

During verification, DNS-related telemetry was observed showing that `powershell.exe` performed a DNS query for the requested domain.

Important telemetry fields included:

- `Image`
- `CommandLine`
- `QueryName`
- `QueryResults`
- `User`

The telemetry confirmed that PowerShell initiated network-related activity associated with the controlled web request.

---

## 8. Wazuh Detection

After the custom rule was loaded and the Wazuh Manager was running, the PowerShell activity triggered the custom detection rule.

Expected alert details:

|Field|Value|
|---|---|
|Rule ID|100101|
|Alert Level|10|
|Description|SOC Lab: PowerShell used to download content from the internet|
|MITRE Technique|T1105|
|Detection Category|PowerShell / Download Activity|

---

## 9. Alert Verification

The alert was verified from the Wazuh Manager using:

```
sudo grep -a '"id":"100101"' /var/ossec/logs/alerts/alerts.json | tail -5
```

Additional telemetry was investigated using PowerShell and Sysmon event logs to confirm the related endpoint activity.

The investigation confirmed that the Windows endpoint generated telemetry associated with PowerShell network activity.

---

## 10. Detection Flow

The complete detection flow for this scenario was:

1. A controlled PowerShell web request was executed on the Windows endpoint.
2. PowerShell initiated communication with an external web resource.
3. Sysmon generated telemetry related to the endpoint activity.
4. The Wazuh agent collected the Sysmon event logs.
5. The events were forwarded to the Wazuh Manager.
6. Wazuh analyzed the PowerShell command-line activity.
7. Custom Rule `100101` detected the `Invoke-WebRequest` or `iwr` pattern.
8. A Level 10 alert was generated.
9. The alert was available for investigation in the Wazuh monitoring environment.

---

## 11. Screenshots

The following screenshots should be included for this scenario.

### Screenshot 1 — PowerShell Download Activity Simulation

![PowerShell Download Activity Simulation](s5_01.png)

### Screenshot 2 — Wazuh Alert

![Wazuh Alert](s5_02.png)

### Screenshot 3 — Alert Details

![Alert Detaild](s5_03.png)

---

## 12. Conclusion

This scenario successfully demonstrated the detection of PowerShell being used for download-related internet activity.

The Windows endpoint generated Sysmon telemetry, which was collected by the Wazuh agent and forwarded to the Wazuh Manager. The custom Rule ID `100101` was designed to identify PowerShell commands containing `Invoke-WebRequest` or `iwr` and generate a Level 10 security alert.

This scenario demonstrates how custom detection rules can be used to improve visibility into PowerShell-based network activity and identify behavior that may be associated with suspicious file or tool transfers.

