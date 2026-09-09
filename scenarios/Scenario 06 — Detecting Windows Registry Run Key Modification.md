
## 1. Objective

The objective of this scenario was to detect modification of a Windows Registry **Run key**, which can be used to establish persistence on a Windows system.

Registry Run keys are commonly monitored by SOC analysts because programs configured in these locations can automatically execute when a user logs in.

This scenario used Sysmon Event ID 13 telemetry and a custom Wazuh detection rule to identify registry modifications under the Windows Run key.

---

## 2. MITRE ATT&CK Mapping

|Technique|ID|
|---|---|
|Registry Run Keys / Startup Folder|T1547.001|

---

## 3. Detection Strategy

The Windows endpoint generates Sysmon Event ID 13 events when configured registry values are modified.

The Wazuh agent collects the Sysmon Operational event logs and forwards them to the Wazuh Manager.

A custom Wazuh rule was created to detect registry modifications where the `TargetObject` contains:

```
\Software\Microsoft\Windows\CurrentVersion\Run\
```

The custom detection rule uses Rule ID `100102`.

---

## 4. Custom Detection Rule

The following rule was configured in:

```
/var/ossec/etc/rules/local_rules.xml
```

```
<rule id="100102" level="10">
  <if_group>sysmon_event_13</if_group>

  <field name="win.eventdata.targetObject" type="pcre2">(?i)\\software\\microsoft\\windows\\currentversion\\run\\</field>

  <description>SOC Lab: Registry Run key modified</description>

  <group>sysmon,registry,persistence,</group>

  <mitre>
    <id>T1547.001</id>
  </mitre>
</rule>
```

---

## 5. Detection Logic

The detection rule checks the following conditions:

1. The event belongs to the Sysmon Event ID 13 detection group.
2. The event contains a registry modification.
3. The `TargetObject` contains the Windows Registry Run key path.
4. If the conditions match, Wazuh identifies the event using Rule ID `100102`.
5. The rule is configured with Alert Level `10`.

The targeted registry location is:

```
Software\Microsoft\Windows\CurrentVersion\Run
```

---

## 6. Attack Simulation

A controlled Registry Run key modification was performed on the Windows endpoint using PowerShell.

The following command was executed:

```
New-ItemProperty `
-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
-Name "FINALRunTest" `
-Value "C:\Windows\System32\notepad.exe" `
-PropertyType String `
-Force
```

This created a registry value named:

```
FINALRunTest
```

under:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

The configured value was:

```
C:\Windows\System32\notepad.exe
```

This was used as a controlled simulation to generate registry persistence-related telemetry.

---

## 7. Telemetry Generated

The PowerShell command successfully generated a Sysmon Event ID 13 event.

Important telemetry fields included:

- `Event ID`
- `RuleName`
- `EventType`
- `Image`
- `TargetObject`
- `Details`
- `User`

The event contained the following important information:

```
Event ID: 13

Image:
C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe

TargetObject:
HKU\...\Software\Microsoft\Windows\CurrentVersion\Run\FINALRunTest

Details:
C:\Windows\System32\notepad.exe

User:
BEMYGUEST\Mandar
```

This confirmed that Sysmon successfully recorded the Registry Run key modification.

---

## 8. Wazuh Telemetry Collection

The event was successfully received by the Wazuh Manager.

The event was verified in:

```
/var/ossec/logs/archives/archives.json
```

The following command was used:

```
sudo grep -a "FINALRunTest" /var/ossec/logs/archives/archives.json | tail -5
```

The archived event confirmed:

- Windows Sysmon generated Event ID 13.
- The Wazuh agent collected the event.
- The event was forwarded to the Wazuh Manager.
- Wazuh successfully decoded the Windows event fields.

This confirmed that the telemetry pipeline was functioning correctly:

```
Windows Endpoint
        ↓
      Sysmon
        ↓
   Wazuh Agent
        ↓
   Wazuh Manager
        ↓
 archives.json
```

---

## 9. Custom Rule Validation

The custom rule was tested using:

```
sudo /var/ossec/bin/wazuh-logtest
```

A sample Sysmon Event ID 13 containing the Registry Run key modification was provided to the Wazuh Logtest utility.

The result showed:

```
Phase 1: Completed pre-decoding.

Phase 2: Completed decoding.

Phase 3: Completed filtering (rules).

id: '100102'
level: '10'
description: 'SOC Lab: Registry Run key modified'

Alert to be generated.
```

This confirmed that:

- The event was decoded correctly.
- The required fields were available.
- Rule `100102` matched successfully.
- The detection logic was valid.
- Wazuh Logtest determined that an alert should be generated.

---

## 10. Live Alert Verification

The live alert was monitored using:

```
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep --line-buffered '"id":"100102"'
```

Historical alerts were also checked using:

```
sudo grep -a '"id":"100102"' /var/ossec/logs/alerts/alerts.json | tail -5
```

The Windows event containing `FINALRunTest` was successfully found in:

```
archives.json
```

However, the custom Rule ID `100102` alert was not found in:

```
alerts.json
```

The only result containing `FINALRunTest` in `alerts.json` was related to the Ubuntu `sudo grep` command used during investigation, not the Windows Registry event itself.

---

## 11. Investigation Result

The investigation confirmed the following:

|Component|Result|
|---|---|
|Registry modification|Successful|
|Sysmon Event ID 13 generation|Successful|
|Wazuh agent collection|Successful|
|Event arrival at Wazuh Manager|Successful|
|Event stored in `archives.json`|Successful|
|Event decoding|Successful|
|Custom Rule `100102` validation|Successful|
|Wazuh Logtest rule match|Successful|
|Live Rule `100102` alert in `alerts.json`|Not observed|

The investigation therefore isolated the remaining issue to the **live alert generation or storage pipeline**, rather than the Sysmon configuration, telemetry collection, event decoding, or custom rule logic.

---

## 12. Detection Flow

The complete detection flow for this scenario was:

1. A Registry Run key modification was performed on the Windows endpoint.
2. Sysmon generated Event ID 13.
3. The event recorded the PowerShell process responsible for the modification.
4. The Wazuh agent collected the Sysmon event.
5. The event was forwarded to the Wazuh Manager.
6. Wazuh stored the received event in `archives.json`.
7. The event fields were successfully decoded.
8. Custom Rule `100102` was tested using `wazuh-logtest`.
9. The rule successfully matched the Registry Run key path.
10. Wazuh Logtest indicated that an alert should be generated.
11. The corresponding live custom alert was not observed in `alerts.json`.

---

## 13. Screenshots

The following screenshots should be included for this scenario.

### Screenshot 1 — PowerShell Registry Run Key Simulation

![PowerShell Registry Run Key Simulation](s6_01.png)

---

### Screenshot 2 — Sysmon Event ID 13

![Sysmon Event ID 13](s6_02.png)

---

### Screenshot 3 — Wazuh Archived Event

![Wazuh Archived Event](s6_03.png)

---

### Screenshot 4 — Wazuh Logtest Rule Validation

![Wazuh Logtest Rule Validation](s6_04.png)

---

### Screenshot 5 — Custom Rule Configuration

Show Rule `100102` inside:

```
/var/ossec/etc/rules/local_rules.xml
```

---

## 14. Conclusion

This scenario successfully demonstrated the collection and detection validation of a Windows Registry Run key modification.

A controlled Registry Run key modification was performed using PowerShell, which generated a Sysmon Event ID 13 event. The Wazuh agent successfully collected the event and forwarded it to the Wazuh Manager, where the event was confirmed in `archives.json`.

The custom Wazuh Rule `100102` was validated using `wazuh-logtest`. The rule successfully matched the Registry Run key modification and produced the result:

```
Alert to be generated.
```

During live testing, however, the expected Rule ID `100102` alert was not observed in `alerts.json`.

Therefore, the scenario successfully validated the following components:

- Registry persistence telemetry generation
- Sysmon Event ID 13 monitoring
- Wazuh agent event collection
- Wazuh Manager event reception
- Event decoding
- Custom rule detection logic

The remaining issue was isolated to the **live alert generation or alert storage pipeline**.

**Overall result: Detection logic successfully validated, with live alert output requiring further investigation.**