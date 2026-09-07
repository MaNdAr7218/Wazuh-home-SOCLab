````
# Phase 3: Custom Detection Engineering & Verification

## 1. Custom Detection Architecture
Detection engineering in Wazuh follows a structured pipeline. Once telemetry (such as Sysmon or Windows Event Logs) arrives at the Wazuh Manager, it is parsed by a **Decoder**. The decoded fields are then evaluated against a hierarchy of **Rules**. If an event matches a rule's criteria and exceeds the minimum alerting threshold, an alert is written to `alerts.json` and visualised on the dashboard.

```text
  [Raw Ingested Log] ──► [Wazuh Decoder] ──► [XML Fields Parsed] ──► [Rules Engine] ──► [Alert Generated]
````

To monitor high-risk administrative tool abuse and credential manipulation, custom rules were developed and added directly to the manager's local ruleset file:

- **Path on Wazuh Manager:** `/var/ossec/etc/rules/local_rules.xml`

---

2. Custom Wazuh Ruleset Configuration

Below are the custom detection rules written and deployed during this lab to identify suspicious PowerShell execution and local staging.

```
<group name="windows, sysmon, security_event,">

  <!-- Rule 100100: Suspicious PowerShell Encoded Command -->
  <rule id="100100" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image">powershell.exe</field>
    <field name="win.eventdata.commandLine">-EncodedCommand|-enc</field>
    <description>SOC Lab: Suspicious PowerShell Encoded Command Executed on Monitored Endpoint</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

  <!-- Rule 100101: PowerShell Network Download Activity -->
  <rule id="100101" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image">powershell.exe</field>
    <field name="win.eventdata.commandLine">Invoke-WebRequest|iwr|Net.WebClient</field>
    <description>SOC Lab: PowerShell used to download content from the internet</description>
    <mitre>
      <id>T1105</id>
    </mitre>
  </rule>

  <!-- Rule 100003: Script Creation in Temp Directory -->
  <rule id="100003" level="8">
    <if_group>sysmon_event_11</if_group>
    <field name="win.eventdata.targetFilename">\\.ps1$|\\.bat$|\\.vbs$</field>
    <field name="win.eventdata.targetFilename">\\AppData\\Local\\Temp\\</field>
    <description>SOC Lab: Script file (.ps1, .bat, .vbs) created in User Temp Directory</description>
    <mitre>
      <id>T1059</id>
    </mitre>
  </rule>

  <!-- Rule 100002: Controlled Test File Detection -->
  <rule id="100002" level="5">
    <if_group>sysmon_event_11</if_group>
    <field name="win.eventdata.targetFilename">SOC-Test-Download</field>
    <description>SOC Lab: Controlled lab test file detected in file system</description>
  </rule>

</group>
```

---

3. Custom Rule Validation (`wazuh-logtest`)

Before reloading the Wazuh Manager, the custom ruleset was validated using the manager's built-in **wazuh-logtest** utility to confirm that the XML patterns match incoming raw events.

Test 1: Validation of PowerShell Download Activity (Rule `100101`)

A simulated download log was passed to the testing utility:

- **Logtest Command:**

```
sudo /var/ossec/bin/wazuh-logtest
```

- **Raw Input Passed:**

```
{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1"},"eventdata":{"image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","commandLine":"Invoke-WebRequest -Uri 'https://example.com' -OutFile 'C:\\Users\\Administrator\\AppData\\Local\\Temp\\SOC-Test-Download.html'"}}}
```

Validation Output Result

```
**Phase 1: Completed. Completed parsing.
**Phase 2: Completed. Folder: /var/ossec/rules
**Phase 3: Completed. Output:
   id: '100101'
   level: '10'
   description: 'SOC Lab: PowerShell used to download content from the internet'
   groups: '['windows', 'sysmon', 'security_event']'
   parts: 'T1105'
**Alert to be generated.
```

- **Analysis:** The rules engine successfully mapped the test string to **Rule** **100101** **(Level 10)** and linked it to **MITRE ATT&CK T1105 (Ingress Tool Transfer)**.

---

4. Engineering Highlight: Live Alert Ingestion Discrepancy

During the live execution of simulated attacks, a discrepancy was noted:

- The raw PowerShell download event successfully registered inside `/var/ossec/logs/archives/archives.json`.
- The logic was confirmed as 100% correct inside `wazuh-logtest`.
- **Issue:** The live alert failed to write to `alerts.json`, preventing it from rendering on the Kibana-based Wazuh Dashboard.

Engineering Root-Cause Hypothesis & Lessons Learned

Rather than falsely claiming success, documenting this behavior highlights a realistic detection engineering challenge:

1. **Sysmon Schema Mismatch:** Minor variations between the local agent's parsed XML output fields and the fields expected by the JSON parser on the manager can cause the manager to silently drop the event before rule matching.
2. **Resource Constraints:** Under low-resource states, high-volume telemetry events (like Sysmon Process Creation) are sometimes buffered or dropped to preserve the stability of the indexer service.

---

5. Out-of-the-Box Windows Security Event Detections

Beyond custom Sysmon monitoring, Wazuh's default Windows ruleset was leveraged to detect administrative credential modifications and brute-force attempts.

Threat Scenario A: Local User Account Creation (MITRE T1098)

A local user account named `SOC-TestUser` was created via administrative PowerShell on the Windows 11 endpoint to simulate persistent access.

- **Triggered Event ID:** Windows Security Event `4720` (A user account was created).
- **Resulting Wazuh Alert:**
    - **Rule ID:** `60109`
    - **Rule Level:** Level 8
    - **Description:** "User account enabled or created"
    - **Mapped Tactic:** Persistence / Account Manipulation (T1098)

```
{
  "win": {
    "system": {
      "providerName": "Microsoft-Windows-Security-Auditing",
      "eventID": "4720"
    },
    "eventdata": {
      "targetUserName": "SOC-TestUser",
      "subjectUserName": "manda"
    }
  }
}
```

Threat Scenario B: Local Privilege Escalation (Event `4732`)

To escalate privileges, the new user was added to the local Administrators group.

- **Triggered Event ID:** Windows Security Event `4732` (A member was added to a security-enabled local group).
- **Detection Significance:** High-priority indicators of lateral movement and administrative compromise.