
## 1. Objective

Detect the creation of a Windows Scheduled Task on a monitored Windows endpoint.

The scenario simulates an attacker creating a scheduled task that could be used for **persistence** or repeated execution of a program.

---

## 2. MITRE ATT&CK Mapping

- **Technique:** T1053.005 — Scheduled Task/Job: Scheduled Task
- **Tactic:** Execution, Persistence, Privilege Escalation

---

## 3. Detection Strategy

The detection uses **Sysmon telemetry** from the Windows endpoint.

The original Event ID 1 approach detected `schtasks.exe`, but the live custom alert was not generated even though the event reached Wazuh.

Therefore, the final detection rule was changed to use **Sysmon Event ID 11**, which records creation of the scheduled-task file under:

```
C:\Windows\System32\Tasks\
```

This provides direct evidence that the scheduled task was created.

---

## 4. Custom Detection Rule

Custom Wazuh Rule:

```
<rule id="100103" level="10">
  <decoded_as>json</decoded_as>
  <field name="win.system.eventID">11</field>
  <field name="win.eventdata.targetFilename" type="pcre2">(?i)\\Windows\\System32\\Tasks\\</field>

  <description>SOC Lab: Windows Scheduled Task created</description>

  <group>sysmon,persistence,scheduled_task,</group>

  <mitre>
    <id>T1053.005</id>
  </mitre>
</rule>
```

**Rule ID:** `100103`  
**Severity:** Level 10

---

## 5. Detection Logic

The rule checks for:

1. JSON-decoded Windows event.
2. **Sysmon Event ID 11**.
3. A file created inside:

```
C:\Windows\System32\Tasks\
```

When all conditions are satisfied, Wazuh generates Rule `100103`.

---

## 6. Attack Simulation

The following command was executed on the Windows 11 endpoint:

```
schtasks.exe /create /tn "SOCLabScheduledTask" /tr "notepad.exe" /sc once /st 23:59 /f
```

Windows successfully created the scheduled task:

```
SUCCESS: The scheduled task "SOCLabScheduledTask" has successfully been created.
```

---

## 7. Telemetry Generated

The attack generated Sysmon telemetry that was successfully received by Wazuh.

### Sysmon Event ID 1

The process creation event showed:

```
Image:
C:\Windows\System32\schtasks.exe
```

Command line:

```
schtasks.exe /create /tn SOCLabScheduledTask /tr notepad.exe /sc once /st 23:59 /f
```

### Sysmon Event ID 11

A file creation event was generated for:

```
C:\Windows\System32\Tasks\SOCLabScheduledTask
```

The event was confirmed in Wazuh's `archives.json`.

---

## 8. Wazuh Detection

The custom rule was tested using `wazuh-logtest`.

The rule successfully matched:

```
id: '100103'
level: '10'
description: 'SOC Lab: Windows Scheduled Task created'
```

MITRE mapping:

```
T1053.005
Scheduled Task
```

Wazuh reported:

```
Alert to be generated.
```

---

## 9. Alert Verification

The real Windows event was successfully received and stored by Wazuh in:

```
/var/ossec/logs/archives/archives.json
```

The archived telemetry contained the scheduled-task creation event and the task file:

```
C:\Windows\System32\Tasks\SOCLabScheduledTask
```

However, the custom Rule `100103` **did not appear in the live `alerts.json`**.

Therefore:

- Telemetry ingestion: **Successful**
- Custom rule validation: **Successful**
- Live custom alert generation: **Not confirmed**

This distinction was retained rather than treating the `wazuh-logtest` result as proof of live alert generation.

---

## 10. Detection Flow

```
Windows 11 Endpoint
        │
        ▼
schtasks.exe creates scheduled task
        │
        ▼
Sysmon Event ID 11
        │
        ▼
C:\Windows\System32\Tasks\SOCLabScheduledTask
        │
        ▼
Wazuh Agent
        │
        ▼
Wazuh Manager
        │
        ├──► archives.json
        │       └── Telemetry confirmed
        │
        └──► Rule 100103
                └── Rule validated with wazuh-logtest
```

## 11. Conclusion

Scenario 7 successfully demonstrated detection of **Windows Scheduled Task creation** using Sysmon and Wazuh.

The custom Rule `100103` correctly detected Sysmon Event ID 11 telemetry representing creation of a scheduled-task file and was successfully validated using `wazuh-logtest`.

The real endpoint telemetry was also successfully received by Wazuh and stored in `archives.json`. However, the custom rule did not appear in the live `alerts.json`, so live custom-alert generation remains unresolved.

The scenario therefore demonstrates both **successful telemetry collection and rule validation**, while documenting the remaining live-alert limitation accurately.