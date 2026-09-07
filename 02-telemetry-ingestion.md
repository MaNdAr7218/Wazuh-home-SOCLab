````
# Phase 2: Telemetry Ingestion (Configuring Sysmon & Windows Log Collection)

## 1. Windows Telemetry Ingestion Pipeline
To establish a high-fidelity monitoring environment, standard Windows Event Logs are supplemented with **Microsoft Sysmon (System Monitor)**. Standard Windows Security logs often lack critical forensic details—such as process hashes, parent-child process relationships, and command-line arguments. 

This lab establishes a multi-tiered telemetry ingestion pipeline [1]:

```text
[Windows Endpoint]               [Wazuh Agent]                  [Wazuh Manager]
  Active Telemetry  ───(Local)───► Ingestion Engine ───(SSL)───► Decoders & Rules
  (Sysmon Event 1)                 (ossec.conf)                  (alerts.json)
  (Sysmon Event 11)
````

By passing raw OS telemetry to the local **Wazuh Agent**, logs are compressed, encrypted, and forwarded in real-time to the **Wazuh Manager** for central decoding and analysis.

---

2. Microsoft Sysmon Installation & Tuning

Sysmon provides granular monitoring of system activity on the Windows 11 endpoint. In this lab, we focus on harvesting two high-value security events:

- **Sysmon Event ID 1 (Process Creation):** Collects vital execution context, including the executing image, process command line, parent process name, parent command line, executing user, and cryptographic hashes (SHA256, MD5, etc.).
- **Sysmon Event ID 11 (File Creation):** Detects file system modifications, specifically targeting scripts created in temporary directories commonly used for malware staging.

Step-by-Step Sysmon Deployment

1. **Download Sysmon:** Downloaded the latest Microsoft Sysmon binary package from the official Microsoft Sysinternals suite.
2. **Acquire a Detection Configuration:** A tuned XML configuration file (such as SwiftOnSecurity's modular configuration) was selected. This configuration filters out routine system noise (such as background browser processes) while ensuring critical execution contexts in Windows PowerShell and system directories are strictly recorded.
3. **Install via Administrator PowerShell:** With the binary and configuration file placed in the same directory, execute the installation command in an elevated PowerShell prompt:

```
.\Sysmon64.exe -i sysmonconfig.xml -accepteula
```

1. **Verification:** Verify the service is active and generating events by running:

```
Get-Service -Name "Sysmon64"
```

Alternatively, confirm that the Event Viewer log stream is populated at: `Applications and Services Logs -> Microsoft -> Windows -> Sysmon -> Operational`

---

3. Configuring the Wazuh Agent (`ossec.conf`)

By default, the local Windows Wazuh Agent only monitors standard Windows Event channels (Application, Security, and System). To capture Sysmon telemetry, we must explicitly direct the agent to read the custom Sysmon operational log channel.

Ingestion Configuration Steps

1. On the **Windows 11 VM**, open your text editor (such as Notepad or VS Code) as an **Administrator**.
2. Open the Wazuh Agent configuration file: `C:\Program Files (x86)\ossec-agent\ossec.conf`
3. Scroll down to the `<localfile>` sections and paste the following XML configuration block to add the Sysmon channel:

```
<!-- Ingest Microsoft Sysmon Operational Logs -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

1. Verify the core manager connection parameters in the same file. Ensure the manager IP block points securely to your isolated manager VM:

```
<client>
  <server>
    <address>&lt;WAZUH_MANAGER_PRIVATE_IP&gt;</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
</client>
```

1. Save the changes.

Restarting the Telemetry Agent

To apply the updated configuration, restart the Wazuh Agent service. This can be accomplished via the Wazuh Agent GUI (Manage -> Restart) or directly inside an **Administrator PowerShell** session:

```
Restart-Service -Name "Wazuh"
```

---

4. Telemetry Verification on Wazuh Manager

To verify that Sysmon logs are successfully arriving at the central manager, we can inspect raw ingested logs directly on the **Ubuntu Server** command line.

Ingestion Validation Procedure

1. Log in to the **Wazuh Manager** terminal.
2. Enable the archive logging engine (which keeps a copy of _all_ incoming events, regardless of whether they trigger an alert) by opening the configuration file:

```
sudo nano /var/ossec/etc/ossec.conf
```

Ensure that the `<logall_json>` option is enabled:

```
<logall_json>yes</logall_json>
```

_Save the file and restart the manager if you had to change this setting:_

```
sudo systemctl restart wazuh-manager
```

1. Execute a live monitoring stream on the raw archives file to watch specifically for incoming Sysmon Event ID 1 telemetry:

```
sudo tail -f /var/ossec/logs/archives/archives.json | grep -i "Sysmon"
```

1. **Result:** When you run commands on your Windows 11 VM, you will see highly structured JSON events containing fields such as `win.eventdata.image`, `win.eventdata.commandLine`, and process hashes streaming live into your manager logs!