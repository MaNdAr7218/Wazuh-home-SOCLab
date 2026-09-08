````
# Phase 4: Telemetry Ingestion (Sysmon & Windows Event Collection)

## 1. Ingestion Pipeline Overview
To successfully perform threat hunting and detect suspicious endpoint behavior, the central SIEM requires a steady, high-fidelity stream of event telemetry [1]. Standard Windows Event Logs are insufficient on their own; they must be enriched with deeper administrative and execution logs [2]. 

This lab establishes a complete end-to-end ingestion pipeline:

```text
[Attack Activity] ──► [Sysmon Log Channel] ──► [Wazuh Agent Ingestion] ──► [Wazuh Manager (Decoders/Rules)]
````

- **Endpoint Generation:** Sysmon monitors system activity and writes events directly to the Windows Event Viewer.
- **Agent Capture:** The local Wazuh Agent reads the Sysmon log channel.
- **Manager Shipping:** The agent compresses and securely ships these logs to the Wazuh Manager over the Host-Only network.

---

2. Microsoft Sysmon Integration

**System Monitor (Sysmon)** is a Windows system service and device driver that, once installed on a host, remains resident across system reboots to monitor and log system activity to the Windows Event log.

For this lab, Sysmon was integrated on the monitored Windows 11 endpoint to capture two high-priority telemetry sources:

A. Sysmon Event ID 1: Process Creation

This event provides rich security context whenever a new process is executed on the system. It captures vital forensic fields, including:

- **Image:** The full file path of the executable (e.g., `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`).
- **CommandLine:** The exact command string executed by the user or system, which is crucial for identifying obfuscated commands.
- **ParentImage:** The process that spawned the new command.
- **ParentCommandLine:** The exact command line used to launch the parent process.
- **User:** The security account name executing the process.
- **Hashes:** Cryptographic hashes of the file (SHA256, MD5, etc.) to perform file reputation checks.
- **ProcessId:** The unique operating system identifier for the process.

B. Sysmon Event ID 11: File Creation

This event is triggered whenever a file is created or overwritten on the filesystem. In this lab, it is specifically monitored to detect files created in highly sensitive or temporary paths (such as `AppData\Local\Temp\`) or when scripting file types (like `.ps1`, `.bat`, or `.vbs`) are dropped.

---

3. Configuring Agent Log Forwarding (`ossec.conf`)

By default, the Windows Wazuh Agent only monitors standard Windows Event channels (Application, Security, and System). To forward the enriched Sysmon telemetry to the Wazuh Manager, the agent's core configuration must be modified.

Step-by-Step Agent Configuration

1. On the Windows 11 VM, open your text editor (such as Notepad or VS Code) as an **Administrator**.
2. Open the Wazuh Agent configuration file located at: `C:\Program Files (x86)\ossec-agent\ossec.conf`
3. Scroll to the `<localfile>` blocks and insert the following XML block to instruct the agent to ingest the Sysmon Event channel:

```
<!-- Ingest Microsoft Sysmon Operational Logs -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

1. Verify the connection block is properly pointed to the private IP of your central Ubuntu Manager over the isolated Host-Only network adapter:

```
<client>
  <server>
    <address>&lt;WAZUH_MANAGER_PRIVATE_IP&gt;</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
</client>
```

1. Save the configuration file.

Applying Configuration Changes

To force the agent to load the new ingestion directives, restart the Windows **Wazuh** service. This can be executed via the local Wazuh Agent GUI or through an elevated PowerShell console:

```
Restart-Service -Name "Wazuh"
```

---

4. Verification of Live Ingestion on Wazuh Manager

Once the agent service is restarted, you can verify that Sysmon logs are successfully arriving at the manager in real-time.

Checking Raw Ingested Events

On the Ubuntu Wazuh Manager server, the raw JSON logs engine can be monitored directly:

1. Enable raw log archiving in `/var/ossec/etc/ossec.conf` by verifying `<logall_json>` is set to `yes`.
2. Use the command line to stream the raw events file and filter for incoming Sysmon telemetry:

```
sudo tail -f /var/ossec/logs/archives/archives.json | grep -i "Sysmon"
```

1. **Expected Result:** When activity is performed on the Windows 11 VM, raw JSON events matching Sysmon Event IDs `1` or `11` will stream onto the console, validating that the entire telemetry pipeline is operational