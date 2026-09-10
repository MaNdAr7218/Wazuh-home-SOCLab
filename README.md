> **A hands-on home Security Operations Center (SOC) lab built with Wazuh, Windows 11, Sysmon, and MITRE ATT&CK.**
> 
> This project demonstrates how security telemetry is generated, collected, analyzed, and converted into actionable detections using custom Wazuh rules.

- **Wazuh:** [Wazuh](https://wazuh.com/?utm_source=chatgpt.com)
- **Windows 11:** [Windows 11](https://www.microsoft.com/windows/?utm_source=chatgpt.com)
- **Sysmon:** Sysmon Documentation
- **MITRE ATT&CK:** [MITRE ATT&CK](https://attack.mitre.org/?utm_source=chatgpt.com)
- **VirtualBox:** [VirtualBox](https://www.virtualbox.org/?utm_source=chatgpt.com)
- **Your GitHub repository:** Wazuh Home SOC Lab

---

## About This Project

This repository contains my **Home SOC Lab**, created to develop practical cybersecurity and SOC analyst skills through hands-on detection engineering.

Instead of only studying security concepts theoretically, this lab focuses on:

- Generating controlled attack-like activity
- Collecting endpoint telemetry
- Writing custom detection rules
- Mapping detections to MITRE ATT&CK
- Validating detection logic
- Investigating Wazuh alerts
- Troubleshooting detection pipelines
- Documenting investigation evidence

The goal is to simulate the workflow of a junior SOC analyst working with endpoint security telemetry.

---

# Architecture

```
                         HOME SOC LAB
                              │
                              │
                    ┌─────────▼─────────┐
                    │    Windows 11     │
                    │      Endpoint     │
                    │                   │
                    │      Sysmon       │
                    └─────────┬─────────┘
                              │
                     Security Telemetry
                              │
                              ▼
                    ┌───────────────────┐
                    │   Wazuh Agent     │
                    │   Agent ID: 003   │
                    └─────────┬─────────┘
                              │
                              │
                              ▼
                    ┌───────────────────┐
                    │   Wazuh Manager   │
                    │                   │
                    │ Detection Engine  │
                    │ Custom Rules      │
                    │ MITRE ATT&CK      │
                    └─────────┬─────────┘
                              │
                              ▼
                    ┌───────────────────┐
                    │ Wazuh Dashboard   │
                    │                   │
                    │ Alerts / Analysis │
                    └───────────────────┘
```

---

# Lab Environment

| Component          | Configuration      |
| ------------------ | ------------------ |
| SIEM/XDR           | Wazuh              |
| Endpoint           | Windows 11         |
| Endpoint Telemetry | Sysmon             |
| Virtualization     | VirtualBox         |
| Wazuh Agent        | `bemyguest`        |
| Agent ID           | `003`              |
| Windows IP         | xxx.xxx.xxx.xxx    |
| Wazuh Manager      | `mandy-VirtualBox` |
| Manager IP         | xxx.xxx.xxx.xxx    |
| API                | Port `55000`       |
| Custom Rules       | `local_rules.xml`  |

---

# Detection Scenarios

The lab is being developed as a collection of individual SOC detection scenarios.

|#|Detection Scenario|MITRE ATT&CK|Status|
|---|---|---|---|
|01|Controlled File Creation|—|Completed|
|02|PowerShell Encoded Command|T1059.001|Completed|
|03|PowerShell Download Activity|T1105|Completed|
|04|Detection Scenario|—|Completed|
|05|Detection Scenario|—|Completed|
|06|Registry Run Key Modification|T1547.001|Completed|
|07|Scheduled Task Creation|T1053.005|Completed|
|08|Windows Service Creation|T1543.003|Completed|

> More scenarios will be added as the lab develops.

---

# Detection Engineering

A major part of this project is creating and testing custom Wazuh rules.

Example:

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

The rule detects scheduled-task artifacts created under:

```
C:\Windows\System32\Tasks\
```

---

# Example Detection Workflow

```
Attack Simulation
       │
       ▼
Windows Activity
       │
       ▼
Sysmon Event
       │
       ▼
Wazuh Agent
       │
       ▼
Wazuh Manager
       │
       ▼
Decoder
       │
       ▼
Detection Rule
       │
       ▼
MITRE ATT&CK Mapping
       │
       ▼
Wazuh Alert
       │
       ▼
SOC Investigation
```

---

# Scenario 07 — Scheduled Task

### Simulation

```
schtasks.exe /create /tn "SOCLabScheduledTask" /tr "notepad.exe" /sc once /st 23:59 /f
```

### Detection

**Rule:** `100103`

**MITRE ATT&CK:** `T1053.005`

**Technique:** Scheduled Task

The activity generated Sysmon telemetry including:

```
Process: schtasks.exe
Action: /create
Task: SOCLabScheduledTask
```

The resulting scheduled-task file was observed at:

```
C:\Windows\System32\Tasks\SOCLabScheduledTask
```

The custom rule was successfully validated with `wazuh-logtest`.

---

# Scenario 08 — Windows Service Creation

### Simulation

```
sc.exe create SOCLabService binPath= "C:\Windows\System32\notepad.exe" start= auto
```

### Detection

**Rule:** `100104`

**MITRE ATT&CK:** `T1543.003`

**Technique:** Windows Service

The endpoint generated multiple telemetry sources:

```
Sysmon Event ID 13
        +
Windows Event ID 7045
        │
        ▼
Wazuh Detection
```

Wazuh successfully generated live alerts including:

```
Rule 92307
Evidence of new service creation
```

and:

```
Rule 61138
New Windows Service Created
```

The service was configured as:

```
Service Name: SOCLabService
Binary: C:\Windows\System32\notepad.exe
Start Type: auto start
Account: LocalSystem
```

---

# Evidence & Proof

Each scenario contains supporting screenshots and evidence.

```
scenarios/
│
├── scenario-01.md
├── scenario-02.md
├── scenario-03.md
├── scenario-04.md
├── scenario-05.md
├── scenario-06.md
├── scenario-07.md
├── scenario-08.md
│
└── proofs/
    ├── s1_01.png
    ├── s1_02.png
    ├── ...
    ├── s7_01.png
    ├── s7_02.png
    ├── s7_03.png
    ├── s7_04.png
    ├── s8_01.png
    ├── s8_02.png
    ├── s8_03.png
    ├── s8_04.png
    └── s8_05.png
```

Screenshots document:

- Attack execution
- Sysmon telemetry
- Wazuh `logtest`
- Wazuh alerts
- Detection evidence
- Investigation results

---

# What I Am Learning

This lab is helping me build practical experience with:

### SOC Operations

- Alert investigation
- Event analysis
- Endpoint monitoring
- Detection validation
- Security telemetry
- Incident investigation

### Wazuh

- Agents
- Manager
- Decoders
- Rules
- `wazuh-logtest`
- `alerts.json`
- `archives.json`
- Custom detection engineering

### Windows Security

- Sysmon
- PowerShell
- Registry
- Scheduled Tasks
- Windows Services
- Process creation
- Windows Event Logs

### Detection Engineering

- Custom Wazuh rules
- PCRE2 patterns
- Event IDs
- Rule dependencies
- MITRE ATT&CK mapping
- False-positive considerations
- Detection troubleshooting

---

# Key SOC Investigation Concept

One important lesson from this project is:

> **Telemetry ingestion does not necessarily mean successful alert generation.**

For example, in Scenario 7 the Windows telemetry successfully reached Wazuh and was visible in `archives.json`, while the custom rule successfully matched the corresponding event in `wazuh-logtest`. However, the custom rule was not observed in the live `alerts.json`.

This distinction is important when troubleshooting a SIEM:

```
Endpoint Event
      ↓
Telemetry Ingestion
      ↓
Archive
      ↓
Decoder
      ↓
Rule Evaluation
      ↓
Alert Generation
```

Each stage needs to be verified independently.

---

# Tools Used

- Wazuh
- Wazuh Dashboard
- Wazuh Agent
- Sysmon
- Windows Event Viewer
- PowerShell
- Windows Command Prompt
- Linux CLI
- VirtualBox
- MITRE ATT&CK
- Git
- GitHub

---

# Repository Structure

```
Wazuh-Home-SOCLab/
│
├── README.md
│
├── scenarios/
│   ├── scenario-01.md
│   ├── scenario-02.md
│   ├── scenario-03.md
│   ├── scenario-04.md
│   ├── scenario-05.md
│   ├── scenario-06.md
│   ├── scenario-07.md
│   ├── scenario-08.md
│   │
│   └── proofs/
│       ├── s1_01.png
│       ├── s1_02.png
│       ├── s7_01.png
│       ├── s7_02.png
│       ├── s7_03.png
│       ├── s7_04.png
│       ├── s8_01.png
│       ├── s8_02.png
│       ├── s8_03.png
│       ├── s8_04.png
│       └── s8_05.png
│
└── ...
```

---

# Future Work

Planned improvements include:

- Additional Windows attack detections
- Network-based detections
- PowerShell threat hunting
- Suspicious process detection
- Credential-access scenarios
- Lateral-movement simulations
- Threat-hunting investigations
- Alert enrichment
- Detection tuning
- SOC investigation reports
- Incident-response playbooks
- Additional MITRE ATT&CK coverage

---

# Disclaimer

This project is a **controlled cybersecurity lab** created for educational and defensive security research.

All attack simulations are performed against isolated lab machines that I control.

The purpose of this repository is to demonstrate:

**Detection → Investigation → Analysis → Documentation**

rather than offensive activity against real systems.

---

# Author

**Mandar Ganiger**

Computer Science & Engineering  
Cybersecurity / SOC Analyst Track

---

## Project Repository

**GitHub:** `MaNdAr7218/Wazuh-home-SOCLab`

The repository contains the detection rules, scenario documentation, screenshots, and evidence collected throughout the development of the Home SOC Lab.
