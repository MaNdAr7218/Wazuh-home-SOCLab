````
# Phase 1: System Architecture & Virtual Network Setup

## 1. Physical Host System Specifications (A16)
To build a high-performance, single-host Security Operations Center (SOC) lab, a capable physical machine is required to run multiple virtualised environments simultaneously without resource starvation [1]. The physical host laptop (**A16**) possesses the following hardware specifications:

*   **Processor (CPU):** AMD Ryzen 7 7435HS @ 3.10 GHz (8 physical cores, 16 threads)
*   **System RAM:** 16 GB DDR5 @ 4800 MT/s
*   **Graphics (GPU):** AMD Radeon RX 7600S (8 GB Dedicated VRAM)
*   **Storage capacity:** 477 GB NVMe SSD (273 GB currently consumed)

---

## 2. Virtual Machine Provisioning & Allocations
Two virtual machines were provisioned inside **Oracle VM VirtualBox** [2, 3]. Because the physical host has 16 GB of RAM, resources were carefully balanced to allocate **12 GB** to active virtual systems, leaving a healthy **4 GB safety buffer** for the physical host Windows 11 operating system [1].

### VM 1: Wazuh Manager (Ubuntu Server)
*   **Operating System:** Ubuntu Server (64-bit) [1]
*   **Base Memory (RAM):** 8,192 MB (8 GB) [1]
*   **Processors (vCPUs):** 4 vCPUs (Processing Cap: 100%)
*   **Storage:** Dynamic Allocation
*   **Core Role:** Log collection, normalization, analysis, custom rule parsing, and indexing [2].

### VM 2: Monitored Endpoint (Windows 11)
*   **Operating System:** Windows 11 Client (64-bit) [2]
*   **Base Memory (RAM):** 4,096 MB (4 GB) [1]
*   **Processors (vCPUs):** 2 vCPUs (Processing Cap: 100%)
*   **Storage:** Solid State Drive (Dynamic)
*   **Core Role:** Target client running Sysmon, forwarding OS and Security Event logs, and simulating threat scenarios [3].

---

## 3. Network Architecture & Interface Engineering
The lab employs a **dual-adapter network design** to maintain complete isolation for security analysis while still allowing secure internet connectivity when required for system updates and package downloads [3].

```text
               ┌────────────────────────────────────────────────────────┐
               │              PHYSICAL HOST (A16 Laptop)                │
               │                   Windows 11 OS                        │
               │               Host IP: 192.168.56.1                    │
               └──────────────────────────┬─────────────────────────────┘
                                          │
                                   (VirtualBox)
                                          │
                  ┌───────────────────────┴───────────────────────┐
                  │                                               │
   ┌──────────────▼──────────────┐                 ┌──────────────▼──────────────┐
   │         VIRTUAL VM 1        │                 │         VIRTUAL VM 2        │
   │      Ubuntu Server OS       │                 │         Windows 11 VM       │
   │       Wazuh Manager         │                 │    Wazuh Agent & Sysmon     │
   │    IP: 192.168.56.101       │                 │       IP: 192.168.56.X      │
   └──────────────┬──────────────┘                 └──────────────┬──────────────┘
                  │                                               │
      [Adapter 1: Host-Only]                          [Adapter 1: NAT]
      [Adapter 2: NAT]                                [Adapter 2: Host-Only]
````
VirtualBox Adapter Mapping

1. **Ubuntu Manager Interface Mapping:**
    - **Adapter 1 (Host-Only):** Bound to `VirtualBox Host-Only Ethernet Adapter`. This adapter provides static IP communication at `192.168.56.101`. Promiscuous Mode: Deny. Cable Connected: True.
    - **Adapter 2 (NAT):** Enabled to allow the Ubuntu operating system to access package mirrors (e.g., `apt-get install` or fetching Wazuh updates).
2. **Windows 11 Endpoint Interface Mapping:**
    - **Adapter 1 (NAT):** Configured as the primary interface to download threat emulation packages, Sysmon binaries, and Wazuh installer files.
    - **Adapter 2 (Host-Only):** Bound to `VirtualBox Host-Only Ethernet Adapter` to route cryptographic telemetry traffic to the Wazuh Manager.

---

4. Engineering Highlight: Host-Only Troubleshooting Log

Issue Statement

During initial testing, the Wazuh Manager lost all connectivity with the Windows 11 endpoint. Running the manager control utility returned a status of:

```
ID: 001, Name: A16, IP: any, Disconnected
```

The agent host could not ping the Wazuh manager at `192.168.56.101`, resulting in connection timeouts.

Diagnostic Steps

1. Checked active virtual interfaces on the Ubuntu manager to verify if IP binding had failed.
2. Inspected the VirtualBox configuration panel on the host machine.
3. Identified that the Host-Only network binding had become inactive on the physical host hypervisor, causing packet loss between the guest subnets.

Resolution

1. Restored and verified the binding status of the `VirtualBox Host-Only Ethernet Adapter` within virtual settings for both VMs.
2. Executed an ICMP echo verification from the monitored Windows VM:

```
ping 192.168.56.101
```

1. **Result:** Restored 100% network reachability with `0% packet loss` and an average round-trip time of `0ms`, allowing the Wazuh Agent to successfully re-register and change its status to `Active`.

---

5. Troubleshooting Log: Wazuh Dashboard API Connectivity

Issue Statement

Upon loading the Wazuh Web Dashboard, the dashboard threw a critical error screen stating **"The API connections could be down or inaccessible"** with the default connection status showing **Offline / Error checking updates**.

Diagnostic Flow

When this error occurs, it indicates that the Wazuh Dashboard service (Kibana-based interface) cannot communicate with the core Wazuh Manager API on port `55000`.

Troubleshooting Commands to Run on Ubuntu VM

To resolve this issue, the security engineer must verify the status of the indexing and API management services:

1. **Check Wazuh Indexer Status:**

```
sudo systemctl status wazuh-indexer
```

1. **Check Wazuh Manager API Status:**

```
sudo systemctl status wazuh-manager
```

1. **Check Filebeat Ingestion Engine:**

```
sudo systemctl status filebeat
```

1. **Restart Failing Components:** If any of the services display as stopped or inactive (often caused by RAM memory spikes), execute a full service restart:

```
sudo systemctl restart wazuh-indexer wazuh-manager filebeat
```