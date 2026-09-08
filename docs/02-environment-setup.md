````
# Phase 2: Wazuh Manager Environment Setup

## 1. Ubuntu Virtual Machine Resource Allocations
The central Wazuh Manager server is hosted on an Ubuntu Server virtual machine running inside VirtualBox. The system specifications are configured as follows:

*   **vCPUs (Processors):** 4 CPUs allocated with a 100% Processing Cap.
*   **System Memory (Base Memory):** 8192 MB (8 GB).
*   **Motherboard Chipset:** PIIX3.
*   **TPM Version:** None.
*   **Pointing Device:** USB Tablet.
*   **System Features:** I/O APIC enabled, Hardware Clock in UTC.

---

## 2. Virtual Network Configuration
The Ubuntu VM uses a dual-adapter configuration to separate secure monitoring traffic from outbound public networks:

*   **Adapter 1 (Host-Only Network):**
    *   **Attachment:** Host-only Adapter
    *   **Adapter Name:** VirtualBox Host-Only Ethernet Adapter
    *   **Promiscuous Mode:** Deny
    *   **Cable Status:** Connected (Virtual Cable Connected)
    *   **Purpose:** Routes private inter-VM telemetry traffic and Host-Only communications across the `<SUBNET_RANGE>` address space.
*   **Adapter 2 (Network Address Translation - NAT):**
    *   **Attachment:** NAT
    *   **Promiscuous Mode:** Deny
    *   **Cable Status:** Connected (Virtual Cable Connected)
    *   **Purpose:** Secure outbound internet access for package updates and system dependencies.

---

## 3. Wazuh Manager Roles & Core Directories
The Ubuntu VM acts as the central engine for your Security Operations Center (SOC). It receives logs from endpoints, normalizes them, processes decoders, applies custom detection rules, and outputs alerts.

The following core directories and utility paths are configured on this server:

| Path / Command | Purpose |
| :--- | :--- |
| `/var/ossec/etc/rules/local_rules.xml` | Repository for custom XML detection rules. |
| `/var/ossec/logs/alerts/alerts.json` | Stores generated security alerts. |
| `/var/ossec/logs/archives/archives.json` | Live stream of all raw processed events received by the manager. |
| `sudo /var/ossec/bin/wazuh-logtest` | Built-in CLI tool used to test and validate custom rules. |
| `sudo /var/ossec/bin/agent_control -l` | CLI utility used to list and verify registered agent statuses. |

---

## 4. Troubleshooting: Wazuh Dashboard API Connection Error
During the initial launch of the security dashboard, a connection failure interrupted communication.

### Incident Evidence
*   **Error Screen UI Message:** *"The API connections could be down or inaccessible"*
*   **Target Connection ID:** `default`
*   **Host Path:** `https://<LOOPBACK_IP>`
*   **Port:** `55000` (Wazuh Manager API Port)
*   **Default Username:** `wazuh-wui`
*   **Connection Status:** `Offline`
*   **Updates Status:** `Error checking updates`

### Cause & Corrective Actions
This error indicates that the frontend Kibana web console was unable to authenticate or establish a connection with the backend Wazuh Manager API on Port `55000`. This usually occurs when indexing services run out of memory or stall. To resolve the issue, verify and restart the central services on the Ubuntu server:
```bash
# Restart the core indexing and ingestion pipeline
sudo systemctl restart wazuh-indexer
sudo systemctl restart filebeat
sudo systemctl restart wazuh-manager
````

```

***
```