````
# Phase 3: Wazuh Agent Deployment & Authentication

## 1. Monitored Windows Endpoint Specifications
To simulate endpoint threat monitoring, a target client was configured on a dedicated Windows 11 virtual machine. The system specifications are allocated to ensure a realistic endpoint execution environment:

*   **vCPUs (Processors):** 2 CPUs allocated with a 100% Processing Cap.
*   **System Memory (Base Memory):** 4096 MB (4 GB).
*   **Motherboard Chipset:** PIIX3.
*   **TPM Version:** 2.0 (Enabled).
*   **System Features:** I/O APIC, UEFI, and Secure Boot enabled.

---

## 2. Windows 11 Network Interfaces
The Windows endpoint utilizes a dual-adapter configuration to separate secure, isolated telemetry forwarders from public package downloads:

*   **Adapter 1 (NAT):**
    *   **Attachment:** NAT
    *   **Promiscuous Mode:** Deny
    *   **Cable Status:** Connected (Virtual Cable Connected)
    *   **Purpose:** Allows secure outbound internet access for downloading the Wazuh agent installer and administrative monitoring utilities (like Microsoft Sysmon).
*   **Adapter 2 (Host-Only Network):**
    *   **Attachment:** Host-only Adapter
    *   **Adapter Name:** VirtualBox Host-Only Ethernet Adapter
    *   **Promiscuous Mode:** Deny
    *   **Cable Status:** Connected (Virtual Cable Connected)
    *   **Purpose:** Establishes a private inter-VM transmission path across the `<SUBNET_RANGE>` space to securely forward cryptographic logs to the Wazuh Manager.

---

## 3. Wazuh Agent Installation & Initial State
The endpoint agent was deployed to establish the telemetry tunnel back to the manager.

### Agent Environment
*   **Agent Software Version:** `Wazuh v4.4.5`
*   **Service Name:** `Wazuh`
*   **Default State Post-Installation:**
    *   **Manager IP:** `<PLACEHOLDER_IP_OR_0.0.0.0>`
    *   **Authentication Key:** `<insert_auth_key_here>`
    *   **Agent Registration Status:** `Auth key not imported. (0) - 0`
    *   **Wazuh Agent Status:** `Require import of authentication key. - Not Running`

To transition the agent to an active state, the endpoint must register with the manager to obtain a unique cryptographic authentication key and complete the secure SSL handshake on Port `1515`.

---

## 4. Operational Analysis: Agent Registration Naming Discrepancies
After performing initial registration steps, the active agents were listed on the central Wazuh Manager server using the agent control utility:

```bash
sudo /var/ossec/bin/agent_control -l
````

Registered Agents Status Output

```
Wazuh agent_control. List of available agents:
  ID: 000, Name: mandy-VirtualBox (server), IP: <LOOPBACK_IP>, Active/Local
  ID: 001, Name: A16, IP: any, Active
  ID: 002, Name: W11, IP: any, Disconnected
  ID: 003, Name: bemyguest, IP: any, Active
```

Forensic Analysis of Hostnames

The output reveals a naming mismatch across the environment:

1. **Agent ID** **001** **(Name:** **A16** **- Active):** This agent represents the initial registration under the physical host machine's name context (`A16`), which initially caused network route confusion.
2. **Agent ID** **002** **(Name:** **W11** **- Disconnected):** A pre-registered agent entry named `W11` was created but is currently inactive because no host has completed an active handshake using its designated authentication key.
3. **Agent ID** **003** **(Name:** **bemyguest** **- Active):** The active Windows 11 VM successfully enrolled under the hostname `bemyguest`. The live telemetry pipeline is currently running through this agent ID.

Remediation Roadmap

To maintain clean documentation and align with enterprise standards, the hostnames will be structured as follows:

- Keep the telemetry running on the active agent ID `003` (`bemyguest`) for testing scenarios.
- For a clean deployment, the disconnected agent registrations (such as IDs `001` and `002`) can be deregistered using the `manage_agents` utility on the manager:

```
# Command to remove unused/stale agents
sudo /var/ossec/bin/manage_agents
```

