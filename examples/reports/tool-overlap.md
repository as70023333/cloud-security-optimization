# Security tool overlap review

**Source:** built-in demo inventory (fictional company)

## Summary

| Measure | Value |
|---|---|
| Tools | 14 (8 paid separately) |
| Annual spend | $344,000 |
| Capabilities covered | 26 |
| Capabilities provided by more than one tool | 6 |
| Required capabilities with no tool | 2 |
| Spend on fully redundant tools | $92,000 a year (27% of spend) |

## Opportunities

**Estimated saving: up to $7,667 a month ($92,000 a year).**

| # | Opportunity | Saving / month | Effort |
|---|---|---|---|
| 1 | Acme EDR is fully covered by other tools | $4,500 | high |
| 2 | Acme Email Gateway is fully covered by other tools | $3,167 | high |
| 3 | No tool covers Backup and recovery | - | medium |
| 4 | No tool covers Privileged access management | - | medium |
| 5 | Phishing simulation is provided by 2 tools | - | medium |
| 6 | SIEM / log management is provided by 2 tools | - | medium |
| 7 | Vulnerability management is provided by 2 tools | - | medium |

### 1. Acme EDR is fully covered by other tools

All 2 of its capabilities (Antivirus / next-generation antivirus, Endpoint detection and response) are also provided by Microsoft Defender for Endpoint. It costs $54,000 a year.

**What to do:** Compare depth, not just the label: confirm the other tools meet the same requirements, plan the migration, then retire this one at renewal.

### 2. Acme Email Gateway is fully covered by other tools

All 1 of its capabilities (Email security (phishing, malware)) are also provided by Microsoft Defender for Office 365. It costs $38,000 a year.

**What to do:** Compare depth, not just the label: confirm the other tools meet the same requirements, plan the migration, then retire this one at renewal.

### 3. No tool covers Backup and recovery

Backup and recovery (Data) is required but no tool in the inventory provides it.

**What to do:** Check whether a licence you already own includes it before buying something new; if it does not apply to you, add it to not_required in the inventory.

### 4. No tool covers Privileged access management

Privileged access management (Identity) is required but no tool in the inventory provides it.

**What to do:** Check whether a licence you already own includes it before buying something new; if it does not apply to you, add it to not_required in the inventory.

### 5. Phishing simulation is provided by 2 tools

Microsoft Defender for Office 365 (bundled with Microsoft 365 E5), Acme Awareness Training ($9,000/yr).

**What to do:** Pick one as the standard for this capability. If a paid tool is kept only for this, negotiate it out of the contract or drop the module.

### 6. SIEM / log management is provided by 2 tools

Microsoft Sentinel ($96,000/yr), Acme SIEM (legacy) ($72,000/yr).

**What to do:** Pick one as the standard for this capability. If a paid tool is kept only for this, negotiate it out of the contract or drop the module.

### 7. Vulnerability management is provided by 2 tools

Microsoft Defender for Endpoint (bundled with Microsoft 365 E5), Acme Vulnerability Scanner ($24,000/yr).

**What to do:** Pick one as the standard for this capability. If a paid tool is kept only for this, negotiate it out of the contract or drop the module.

## Capability matrix

**Gap** = required, but no tool in the inventory provides it.

### Endpoint

| Capability | Provided by | Status |
|---|---|---|
| Antivirus / next-generation antivirus | Microsoft Defender for Endpoint, Acme EDR | Overlap (2) |
| Device management (MDM / UEM) | Microsoft Intune | Covered |
| Disk encryption management | Microsoft Intune | Covered |
| Endpoint detection and response | Microsoft Defender for Endpoint, Acme EDR | Overlap (2) |
| Patch management | Microsoft Intune | Covered |
| Vulnerability management | Microsoft Defender for Endpoint, Acme Vulnerability Scanner | Overlap (2) |

### Identity

| Capability | Provided by | Status |
|---|---|---|
| Conditional / risk-based access | Microsoft Entra ID P2 | Covered |
| Identity governance and access reviews | Microsoft Entra ID P2 | Covered |
| Identity threat detection (ITDR) | Microsoft Defender for Identity | Covered |
| Multifactor authentication | Microsoft Entra ID P2 | Covered |
| Password manager | Acme Password Manager | Covered |
| Privileged access management | - | **Gap** |
| Single sign-on | Microsoft Entra ID P2 | Covered |

### Email

| Capability | Provided by | Status |
|---|---|---|
| Email security (phishing, malware) | Microsoft Defender for Office 365, Acme Email Gateway | Overlap (2) |
| Phishing simulation | Microsoft Defender for Office 365, Acme Awareness Training | Overlap (2) |
| Security awareness training | Acme Awareness Training | Covered |

### Network

| Capability | Provided by | Status |
|---|---|---|
| Intrusion detection / prevention | Acme Firewall | Covered |
| Network firewall | Acme Firewall | Covered |
| Secure web gateway / web filtering | Acme Firewall | Covered |
| Zero trust network access / VPN | Acme Firewall | Covered |

### Cloud

| Capability | Provided by | Status |
|---|---|---|
| Cloud access security broker / SaaS security | Microsoft Defender for Cloud Apps | Covered |

### Data

| Capability | Provided by | Status |
|---|---|---|
| Backup and recovery | - | **Gap** |

### Security operations

| Capability | Provided by | Status |
|---|---|---|
| Incident case management | Acme SIEM (legacy) | Covered |
| SIEM / log management | Microsoft Sentinel, Acme SIEM (legacy) | Overlap (2) |
| Security orchestration and automation | Microsoft Sentinel | Covered |
| Threat intelligence | Microsoft Sentinel | Covered |
| User and entity behaviour analytics | Microsoft Sentinel | Covered |

### Governance

| Capability | Provided by | Status |
|---|---|---|
| Asset inventory | Acme Vulnerability Scanner | Covered |

## Tools

| Tool | Vendor | Cost / year | Only this tool provides | Also provided elsewhere |
|---|---|---|---|---|
| Microsoft Defender for Endpoint | Microsoft | bundled (Microsoft 365 E5) | nothing | Antivirus / next-generation antivirus, Endpoint detection and response, Vulnerability management |
| Microsoft Intune | Microsoft | bundled (Microsoft 365 E5) | Device management (MDM / UEM), Patch management, Disk encryption management | - |
| Microsoft Entra ID P2 | Microsoft | bundled (Microsoft 365 E5) | Single sign-on, Multifactor authentication, Conditional / risk-based access, Identity governance and access reviews | - |
| Microsoft Defender for Identity | Microsoft | bundled (Microsoft 365 E5) | Identity threat detection (ITDR) | - |
| Microsoft Defender for Office 365 | Microsoft | bundled (Microsoft 365 E5) | nothing | Email security (phishing, malware), Phishing simulation |
| Microsoft Defender for Cloud Apps | Microsoft | bundled (Microsoft 365 E5) | Cloud access security broker / SaaS security | - |
| Microsoft Sentinel | Microsoft | $96,000 | Security orchestration and automation, User and entity behaviour analytics, Threat intelligence | SIEM / log management |
| Acme EDR | Acme | $54,000 | nothing | Antivirus / next-generation antivirus, Endpoint detection and response |
| Acme Email Gateway | Acme | $38,000 | nothing | Email security (phishing, malware) |
| Acme SIEM (legacy) | Acme | $72,000 | Incident case management | SIEM / log management |
| Acme Vulnerability Scanner | Acme | $24,000 | Asset inventory | Vulnerability management |
| Acme Firewall | Acme | $45,000 | Network firewall, Intrusion detection / prevention, Secure web gateway / web filtering, Zero trust network access / VPN | - |
| Acme Awareness Training | Acme | $9,000 | Security awareness training | Phishing simulation |
| Acme Password Manager | Acme | $6,000 | Password manager | - |

---
Generated by cloud-security-optimization 1.0.0. Read-only: nothing was changed.
