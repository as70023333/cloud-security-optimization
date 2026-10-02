"""The capability vocabulary used to describe security tools.

Each capability has an id (used in the inventory file), a plain name, a domain, and whether it is
part of the baseline: the capabilities most organizations are expected to have, used for the gap
analysis. The baseline is a starting point; override it in the inventory file with ``required``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Capability:
    id: str
    name: str
    domain: str
    baseline: bool = False


_RAW: tuple[tuple[str, str, str, bool], ...] = (
    # endpoint
    ("antivirus", "Antivirus / next-generation antivirus", "Endpoint", True),
    ("edr", "Endpoint detection and response", "Endpoint", True),
    ("device-management", "Device management (MDM / UEM)", "Endpoint", True),
    ("patch-management", "Patch management", "Endpoint", True),
    ("vulnerability-management", "Vulnerability management", "Endpoint", True),
    ("disk-encryption", "Disk encryption management", "Endpoint", False),
    # identity
    ("sso", "Single sign-on", "Identity", True),
    ("mfa", "Multifactor authentication", "Identity", True),
    ("conditional-access", "Conditional / risk-based access", "Identity", False),
    ("pam", "Privileged access management", "Identity", False),
    ("identity-governance", "Identity governance and access reviews", "Identity", False),
    ("identity-threat-detection", "Identity threat detection (ITDR)", "Identity", False),
    ("password-manager", "Password manager", "Identity", False),
    # email and collaboration
    ("email-security", "Email security (phishing, malware)", "Email", True),
    ("phishing-simulation", "Phishing simulation", "Email", False),
    ("security-awareness", "Security awareness training", "Email", True),
    # network
    ("firewall", "Network firewall", "Network", True),
    ("ids-ips", "Intrusion detection / prevention", "Network", False),
    ("web-filtering", "Secure web gateway / web filtering", "Network", False),
    ("dns-security", "DNS security", "Network", False),
    ("ztna", "Zero trust network access / VPN", "Network", True),
    ("ndr", "Network detection and response", "Network", False),
    ("waf", "Web application firewall", "Network", False),
    ("ddos-protection", "DDoS protection", "Network", False),
    # cloud
    ("cspm", "Cloud security posture management", "Cloud", False),
    ("cwpp", "Cloud workload protection", "Cloud", False),
    ("casb", "Cloud access security broker / SaaS security", "Cloud", False),
    ("ciem", "Cloud infrastructure entitlement management", "Cloud", False),
    # data
    ("dlp", "Data loss prevention", "Data", False),
    ("data-classification", "Data classification and labelling", "Data", False),
    ("key-management", "Key and certificate management", "Data", False),
    ("secrets-management", "Secrets management", "Data", False),
    ("backup", "Backup and recovery", "Data", True),
    # security operations
    ("siem", "SIEM / log management", "Security operations", True),
    ("soar", "Security orchestration and automation", "Security operations", False),
    ("threat-intelligence", "Threat intelligence", "Security operations", False),
    ("ueba", "User and entity behaviour analytics", "Security operations", False),
    ("case-management", "Incident case management", "Security operations", False),
    ("mdr", "Managed detection and response service", "Security operations", False),
    # application security
    ("sast", "Static application security testing", "Application security", False),
    ("dast", "Dynamic application security testing", "Application security", False),
    ("sca", "Software composition analysis", "Application security", False),
    ("secrets-scanning", "Secrets scanning in code", "Application security", False),
    # governance
    ("asset-inventory", "Asset inventory", "Governance", True),
    ("grc", "Governance, risk and compliance", "Governance", False),
    ("attack-surface-management", "External attack surface management", "Governance", False),
)

CAPABILITIES: dict[str, Capability] = {row[0]: Capability(*row) for row in _RAW}
DOMAINS: tuple[str, ...] = tuple(dict.fromkeys(c.domain for c in CAPABILITIES.values()))
BASELINE: frozenset[str] = frozenset(c.id for c in CAPABILITIES.values() if c.baseline)
