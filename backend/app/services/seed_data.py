from typing import List, Dict, Any
from sqlalchemy.orm import Session
from app.models.firewall_rule import FirewallRule
from app.models.bastion_host import BastionHost
from app.models.system_config import SystemConfig
from app.services.traffic_simulator import set_default_firewall_policy

DEMO_FIREWALL_RULES = [
    {
        "name": "Block Malicious Source IP",
        "source_ip": "203.0.113.100",
        "destination_ip": "ANY",
        "destination_port": "ANY",
        "protocol": "ANY",
        "action": "BLOCK",
        "priority": 10,
        "is_enabled": True,
        "description": "Block all simulated traffic originating from known malicious threat actor IP."
    },
    {
        "name": "Block Legacy Insecure Telnet",
        "source_ip": "ANY",
        "destination_ip": "ANY",
        "destination_port": "23",
        "protocol": "TCP",
        "action": "BLOCK",
        "priority": 20,
        "is_enabled": True,
        "description": "Reject unencrypted Telnet port 23 to prevent credential sniffing in transit."
    },
    {
        "name": "Allow Web HTTP",
        "source_ip": "ANY",
        "destination_ip": "ANY",
        "destination_port": "80",
        "protocol": "TCP",
        "action": "ALLOW",
        "priority": 30,
        "is_enabled": True,
        "description": "Permit inbound web traffic on standard HTTP port 80."
    },
    {
        "name": "Allow Secure Web HTTPS",
        "source_ip": "ANY",
        "destination_ip": "ANY",
        "destination_port": "443",
        "protocol": "TCP",
        "action": "ALLOW",
        "priority": 40,
        "is_enabled": True,
        "description": "Permit encrypted web traffic on standard HTTPS port 443."
    },
    {
        "name": "Allow Internal Corporate Subnet",
        "source_ip": "192.168.1.0/24",
        "destination_ip": "ANY",
        "destination_port": "ANY",
        "protocol": "ANY",
        "action": "ALLOW",
        "priority": 50,
        "is_enabled": True,
        "description": "Permit legitimate management and operational traffic from trusted internal /24 subnet."
    },
    {
        "name": "Allow Domain Name System (DNS)",
        "source_ip": "ANY",
        "destination_ip": "ANY",
        "destination_port": "53",
        "protocol": "UDP",
        "action": "ALLOW",
        "priority": 60,
        "is_enabled": True,
        "description": "Allow recursive DNS queries over UDP port 53."
    }
]

DEMO_BASTION_HOSTS = [
    {
        "name": "Sentinel-Primary-Bastion-01",
        "ip_address": "10.0.0.254",
        "purpose": "Perimeter Jump Host for Internal Server Management",
        "management_protocol": "SSH",
        "management_port": 22,
        "admin_access_status": "MFA_REQUIRED",
        "monitoring_status": "ENHANCED",
        "is_enabled": True,
        "description": "Hardened gateway server providing an isolated conduit between untrusted external networks and sensitive database/application subnets."
    },
    {
        "name": "Sentinel-SecOps-Proxy-02",
        "ip_address": "10.0.1.10",
        "purpose": "Security Operations Out-of-Band Admin Gateway",
        "management_protocol": "HTTPS",
        "management_port": 8443,
        "admin_access_status": "RESTRICTED",
        "monitoring_status": "ACTIVE",
        "is_enabled": True,
        "description": "Secondary administrative proxy configured with mutual TLS and session keystroke recording for SecOps audits."
    }
]

THREAT_ENCYCLOPEDIA_DATA = [
    {
        "id": "intruder-classes",
        "title": "Classes of Intruders & Threat Actors",
        "category": "Intruder",
        "summary": "Overview of adversarial groups ranging from opportunistic script kiddies to state-sponsored persistent threats.",
        "definition": "An intruder is an unauthorized entity attempting to breach confidential, integrity, or availability boundaries of computer systems or networks.",
        "propagation_or_behavior": "Adversaries leverage vulnerability scanners, automated exploit frameworks, social engineering, credential stuffing, and brute force attacks to penetrate targets.",
        "potential_effects": "Unauthorized data exfiltration, ransomware deployment, lateral privilege escalation, intellectual property theft, and infrastructure disruption.",
        "prevention": "Defense-in-depth architecture, least-privilege role assignment, strong multi-factor authentication (MFA), network segmentation, and regular vulnerability patching.",
        "detection": "Host and network intrusion detection systems (HIDS/NIDS), centralized SIEM log correlation, firewall deny tracking, and anomaly detection engines.",
        "recovery": "Incident response containment, credential rotation, forensic root-cause analysis, and system reimaging from verified clean backups.",
        "tags": ["Threat Actors", "APT", "Defense in Depth", "Access Control"]
    },
    {
        "id": "virus-file-infector",
        "title": "File-Infector Viruses",
        "category": "Virus",
        "summary": "Classic viruses that append or prepend malicious executable code to host files (e.g. .EXE, .COM, .ELF).",
        "definition": "A file-infector virus attaches its parasitic code to executable programs. When the infected host program is executed by a user, the virus executes first, infects other clean binaries on disk, and then transfers control back to the original program.",
        "propagation_or_behavior": "Propagates when users execute or distribute infected binaries across removable storage, file shares, or email attachments. It hooks OS execution routines (e.g. CreateProcess, execve).",
        "potential_effects": "File corruption, binary tampering, covert backdoors, system degradation, and secondary payload delivery.",
        "prevention": "Software execution whitelisting (AppLocker, SRP), read-only system partitions, and disabling untrusted binary execution.",
        "detection": "Cryptographic file integrity monitoring (FIM), antivirus signature scanning, and heuristic behavioral monitors.",
        "recovery": "Disinfecting or restoring original executables from authenticated repositories; isolating affected endpoints.",
        "tags": ["Malware", "Parasitic Virus", "Execution Flow", "Integrity"]
    },
    {
        "id": "virus-boot-sector",
        "title": "Boot-Sector Viruses",
        "category": "Virus",
        "summary": "Malware targeting the Master Boot Record (MBR) or Volume Boot Record to gain control before the OS loads.",
        "definition": "A boot-sector virus copies its malicious code into the partition boot record or MBR of storage media, ensuring execution during early hardware boot sequences before OS defensive mechanisms activate.",
        "propagation_or_behavior": "Historical propagation occurred via infected floppy disks and USB drives left in drives during boot. When the BIOS/UEFI attempts to boot from the drive, the virus loads into physical RAM.",
        "potential_effects": "Total device compromise, stealth rootkit persistence, encryption of partition tables, and rendering systems unbootable.",
        "prevention": "UEFI Secure Boot with cryptographically signed bootloaders, disabling boot from removable media in BIOS firmware passwords.",
        "detection": "MBR integrity scanning tools, offline firmware verification, and hardware-enforced trust roots.",
        "recovery": "Rewriting the MBR using clean recovery media (`bootrec /fixmbr`), re-partitioning, and clearing non-volatile storage.",
        "tags": ["MBR", "Firmware", "Rootkits", "Secure Boot"]
    },
    {
        "id": "virus-macro",
        "title": "Macro Viruses",
        "category": "Virus",
        "summary": "Viruses embedded in productivity documents (Word, Excel) that execute via scripting engines.",
        "definition": "A macro virus is written in application-level macro scripting languages (such as Microsoft Visual Basic for Applications - VBA). It triggers automatically when the victim opens or enables editing in an infected document.",
        "propagation_or_behavior": "Embedded in phishing document attachments. When executed, the macro queries auto-exec hooks (e.g., AutoOpen, Workbook_Open), drops secondary PowerShell payloads, and emails copies to the user's contacts.",
        "potential_effects": "Credential harvesting, arbitrary remote code execution (RCE), ransomware installation, and corporate espionage.",
        "prevention": "Disabling macros by default across enterprise group policies, blocking macros in files downloaded from the Internet (Mark-of-the-Web).",
        "detection": "Email gateway attachment sandbox detonation, static macro analysis, and Antivirus API (AMSI) runtime inspection.",
        "recovery": "Quarantine the infected document, kill spawned unauthorized child processes (PowerShell/cmd), and inspect network perimeter logs for outbound C2 callbacks.",
        "tags": ["VBA", "Phishing", "Document Exploits", "AMSI"]
    },
    {
        "id": "worm-network",
        "title": "Network Worms",
        "category": "Worm",
        "summary": "Self-replicating autonomous malware that scans and infects remote network hosts without human intervention.",
        "definition": "Unlike a virus, which requires a human host action to propagate (e.g. opening a file), a network worm is a self-contained program that exploits network protocol vulnerabilities to independently scan, penetrate, and replicate across machines.",
        "propagation_or_behavior": "Autonomously sends crafted exploit packets to random or sequential subnet IP addresses targeting vulnerable ports (e.g., SMB port 445 in EternalBlue/WannaCry, MS08-067 in Conficker). Upon compromise, it installs itself and starts scanning for new victims.",
        "potential_effects": "Massive global outages, rapid network saturation, lateral movement within minutes, and enterprise-wide ransomware encryption.",
        "prevention": "Strict firewall segmentation blocking unneeded ports (e.g., port 445, 139, 3389 at perimeter), zero-trust host firewalls, and prompt vulnerability patching.",
        "detection": "Network IDS detecting port scanning bursts, abnormal SYN floods, and known exploit signatures; anomaly detection catching spike in outbound connections.",
        "recovery": "Immediate VLAN network quarantine, disabling vulnerable protocols (e.g. SMBv1), emergency patch deployment, and malware remediation.",
        "tags": ["Self-Replicating", "Autonomous", "Port 445", "Exploits"]
    },
    {
        "id": "worm-email",
        "title": "Email Worms",
        "category": "Worm",
        "summary": "Self-distributing malware that harvests contact address books to mass-mail infected payloads or malicious links.",
        "definition": "An email worm uses victim email client configurations (such as MAPI or SMTP direct connections) to send forged messages containing malicious attachments or URLs to every recipient found in the local address book and browser caches.",
        "propagation_or_behavior": "Tricks users with enticing subject lines (e.g., 'Invoice', 'Account Notice', 'ILOVEYOU'). Once run on one machine, it accesses the local mail spool and generates hundreds of outbound emails.",
        "potential_effects": "Mail server blacklisting, network bandwidth congestion, reputation damage, and mass endpoint compromise.",
        "prevention": "Secure Email Gateways (SEG) with SPF, DKIM, and DMARC enforcement, heuristic spam filters, and user cybersecurity awareness training.",
        "detection": "Outbound SMTP volume anomaly detection, email body hash comparisons, and endpoint process monitoring for unexpected email client automation.",
        "recovery": "Revoking compromised mail sessions, purging queued malicious messages from mail transfer agents (MTAs), and resetting user passwords.",
        "tags": ["Email Security", "Social Engineering", "SMTP", "Spreading"]
    },
    {
        "id": "concept-ids-engines",
        "title": "Rule-Based IDS vs. Statistical Anomaly Detection",
        "category": "Concept",
        "summary": "Deep dive into deterministic signature matching versus statistical baseline deviation.",
        "definition": "Intrusion Detection Systems analyze network and system events to detect policy violations or malicious activities. Modern defenses combine deterministic rule engines with statistical anomaly models.",
        "propagation_or_behavior": "Rule-Based IDS uses predefined boolean conditions and signatures (e.g., Telnet port 23 probe, >=5 SSH failures in 60s). Statistical Anomaly Detection computes running baseline metrics (mean, standard deviation) and flags deviations exceeding K standard deviations (z-scores).",
        "potential_effects": "Effective early detection of both known structured attacks and previously unseen zero-day volumetric anomalies.",
        "prevention": "Tune detection thresholds to balance security sensitivity with operational noise.",
        "detection": "Rule engine flags known exploit patterns; anomaly detector flags volumetric spikes in packets, bandwidth, or connection frequencies.",
        "recovery": "Correlate IDS alerts with firewall drop logs to create adaptive block rules.",
        "tags": ["IDS", "Signatures", "Z-Score", "Baseline Metrics"]
    },
    {
        "id": "concept-false-positives-negatives",
        "title": "False Positives vs. False Negatives in Cybersecurity",
        "category": "Concept",
        "summary": "Understanding detection trade-offs, alert fatigue, and statistical confidence intervals.",
        "definition": "A False Positive (Type I error) occurs when benign legitimate traffic is incorrectly classified as an attack. A False Negative (Type II error) occurs when actual malicious activity evades detection completely.",
        "propagation_or_behavior": "Lowering anomaly detection thresholds (e.g., small K) catches more stealthy attacks but inundates security analysts with false alerts (alert fatigue). Raising thresholds reduces noise but risks missing low-and-slow breaches.",
        "potential_effects": "Analyst burnout, ignored true alerts, or undetected security breaches.",
        "prevention": "Baseline learning periods with sufficient sample sizes, context-aware alert grouping, and dual-engine correlation.",
        "detection": "Continuous benchmarking of precision, recall, and ROC (Receiver Operating Characteristic) curves.",
        "recovery": "Iteratively whitelist verified false positives and refine signature rules.",
        "tags": ["Type I Error", "Type II Error", "Precision & Recall", "Tuning"]
    }
]

FIREWALL_CONCEPTS_DATA = [
    {
        "id": "packet-filtering",
        "name": "1. Packet-Filtering Firewall (Stateless)",
        "definition": "The foundational generation of firewalls that inspects individual packets in isolation without maintaining session or connection state.",
        "how_it_works": "Examines header fields of incoming and outgoing packets against a sequential list of rules. If a rule matches, the specified action (ALLOW or BLOCK) is executed immediately. Subsequent rules are bypassed (first-match policy).",
        "what_it_examines": "Source IP address, Destination IP address, IP protocol (TCP, UDP, ICMP), Source Port, Destination Port, and interface direction.",
        "advantages": [
            "Extremely fast and minimal CPU/memory overhead.",
            "Simple, transparent rule syntax easy to understand.",
            "Suitable for high-throughput edge routing filters."
        ],
        "limitations": [
            "Stateless: Cannot verify whether an incoming packet is part of an established legitimate connection.",
            "Vulnerable to IP spoofing and ACK-scan attacks.",
            "Cannot inspect application payload or detect malicious content inside valid protocols."
        ],
        "practical_example": "Dropping all incoming TCP packets targeting port 23 (Telnet) while permitting outbound HTTP traffic on port 80.",
        "sentinel_simulation_note": "Sentinel's implemented rule engine is an authentic educational simulation of rule-based packet filtering, featuring first-match evaluation, CIDR subnet matching, port range checks, and customizable default policies."
    },
    {
        "id": "stateful-inspection",
        "name": "2. Stateful Inspection Firewall",
        "definition": "An advanced firewall architecture that tracks the state of active network connections in a dynamic state table.",
        "how_it_works": "Monitors TCP handshakes (SYN, SYN-ACK, ACK), UDP pseudo-sessions, and ICMP query/response pairs. Packets matching an established session in the state table are automatically permitted without re-evaluating the full rule set.",
        "what_it_examines": "Packet headers, TCP sequence and acknowledgment numbers, TCP control flags (SYN, ACK, FIN, RST), and connection timers.",
        "advantages": [
            "Dramatically safer than stateless filtering; blocks unsolicited incoming packets.",
            "Dynamic port handling for protocols like FTP.",
            "Higher security with negligible latency after handshake verification."
        ],
        "limitations": [
            "State table exhaustion attacks (SYN flood, state starvation).",
            "Still cannot parse application-layer payloads or detect application-level exploits (e.g. SQL Injection over port 443)."
        ],
        "practical_example": "Permitting return web responses from an external web server only if an internal client initiated the outbound HTTP request first.",
        "sentinel_simulation_note": "Educational reference concept. While Sentinel logs session timestamps and connection flows, it clearly documents its packet processor as rule-based filtering rather than a kernel-level stateful proxy."
    },
    {
        "id": "application-level-gateway",
        "name": "3. Application-Level Gateway (Proxy Firewall)",
        "definition": "A dedicated security proxy that terminates client connections and regenerates requests to the destination server on behalf of the client.",
        "how_it_works": "Acts as an intermediary. The client connects to the proxy; the proxy validates application commands (e.g. HTTP GET, FTP RETR) before opening a separate connection to the actual target server.",
        "what_it_examines": "Full application-layer payloads, HTTP request headers, user-agents, URI strings, MIME types, and file transfers.",
        "advantages": [
            "Hides internal network addressing completely.",
            "Can enforce deep application protocol compliance and block malicious commands.",
            "Provides granular user authentication and payload content filtering."
        ],
        "limitations": [
            "High latency and compute overhead per connection.",
            "Requires specific proxy support for each protocol.",
            "Can become a major bottleneck in high-speed enterprise networks."
        ],
        "practical_example": "A corporate forward web proxy that inspects outgoing HTTP requests and strips risky HTTP headers or blocks file downloads exceeding 50 MB.",
        "sentinel_simulation_note": "Educational comparison concept explaining proxy isolation."
    },
    {
        "id": "next-generation-firewall",
        "name": "4. Next-Generation Firewall (NGFW)",
        "definition": "A modern multi-faceted security platform integrating stateful inspection with deep packet inspection (DPI), integrated IDS/IPS, TLS decryption, and identity-aware policies.",
        "how_it_works": "Disregards simple port numbers by identifying applications regardless of port (e.g., detecting BitTorrent running over port 80). Decrypts SSL/TLS traffic, scans for signatures and malware, correlates user directory identities (Active Directory/LDAP), and queries cloud threat intelligence.",
        "what_it_examines": "Encrypted payloads (via TLS inspection), application signatures, file heuristics, user identity, geolocation, and behavioral threat intelligence.",
        "advantages": [
            "Comprehensive unified threat management in a single platform.",
            "Deep visibility into encrypted application traffic and evasion techniques.",
            "Context-aware policies based on user identity rather than static IP addresses."
        ],
        "limitations": [
            "High cost and complex administrative maintenance.",
            "SSL/TLS decryption requires endpoint trust certificate deployment and raises privacy concerns.",
            "Heavy compute requirements requiring hardware acceleration (ASICs)."
        ],
        "practical_example": "Allowing employees to use Microsoft Teams for text chat while blocking file transfers within the same application, regardless of the port used.",
        "sentinel_simulation_note": "Educational concept illustrating the evolution of modern enterprise perimeter security."
    }
]

def seed_demo_data(db: Session, force_reset: bool = False):
    """
    Seeds initial demo rules, bastion hosts, and default config if not present.
    If force_reset is True, deletes existing demo records before re-inserting.
    """
    if force_reset:
        db.query(FirewallRule).delete()
        db.query(BastionHost).delete()
        db.commit()

    # Seed Default Firewall Policy
    set_default_firewall_policy(db, "BLOCK")

    # Seed demo firewall rules if none exist
    rule_count = db.query(FirewallRule).count()
    if rule_count == 0:
        for r_data in DEMO_FIREWALL_RULES:
            rule = FirewallRule(**r_data)
            db.add(rule)
        db.commit()

    # Seed demo bastion hosts if none exist
    bastion_count = db.query(BastionHost).count()
    if bastion_count == 0:
        for b_data in DEMO_BASTION_HOSTS:
            host = BastionHost(**b_data)
            db.add(host)
        db.commit()
