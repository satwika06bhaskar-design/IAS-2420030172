
# SENTINEL — Intrusion Detection & Firewall Simulator

Sentinel is a comprehensive, full-stack educational cybersecurity web application designed to demonstrate the fundamentals of network perimeter defense, rule-based packet filtering, deterministic signature-based intrusion detection (IDS), and statistical anomaly detection.

> **EDUCATIONAL SIMULATION DISCLAIMER**  
> Sentinel is an educational simulation platform. All network traffic, IP packets, threat events, and bastion host telemetry are simulated entirely within an in-memory/SQLite database pipeline. The application does not capture live raw network packets, inspect real host adapters, execute malicious code, or alter operating system firewall tables. It does not replace a commercial enterprise firewall or production Security Information and Event Management (SIEM) system.

---

## 1. KEY FEATURES

### 🛡️ Firewall Rule Manager & Packet Inspection Engine
- **First-Match Rule Evaluation Policy:** Evaluates enabled firewall rules in ascending priority order (lower number = evaluated first).
- **Subnet & Range Support:** Supports individual IPv4 addresses, CIDR notation (e.g. `192.168.1.0/24`), protocol filters (`TCP`, `UDP`, `ICMP`, `ANY`), and destination port ranges (e.g. `80-443`).
- **Configurable Fallback Default:** Toggleable default policy (`BLOCK` or `ALLOW`) applied when no rule matches.
- **Rule Management:** Add, edit, delete, enable/disable, search, filter, and sort rules with database persistence.
- **Visual Packet Journey Inspector:** 4-step sequence (`Packet Generated ➔ Rules Inspected ➔ Firewall Decision ➔ Final Result`) with step-by-step sequential audit log and plain English explanations.

### 🚨 Dual-Engine Intrusion Detection System (IDS)
Sentinel incorporates two distinct detection paradigms:

#### A. Rule-Based Signature IDS
1. **Rule 1 (SSH Brute Force):** Generates `CRITICAL` alert upon \(\ge 5\) failed SSH authentication attempts from the same source IP within a rolling 60-second window.
2. **Rule 2 (Suspicious Telnet):** Generates `HIGH` alert upon any TCP traffic targeting unencrypted Telnet port 23.
3. **Rule 3 (Port Scanning):** Generates `HIGH` alert when a source IP attempts connections to \(\ge 10\) distinct destination ports within 60 seconds.
4. **Rule 4 (Excessive Packet Volume):** Generates `MEDIUM` alert when packet volume from a source IP exceeds the configurable threshold within 60 seconds.
5. **Rule 5 (Repeated Firewall Denials):** Generates `MEDIUM` alert when \(\ge 5\) packets from a source IP are dropped by firewall rules within 60 seconds.
- **Dynamic Threshold Tuning:** Configure all rule thresholds and rolling window duration through the UI.
- **Deduplication:** Automatic suppression prevents alert flooding for subsequent packets within active windows.

#### B. Statistical Anomaly Detection Engine (Python & NumPy)
- Computes baseline statistical Mean (\(\mu\)) and Sample Standard Deviation (\(\sigma\)) using NumPy:
  $$\text{Upper Threshold} = \mu + K \cdot \sigma$$
- Tracks 3 core metrics:
  1. Packets per second from source IP (`PACKETS_PER_SECOND`)
  2. SSH login attempts per minute (`SSH_ATTEMPTS_PER_MIN`)
  3. Bytes transferred bandwidth volume (`BYTES_TRANSFERRED`)
- Configurable \(K\) multiplier (default \(3.0\), three-sigma rule).
- Optional **Two-Sided Detection** for anomalous drops (e.g. heartbeat loss).
- Automatically triggers a `Statistical Anomaly Detection` IDS alert when observed metrics breach the statistical baseline.

### 🌐 Network Traffic Simulator
- **6 Predefined Scenarios:**
  1. *Normal HTTP Web Traffic* (legitimate web traffic)
  2. *Failed SSH Login Attempts* (triggers Rule 1)
  3. *Suspicious Telnet Traffic* (triggers Rule 2)
  4. *Port Scan Reconnaissance* (triggers Rule 3)
  5. *High-Volume Packet Burst* (triggers Rule 4 & Anomaly spike)
  6. *Large Data Transfer* (bandwidth metric spike)
- **Custom Packet Injector:** Custom source/dest IP, port, protocol, size, SSH auth outcome, and transmission rate.
- **Live Stream Generator:** Continuous background packet injection with start, pause, resume, and stop controls.
- **Full Pipeline Audit Log:** Live-updating event table displaying decisions, matched rules, and IDS findings.

### 🏰 Bastion Host Perimeter Architecture
- Interactive visual mediation diagram:
  `External Untrusted Network` ──> `Hardened Bastion Jump Host` ──> `Protected Internal Enclave`
- Bastion Host configuration CRUD: simulated IP, purpose, allowed management protocol/port, MFA access status, and SIEM monitoring status.
- **Interactive Connection Verification Tool:** Simulates external admin connection tests, verifies host operational status, port binding, and MFA challenge requirements.
- Educational hardening principles (least privilege, MFA enforcement, service minimization, session recording).

### 📚 Threat Encyclopedia & Firewall Concepts
- **Threat Encyclopedia:** In-depth catalog of Threat Actors/Intruders, File-Infector Viruses, Boot-Sector Viruses, Macro Viruses, Network Worms, Email Worms, and False Positives vs. False Negatives.
- **Protocol & Firewall Concepts:** Architectural breakdown and comparison matrix across the 4 generations:
  1. Packet-Filtering Firewall (Stateless)
  2. Stateful Inspection Firewall
  3. Application-Level Gateway (Proxy)
  4. Next-Generation Firewall (NGFW)

---

## 2. TECHNOLOGY STACK

| Component | Technology | Version | Purpose |
|---|---|---|---|
| **Frontend Framework** | React + Vite | React 19, Vite 8 | UI components & high-speed development server |
| **Routing** | React Router DOM | v7 | Client-side navigation & route parameters |
| **Data Visualization** | Recharts | v3 | Interactive time-series, Area, Line, and Donut charts |
| **Iconography** | Lucide React | v1.61 | Cohesive cybersecurity iconography |
| **Backend Framework** | Python & FastAPI | Python 3.12, FastAPI 0.162 | Asynchronous REST API with auto OpenAPI docs |
| **ORM & Database** | SQLAlchemy & SQLite | SQLAlchemy 2.1 | Persistent relational storage with indexes |
| **Numerical Computing**| NumPy | NumPy 2.5 | Vectorized baseline mean, std dev, and z-score calculations |
| **Request Validation** | Pydantic v2 | Pydantic 2.14 | CIDR subnet, IPv4, and port range validation |
| **Testing** | Pytest | Pytest 9.1 | Automated test suite verifying all 12 criteria |

---

## 3. PROJECT DIRECTORY STRUCTURE

```
d:/IASP3/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                     # FastAPI application & CORS setup
│   │   ├── database.py                 # SQLite engine & SessionLocal
│   │   ├── models/                     # SQLAlchemy ORM models
│   │   │   ├── __init__.py
│   │   │   ├── firewall_rule.py
│   │   │   ├── bastion_host.py
│   │   │   ├── traffic_event.py
│   │   │   ├── ids_alert.py
│   │   │   └── system_config.py
│   │   ├── schemas/                    # Pydantic validation schemas
│   │   │   ├── __init__.py
│   │   │   ├── firewall.py
│   │   │   ├── bastion.py
│   │   │   ├── traffic.py
│   │   │   ├── ids.py
│   │   │   ├── anomaly.py
│   │   │   └── educational.py
│   │   ├── services/                   # Core business logic engines
│   │   │   ├── __init__.py
│   │   │   ├── firewall_engine.py      # First-match packet evaluation
│   │   │   ├── rule_based_ids.py       # Rolling-window signature rules
│   │   │   ├── anomaly_detector.py     # NumPy baseline z-score engine
│   │   │   ├── traffic_simulator.py    # 9-step unified processing pipeline
│   │   │   └── seed_data.py            # Baseline demo rules & encyclopedia
│   │   └── routers/                    # API route endpoints
│   │       ├── __init__.py
│   │       ├── firewall.py
│   │       ├── bastion.py
│   │       ├── traffic.py
│   │       ├── ids.py
│   │       ├── anomaly.py
│   │       ├── educational.py
│   │       └── demo.py
│   ├── tests/
│   │   └── test_all_requirements.py    # Pytest verifying tests 1-12
│   ├── requirements.txt
│   └── sentinel.db                     # SQLite persistent database
├── frontend/
│   ├── src/
│   │   ├── components/                 # Reusable UI components
│   │   │   ├── ConfirmationModal.jsx
│   │   │   ├── EmptyState.jsx
│   │   │   └── PacketJourneyVisualizer.jsx
│   │   ├── layouts/
│   │   │   └── MainLayout.jsx          # Sidebar, header, disclaimer
│   │   ├── pages/                      # 9 application pages
│   │   │   ├── OverviewPage.jsx
│   │   │   ├── FirewallPage.jsx
│   │   │   ├── TrafficPage.jsx
│   │   │   ├── IDSPage.jsx
│   │   │   ├── AnomalyPage.jsx
│   │   │   ├── BastionPage.jsx
│   │   │   ├── EncyclopediaPage.jsx
│   │   │   ├── ConceptsPage.jsx
│   │   │   └── AboutPage.jsx
│   │   ├── services/
│   │   │   └── api.js                  # Frontend API integration service
│   │   ├── styles/
│   │   │   └── index.css               # Professional light theme CSS variables
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
└── README.md
```

---

## 4. PREREQUISITES

- **Python:** 3.10 or higher (3.12 recommended)
- **Node.js:** v18 or higher (v22 recommended)
- **npm:** v9 or higher

---

## 5. INSTALLATION & SETUP

### Step 1: Install Backend Dependencies
```bash
cd backend
pip install -r requirements.txt
```

### Step 2: Install Frontend Dependencies
```bash
cd ../frontend
npm install
```

---

## 6. RUNNING THE APPLICATION

### 1. Launch Backend API Server
In the `backend` directory, start the Uvicorn server:
```bash
cd backend
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
- API Base URL: `http://127.0.0.1:8000`
- Interactive OpenAPI Docs: `http://127.0.0.1:8000/docs`
- Health Check: `http://127.0.0.1:8000/api/health`

### 2. Launch Frontend Development Server
In a new terminal window, start the Vite development server:
```bash
cd frontend
npm run dev
```
- Frontend Web Interface: `http://localhost:5173`

---

## 7. RUNNING AUTOMATED BACKEND TESTS

To execute the automated test suite verifying all 12 mandatory evaluation criteria:

```bash
cd backend
python -m pytest tests/test_all_requirements.py -v
```

### Test Suite Verification Results:
- `test_blocked_source_ip` — **PASSED**: Verifies packet from blocked source IP `192.168.1.100` is denied (`BLOCK`).
- `test_allowed_http_traffic` — **PASSED**: Verifies valid HTTP TCP port 80 packet is permitted (`ALLOW`).
- `test_rule_priority` — **PASSED**: Confirms first applicable rule in ascending priority determines decision.
- `test_disabled_rule` — **PASSED**: Confirms disabled rules do not interfere with packet processing.
- `test_failed_ssh_login_detection` — **PASSED**: Verifies 5 failed SSH logins in 60s trigger `SSH_BRUTE_FORCE` alert.
- `test_telnet_detection` — **PASSED**: Verifies TCP traffic to port 23 generates `SUSPICIOUS_TELNET` alert.
- `test_port_scan_detection` — **PASSED**: Verifies connection attempts across 10 distinct ports generate `PORT_SCAN` alert.
- `test_statistical_anomaly_detection` — **PASSED**: Calculates NumPy baseline and detects sudden packet rate anomalies.
- `test_bastion_host_persistence` — **PASSED**: Verifies bastion host configurations survive database queries and restarts.
- `test_rule_persistence` — **PASSED**: Verifies firewall rules survive database queries and restarts.
- `test_input_validation` — **PASSED**: Rejects invalid IP formats, malformed CIDR subnets, and out-of-range ports with HTTP 422.
- `test_api_endpoints_integration` — **PASSED**: Verifies all REST endpoints return real data to frontend.

---

## 8. DEMONSTRATION WORKFLOW FOR STUDENTS & INSTRUCTORS

1. **Initialize Sample Data:**
   - Click the **"Load Demo Data"** button in the top navigation header.
   - Sentinel populates baseline normal web traffic, Telnet probes, and SSH attempts.
2. **Explore the Overview Dashboard:**
   - Observe the live KPI summary cards, time-series traffic activity chart, and allowed vs. blocked donut breakdown.
3. **Firewall Manager & Packet Testing:**
   - Navigate to **Firewall Manager**.
   - Review active rules sorted by priority (`#10 Block Malicious IP`, `#20 Block Telnet`, `#30 Allow HTTP`, `#40 Allow HTTPS`).
   - Scroll down to the **Live Packet Processing & Inspection Engine**.
   - Click preset **"Standard HTTP Traffic"** ➔ click **"Simulate Packet"** ➔ observe step-by-step evaluation result: **ALLOW**.
   - Click preset **"Telnet Legacy Probe"** ➔ click **"Simulate Packet"** ➔ observe result: **BLOCK** (matched Rule #20).
4. **Trigger Threat Scenarios in Traffic Simulator:**
   - Navigate to **Traffic Simulator**.
   - Click **"Start"** on *Scenario 2: Failed SSH Login Attempts*.
   - Click **"Start"** on *Scenario 4: Port Scan Reconnaissance*.
   - Click **"Start"** on *Scenario 5: High-Volume Packet Burst*.
   - Watch the live event table update with decisions and generated alerts.
5. **Inspect Detections in IDS Dashboard:**
   - Navigate to **IDS Dashboard**.
   - View newly generated alerts (`SSH_BRUTE_FORCE`, `PORT_SCAN`, `EXCESSIVE_VOLUME`).
   - Click on any alert to open the **Alert Details Drawer** and inspect the triggering packet snapshot.
   - Click **"Configure Thresholds"** to dynamically modify detection parameters.
6. **Analyze Statistical Anomaly Detection:**
   - Navigate to **Anomaly Detection**.
   - Observe the rolling Mean (\(\mu\)), Standard Deviation (\(\sigma\)), and Upper Threshold line (\(\mu + K\sigma\)).
   - Adjust the **K Factor** slider to demonstrate how changing threshold sensitivity alters detection rates.
7. **Verify Bastion Host Mediation:**
   - Navigate to **Bastion Host**.
   - Review the visual network topology diagram.
   - Use the **Interactive Access Verification Tool** to test connections on port 22 (SSH - Allowed with MFA challenge) vs port 23 (Telnet - Rejected).
8. **Study Educational References:**
   - Navigate to **Threat Encyclopedia** and **Protocol & Firewall Concepts** for academic explanations, comparison matrices, and mitigation techniques.
=======
# Information Assurance and Security (IAS)

## Student Details

**Name:** P. SATWIKA REDDY  
**Roll Number:** 2420030172  
**Section:** 11  

**GitHub Repository:**  
https://github.com/satwika06bhaskar-design/IAS-2420030172.git

---

# TASK 1 – Cryptography and Secure File Transfer

Task 1 implements three cryptographic techniques using Python:

1. Caesar Cipher
2. Playfair Cipher
3. SDES / DES File Transfer

The task demonstrates encryption, decryption, client-server communication, and secure transfer of text and binary files.

## Task 1 Project Structure

```text
IAS-2420030172/
│
├── README.md
│
├── TASK-1/
│   │
│   ├── Caesar/
│   │   ├── client.py
│   │   └── server.py
│   │
│   ├── Playfair/
│   │   ├── client.py
│   │   └── server.py
│   │
│   └── SDES/
│       ├── client.py
│       ├── server.py
│       │
│       └── files/
│           ├── client_1MB.pdf
│           └── server_10KB.bin
│
└── TASK-2/
    │
    └── AES/
        ├── client.py
        ├── server.py
        │
        ├── files/
        │   │
        │   ├── CLIENT_TO_SERVER/
        │   │   ├── client_10KB.txt
        │   │   ├── client_document.pdf
        │   │   ├── client_document.docx
        │   │   ├── image.jpg
        │   │   └── test.bin
        │   │
        │   └── SERVER_TO_CLIENT/
        │       ├── server_5KB.txt
        │       ├── server_document.pdf
        │       ├── server_document.docx
        │       ├── image.png
        │       └── test.bin
        │
        └── screenshots/
            ├── starting_server_client.jpg
            ├── client_to_server.jpg
            └── server_to_client.jpg

