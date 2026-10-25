# Integrated Application Security Projects

This repository contains two cybersecurity projects developed for academic learning and demonstration.

## 1. IASP2 — SecureTunnel: Secure Communication Protocol Simulator

### Project Overview
SecureTunnel is an educational cybersecurity web application that simulates secure communication protocols, including TLS, SSH, and IPsec. It demonstrates encryption concepts, authentication mechanisms, secure key exchange, and network communication security through an interactive interface.

### Key Features
- **TLS Simulation:** Demonstrates TLS 1.2 RSA key exchange and TLS 1.3 Diffie–Hellman key exchange.
- **SSH Simulation:** Demonstrates password-based and key-based authentication and command execution.
- **IPsec Simulation:** Explains ESP Transport and Tunnel modes.
- **Interactive Interface:** Visualizes protocol operations and security concepts.

### Technology Stack
- **Frontend:** React, Vite, JavaScript, Tailwind CSS, Axios, React Flow, Lucide React, Recharts.
- **Backend:** Python, FastAPI, Uvicorn, Pydantic.
- **Security and Storage:** Python cryptography library and optional SQLite.
- **Testing:** Vitest, React Testing Library, pytest.

### How to Run
**Backend:**
```bash
cd IASP2/backend
python -m uvicorn app.main:app --reload
```

**Frontend** (open a separate terminal):
```bash
cd IASP2/frontend
npm install
npm run dev
```

---

## 2. IASP3 — Sentinel: Intrusion Detection & Firewall Simulator

### Project Overview
Sentinel is an educational cybersecurity web application designed to simulate network perimeter defense, rule-based packet filtering, signature-based Intrusion Detection Systems (IDS), and statistical anomaly detection.

It demonstrates how firewall policies, intrusion detection rules, traffic monitoring, and bastion host configurations work together.

**Educational Simulation Notice:** All network traffic, packets, IP addresses, threat alerts, and bastion host configurations are simulated in software. Sentinel does not capture real network packets, run live exploits, or modify the host operating system's firewall rules.

### Key Features
- **Firewall Management:** Create, update, delete, enable, and disable firewall rules.
- **First-Match Packet Filtering:** Evaluates enabled rules in ascending priority order and applies the first matching action.
- **Rule-Based IDS:** Detects simulated SSH brute-force attempts, suspicious Telnet connections, port scans, excessive traffic, and repeated firewall denials.
- **Statistical Anomaly Detection:** Uses NumPy to calculate traffic baselines, standard deviations, and configurable detection thresholds.
- **Traffic Simulation:** Runs predefined traffic and attack scenarios.
- **Alert Management:** Displays alerts, severity levels, triggering events, and acknowledgement status.
- **Bastion Host Simulation:** Demonstrates controlled access between external and protected internal networks.
- **Threat Encyclopedia:** Provides educational references about common threats and defensive countermeasures.
- **Interactive Dashboard:** Visualizes traffic statistics, firewall decisions, alerts, and anomaly metrics.
- **Automated Testing:** Includes pytest tests for firewall behavior, IDS detection, database persistence, input validation, and API integration.

### Technology Stack
- **Frontend:** React, Vite, React Router DOM, Recharts, Lucide React.
- **Backend:** Python, FastAPI, Uvicorn, Pydantic.
- **Database:** SQLite and SQLAlchemy.
- **Numerical Processing:** NumPy.
- **Testing:** pytest and HTTPX.

### How to Run
**Backend:**
```powershell
cd IASP3/backend
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

**Frontend** (open a separate terminal):
```powershell
cd IASP3/frontend
npm install
npm run dev
```

Open the application at `http://localhost:5173`.

Backend API documentation: `http://127.0.0.1:8000/docs`

**Run the tests:**
```powershell
cd IASP3/backend
python -m pytest tests/test_all_requirements.py -v
```

### Demonstration Scenarios
- Test firewall decisions for allowed HTTP traffic and blocked traffic.
- Simulate repeated failed SSH logins and suspicious Telnet connections.
- Run port-scanning and high-volume traffic scenarios.
- Inspect IDS alerts and adjust detection thresholds.
- Analyze traffic baselines and statistical anomaly metrics.
- Test simulated bastion host access controls.

---

## Repository Structure

```text
IAS-2420030172/
├── README.md
├── IASP2/
│   ├── backend/
│   ├── frontend/
│   ├── docs/
│   ├── package.json
│   └── ...
├── IASP3/
│   ├── backend/
│   ├── frontend/
│   ├── .gitignore
│   ├── README.md
│   └── ...
├── ALL/
├── TASK-1/
└── TASK-2/
```

## Learning Outcomes
- Understand secure communication protocols such as TLS, SSH, and IPsec.
- Learn firewall rule evaluation and packet filtering concepts.
- Understand signature-based intrusion detection and statistical anomaly detection.
- Explore simulated traffic monitoring, alert management, and bastion host security.

## Disclaimer
Both projects are intended for educational purposes and cybersecurity demonstrations. Their simulations do not replace production security systems or real-world network protection tools.
