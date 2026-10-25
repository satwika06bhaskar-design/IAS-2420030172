# Information Assurance and Security Projects

This repository contains projects developed as part of the Information Assurance and Security (IAS) coursework.

## Projects

### 1. IASP2 – SecureTunnel: Secure Communication Protocol Simulator

**Folder:** `IASP2/`

SecureTunnel is an educational web application that demonstrates how three fundamental security protocols work: TLS (Transport Layer Security), SSH (Secure Shell), and IPsec (Encapsulating Security Payload).

**Key Features**
- TLS 1.2 RSA key exchange and TLS 1.3 Diffie–Hellman handshake visualization.
- SSH password and key-based authentication simulations.
- IPsec ESP Transport and Tunnel mode demonstrations.
- Interactive cryptographic operations, message encryption, and protocol comparisons.
- Searchable glossary of security and cryptography concepts.

**Technology Stack:** React, Vite, JavaScript, Tailwind CSS, Python, FastAPI, Uvicorn, and the Python `cryptography` library.

**Purpose:** To help students understand secure communication protocols through interactive, step-by-step visualizations.

**Note:** SecureTunnel is an educational simulator, not a production security solution. It does not protect real network traffic.

### 2. IASP3 – Sentinel: Network Security Monitoring and Threat Detection

**Folder:** `IASP3/`

Sentinel is a network security application that demonstrates network monitoring, threat detection, and security management concepts.

**Key Features**
- Intrusion Detection System (IDS) demonstrations.
- Firewall rule management and evaluation.
- Network traffic simulation and visualization.
- Anomaly detection for unusual traffic patterns.
- Bastion host management demonstrations.

**Technology Stack:** React, JavaScript, Python, and FastAPI.

**Purpose:** To demonstrate network security monitoring and threat detection concepts through an interactive web application.

## Repository Structure

```text
IAS-2420030172/
├── IASP2/
│   ├── backend/
│   ├── frontend/
│   ├── docs/
│   ├── package.json
│   ├── run.bat
│   ├── run.ps1
│   └── README.md
├── IASP3/
│   ├── backend/
│   ├── frontend/
│   └── README.md
├── ALL/
├── TASK-1/
├── TASK-2/
└── README.md
```

## Technologies Used

- **Frontend:** React, Vite, JavaScript
- **Backend:** Python, FastAPI
- **Security Concepts:** TLS, SSH, IPsec, firewalls, intrusion detection, and anomaly detection
- **Testing:** pytest, Vitest, and React Testing Library

## Objectives

- Understand fundamental information assurance and network security concepts.
- Explore secure communication protocols and cryptographic operations.
- Demonstrate network monitoring, firewall management, and intrusion detection.
- Develop interactive applications for security education.

## Disclaimer

These projects are intended for educational and demonstration purposes. Simulated security operations should not be considered a replacement for production-grade security systems.

