# SecureTunnel — Learn How Secure Communication Works

SecureTunnel is an educational web application that explains how Transport Layer Security (TLS), Secure Shell (SSH), and Internet Protocol Security (IPsec) protect communication between computers. Students can explore each process step by step using simple diagrams and clear explanations.

---

## 1. Project Overview

- **Beginner-Friendly Design**: Clean, light theme with readable text, simple diagrams, and easy-to-understand explanations suitable for undergraduate students.
- **Top Navigation**: Simple top navigation bar with:
  - **Home**: Project description, three large module cards with **Explore** buttons, and educational notice.
  - **TLS Handshake**: Demonstrates how a browser and website establish secure symmetric session keys using TLS 1.2 (RSA) or modern TLS 1.3 (Diffie–Hellman).
  - **SSH Connection**: Demonstrates version exchange, algorithm negotiation, Diffie–Hellman key exchange, server authentication, and user authentication.
  - **IPsec**: Demonstrates network-layer packet encapsulation in Transport Mode vs Tunnel Mode with an interactive packet component inspector.
  - **Compare Protocols**: Clear side-by-side comparison table (TLS vs SSH vs IPsec) and simple everyday examples.
  - **Learn Concepts**: Beginner-friendly glossary of 24 core terms with simple meanings, short examples, and the module where each is used.

---

## 2. Technology Stack

- **Frontend**: React 18 with Vite, JavaScript, Tailwind CSS (clean light theme with blue accents), Axios, and Lucide React icons.
- **Backend**: Python 3.12, FastAPI, Uvicorn, Pydantic, and the PyCA `cryptography` library for real cryptographic operations (AES-GCM, RSA, X25519, Ed25519, X.509).
- **Testing**: `pytest` for backend tests (17 passed) and `vitest` with React Testing Library for frontend tests (9 passed).

---

## 3. How to Run on Windows

Open two Windows PowerShell terminals:

### Terminal 1 — Start the Python FastAPI Backend:
```powershell
cd d:\IASP2\backend
.\venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
- API Base URL: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- Interactive Documentation: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### Terminal 2 — Start the React Frontend:
```powershell
cd d:\IASP2\frontend
npm run dev
```
- Open in your browser: [http://localhost:5173](http://localhost:5173)

---

## 4. One-Click Launch (from Project Root)

From `d:\IASP2`, you can also double-click:
```
run.bat
```
or run in PowerShell:
```powershell
.\run.ps1
```

---

## 5. Running the Automated Tests

### Backend Tests:
```powershell
cd d:\IASP2\backend
.\venv\Scripts\pytest -v tests
```

### Frontend Tests:
```powershell
cd d:\IASP2\frontend
npx vitest run
```

---

## 6. Educational Disclaimer

*This project is an educational simulation. It does not replace real-world security software.*
