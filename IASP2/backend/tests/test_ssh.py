import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_ssh_full_flow():
    # 1. Start SSH
    start = client.post("/api/ssh/start", json={"client_version": "SSH-2.0-SecureTunnel_Client_1.0"})
    assert start.status_code == 200
    session_id = start.json()["session_id"]

    # 2. Step 1: Version exchange
    s1 = client.post(f"/api/ssh/{session_id}/step", json={"step": 1})
    assert s1.status_code == 200
    assert "OpenSSH" in s1.json()["crypto_values"]["server_banner"]

    # 3. Step 2: Algorithm negotiation
    s2 = client.post(f"/api/ssh/{session_id}/step", json={"step": 2})
    assert s2.status_code == 200
    assert "curve25519" in s2.json()["crypto_values"]["negotiated_kex"]

    # 4. Step 3: Diffie-Hellman Key Exchange
    s3 = client.post(f"/api/ssh/{session_id}/step", json={"step": 3})
    assert s3.status_code == 200
    assert "derived_shared_secret_k" in s3.json()["crypto_values"]

    # 5. Step 4: Server Authentication (Trusted host)
    s4 = client.post(f"/api/ssh/{session_id}/step", json={"step": 4, "host_key_scenario": "trusted"})
    assert s4.status_code == 200
    assert s4.json()["verification_status"]["valid"] is True

    # 6. Step 5: Session Key Derivation (RFC 4253 'A'..'F')
    s5 = client.post(f"/api/ssh/{session_id}/step", json={"step": 5})
    assert s5.status_code == 200
    assert "key_C_client_enc_key" in s5.json()["crypto_values"]

    # 7. Step 6: User Authentication Overview
    s6 = client.post(f"/api/ssh/{session_id}/step", json={"step": 6})
    assert s6.status_code == 200

    # Test user auth with invalid password
    bad_auth = client.post(
        f"/api/ssh/{session_id}/authenticate",
        json={"auth_method": "password", "username": "student", "password": "wrongpassword"}
    )
    assert bad_auth.status_code == 200
    assert bad_auth.json()["success"] is False

    # Test user auth with valid demo password
    good_auth = client.post(
        f"/api/ssh/{session_id}/authenticate",
        json={"auth_method": "password", "username": "student", "password": "cyber2026"}
    )
    assert good_auth.status_code == 200
    assert good_auth.json()["success"] is True

    # 8. Step 7: Shell session
    s7 = client.post(f"/api/ssh/{session_id}/step", json={"step": 7})
    assert s7.status_code == 200
    assert s7.json()["protocol_state"] == "established"

    # 9. Send shell command
    cmd_resp = client.post(
        f"/api/ssh/{session_id}/application-data",
        json={"command": "whoami", "tamper_packet": False}
    )
    assert cmd_resp.status_code == 200
    assert "student" in cmd_resp.json()["output"]

    # 10. Send tampered shell command
    tamper_cmd = client.post(
        f"/api/ssh/{session_id}/application-data",
        json={"command": "whoami", "tamper_packet": True}
    )
    assert tamper_cmd.status_code == 200
    assert tamper_cmd.json()["success"] is False
    assert "Corrupted packet" in tamper_cmd.json()["output"]

def test_ssh_host_key_mismatch():
    start = client.post("/api/ssh/start", json={})
    session_id = start.json()["session_id"]
    client.post(f"/api/ssh/{session_id}/step", json={"step": 1})
    client.post(f"/api/ssh/{session_id}/step", json={"step": 2})
    client.post(f"/api/ssh/{session_id}/step", json={"step": 3})

    # Host key changed scenario
    s4_fail = client.post(f"/api/ssh/{session_id}/step", json={"step": 4, "host_key_scenario": "changed_mismatch"})
    assert s4_fail.status_code == 200
    assert s4_fail.json()["protocol_state"] == "failed"
    assert "MISMATCH" in s4_fail.json()["step_title"]
