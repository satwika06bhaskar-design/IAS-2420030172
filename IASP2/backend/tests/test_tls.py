import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_tls12_full_handshake_flow():
    # 1. Start session
    start_resp = client.post("/api/tls/start", json={"mode": "tls12_rsa"})
    assert start_resp.status_code == 200
    session_id = start_resp.json()["session_id"]

    # 2. Step 1: Client Hello
    s1 = client.post(f"/api/tls/{session_id}/step", json={"step": 1})
    assert s1.status_code == 200
    assert s1.json()["current_step"] == 1
    assert "client_random_hex" in s1.json()["crypto_values"]

    # 3. Step 2: Server Hello & Cert
    s2 = client.post(f"/api/tls/{session_id}/step", json={"step": 2})
    assert s2.status_code == 200
    assert s2.json()["current_step"] == 2
    assert "certificate_fingerprint" in s2.json()["crypto_values"]

    # 4. Step 3: Certificate Verification
    s3 = client.post(f"/api/tls/{session_id}/step", json={"step": 3})
    assert s3.status_code == 200
    assert s3.json()["verification_status"]["signature_valid"] is True

    # 5. Step 4: Client Key Exchange
    s4 = client.post(f"/api/tls/{session_id}/step", json={"step": 4})
    assert s4.status_code == 200
    assert s4.json()["crypto_values"]["server_decryption_match"] is True

    # 6. Step 5: Master Secret & Key Derivation
    s5 = client.post(f"/api/tls/{session_id}/step", json={"step": 5})
    assert s5.status_code == 200
    assert "master_secret_preview" in s5.json()["crypto_values"]
    assert "client_write_key_preview" in s5.json()["crypto_values"]

    # 7. Step 6: Finished Messages
    s6 = client.post(f"/api/tls/{session_id}/step", json={"step": 6})
    assert s6.status_code == 200
    assert s6.json()["protocol_state"] == "established"

    # 8. Step 7: Encrypted Application Data view
    s7 = client.post(f"/api/tls/{session_id}/step", json={"step": 7})
    assert s7.status_code == 200

    # 9. Send application data
    app_data_resp = client.post(
        f"/api/tls/{session_id}/application-data",
        json={"message": "GET /dashboard HTTP/1.1", "tamper_ciphertext": False}
    )
    assert app_data_resp.status_code == 200
    app_data = app_data_resp.json()
    assert app_data["success"] is True
    assert app_data["decrypted_plaintext"] == "GET /dashboard HTTP/1.1"

    # 10. Send tampered application data
    tampered_resp = client.post(
        f"/api/tls/{session_id}/application-data",
        json={"message": "Sensitive Transaction", "tamper_ciphertext": True}
    )
    assert tampered_resp.status_code == 200
    assert tampered_resp.json()["success"] is False
    assert "Authentication tag verification failed" in tampered_resp.json()["error"]

def test_tls_invalid_step_jump():
    start_resp = client.post("/api/tls/start", json={"mode": "tls12_rsa"})
    session_id = start_resp.json()["session_id"]

    # Attempt to skip to step 4 without step 1
    bad_step = client.post(f"/api/tls/{session_id}/step", json={"step": 4})
    assert bad_step.status_code == 400
    assert "Invalid step sequence" in bad_step.json()["detail"]

def test_tls13_handshake_flow():
    start_resp = client.post("/api/tls/start", json={"mode": "tls13_dhe"})
    session_id = start_resp.json()["session_id"]

    # Step 1: ClientHello + key_share
    s1 = client.post(f"/api/tls/{session_id}/step", json={"step": 1})
    assert s1.status_code == 200
    assert "client_key_share_hex" in s1.json()["crypto_values"]

    # Step 2: ServerHello + key_share
    s2 = client.post(f"/api/tls/{session_id}/step", json={"step": 2})
    assert s2.status_code == 200
    assert "server_key_share_hex" in s2.json()["crypto_values"]

    # Step 3: ECDH Shared secret
    s3 = client.post(f"/api/tls/{session_id}/step", json={"step": 3})
    assert s3.status_code == 200
    assert s3.json()["crypto_values"]["keys_match"] is True

    # Step 4: HKDF key schedule
    s4 = client.post(f"/api/tls/{session_id}/step", json={"step": 4})
    assert s4.status_code == 200
    assert "handshake_secret_preview" in s4.json()["crypto_values"]

    # Step 5: Encrypted Extensions & Certificate
    s5 = client.post(f"/api/tls/{session_id}/step", json={"step": 5})
    assert s5.status_code == 200
    assert s5.json()["crypto_values"]["certificate_encrypted_in_transit"] is True

    # Step 6: Finished & Application Keys
    s6 = client.post(f"/api/tls/{session_id}/step", json={"step": 6})
    assert s6.status_code == 200
    assert s6.json()["protocol_state"] == "established"
