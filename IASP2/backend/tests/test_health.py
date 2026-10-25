import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "SecureTunnel" in data["service"]

def test_learning_glossary_endpoint():
    response = client.get("/api/learning/glossary")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 24
    terms = [item["term"] for item in data["terms"]]
    assert "Plaintext" in terms
    assert "Ciphertext" in terms
    assert "RSA" in terms
    assert "Diffie–Hellman" in terms
    assert "Pre-Master Secret (PMS)" in terms

def test_protocol_comparison_endpoint():
    response = client.get("/api/learning/protocols")
    assert response.status_code == 200
    data = response.json()
    assert "protocols" in data
    assert len(data["protocols"]) == 3
