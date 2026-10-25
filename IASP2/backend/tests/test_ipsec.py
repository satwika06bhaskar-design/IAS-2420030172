import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_ipsec_transport_encapsulation():
    payload = {
        "mode": "transport",
        "packet": {
            "src_ip": "192.168.1.10",
            "dst_ip": "10.0.0.5",
            "protocol": "TCP",
            "src_port": 54321,
            "dst_port": 443,
            "payload": "Educational Transport Mode Test"
        },
        "spi": 0x12345678,
        "seq_num": 42
    }
    resp = client.post("/api/ipsec/encapsulate", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["mode"] == "transport"
    assert "Original IPv4 Header" in [c["name"] for c in data["encapsulated_packet"]["components"]]
    assert "ESP Header" in [c["name"] for c in data["encapsulated_packet"]["components"]]
    assert "ESP ICV (Authentication Tag)" in [c["name"] for c in data["encapsulated_packet"]["components"]]

def test_ipsec_tunnel_encapsulation():
    payload = {
        "mode": "tunnel",
        "packet": {
            "src_ip": "10.1.1.20",
            "dst_ip": "10.2.2.30",
            "protocol": "TCP",
            "src_port": 60000,
            "dst_port": 80,
            "payload": "Secret Inner Datagram"
        },
        "spi": 0x99998888,
        "seq_num": 1,
        "tunnel_gateway_src": "198.51.100.1",
        "tunnel_gateway_dst": "203.0.113.1"
    }
    resp = client.post("/api/ipsec/encapsulate", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["mode"] == "tunnel"
    assert "New Outer IPv4 Header" in [c["name"] for c in data["encapsulated_packet"]["components"]]
    assert "Encrypted Inner Packet (Original IP + TCP + Data)" in [c["name"] for c in data["encapsulated_packet"]["components"]]

def test_ipsec_inspect_field():
    resp = client.post("/api/ipsec/inspect", json={"field_id": "esp_icv", "mode": "tunnel"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_authenticated"] is True
    assert data["is_encrypted"] is False
    assert "Integrity Check Value" in data["name"]
    assert "ESP Authentication" in data["layer"]
