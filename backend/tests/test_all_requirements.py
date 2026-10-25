import pytest
import datetime
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.main import app
from app.models.firewall_rule import FirewallRule
from app.models.bastion_host import BastionHost
from app.models.traffic_event import TrafficEvent
from app.models.ids_alert import IDSAlert
from app.services.firewall_engine import evaluate_packet
from app.services.traffic_simulator import process_single_packet, run_scenario
from app.services.anomaly_detector import calculate_anomaly_stats

# Use an isolated test database
TEST_DB_URL = "sqlite:///./test_sentinel.db"
test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(autouse=True)
def setup_database():
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

@pytest.fixture
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

# TEST 1: Blocked source IP
def test_blocked_source_ip(db_session):
    rule = FirewallRule(
        name="Block IP 192.168.1.100",
        source_ip="192.168.1.100",
        destination_ip="ANY",
        destination_port="ANY",
        protocol="ANY",
        action="BLOCK",
        priority=10,
        is_enabled=True
    )
    db_session.add(rule)
    db_session.commit()

    decision, matched_id, name, reason = evaluate_packet(
        rules=[rule],
        source_ip="192.168.1.100",
        destination_ip="10.0.0.1",
        protocol="TCP",
        destination_port=80,
        default_policy="ALLOW"
    )
    assert decision == "BLOCK"
    assert matched_id == rule.id

# TEST 2: Allowed HTTP traffic
def test_allowed_http_traffic(db_session):
    rule = FirewallRule(
        name="Allow HTTP port 80",
        source_ip="ANY",
        destination_ip="ANY",
        destination_port="80",
        protocol="TCP",
        action="ALLOW",
        priority=50,
        is_enabled=True
    )
    db_session.add(rule)
    db_session.commit()

    decision, matched_id, name, reason = evaluate_packet(
        rules=[rule],
        source_ip="192.168.1.55",
        destination_ip="10.0.0.1",
        protocol="TCP",
        destination_port=80,
        default_policy="BLOCK"
    )
    assert decision == "ALLOW"
    assert matched_id == rule.id

# TEST 3: Rule priority
def test_rule_priority(db_session):
    # Rule with Priority 10: ALLOW
    rule1 = FirewallRule(
        name="Allow HTTP",
        source_ip="ANY",
        destination_ip="ANY",
        destination_port="80",
        protocol="TCP",
        action="ALLOW",
        priority=10,
        is_enabled=True
    )
    # Rule with Priority 20: BLOCK
    rule2 = FirewallRule(
        name="Block HTTP",
        source_ip="ANY",
        destination_ip="ANY",
        destination_port="80",
        protocol="TCP",
        action="BLOCK",
        priority=20,
        is_enabled=True
    )
    db_session.add_all([rule1, rule2])
    db_session.commit()

    # Rule 1 has lower priority number (10 < 20), so it should win
    decision, matched_id, name, reason = evaluate_packet(
        rules=[rule2, rule1], # Pass in unordered list to test sorting
        source_ip="192.168.1.50",
        destination_ip="10.0.0.1",
        protocol="TCP",
        destination_port=80
    )
    assert decision == "ALLOW"
    assert matched_id == rule1.id

# TEST 4: Disabled rule
def test_disabled_rule(db_session):
    disabled_block = FirewallRule(
        name="Disabled Block",
        source_ip="192.168.1.200",
        destination_ip="ANY",
        destination_port="ANY",
        protocol="ANY",
        action="BLOCK",
        priority=5,
        is_enabled=False # Disabled!
    )
    allow_all = FirewallRule(
        name="Allow All",
        source_ip="ANY",
        destination_ip="ANY",
        destination_port="ANY",
        protocol="ANY",
        action="ALLOW",
        priority=50,
        is_enabled=True
    )
    db_session.add_all([disabled_block, allow_all])
    db_session.commit()

    decision, matched_id, name, reason = evaluate_packet(
        rules=[disabled_block, allow_all],
        source_ip="192.168.1.200",
        destination_ip="10.0.0.1",
        protocol="TCP",
        destination_port=80
    )
    # Disabled rule must not block the packet
    assert decision == "ALLOW"
    assert matched_id == allow_all.id

# TEST 5: Failed SSH login detection
def test_failed_ssh_login_detection(db_session):
    src_ip = "198.51.100.99"
    # Generate 5 failed SSH attempts within 60s
    for i in range(5):
        process_single_packet(
            db=db_session,
            source_ip=src_ip,
            destination_ip="10.0.0.22",
            protocol="TCP",
            destination_port=22,
            event_type="SSH_LOGIN_ATTEMPT",
            ssh_auth_success=False
        )

    alerts = db_session.query(IDSAlert).filter(
        IDSAlert.source_ip == src_ip,
        IDSAlert.alert_type == "SSH_BRUTE_FORCE"
    ).all()
    assert len(alerts) >= 1
    assert alerts[0].severity == "CRITICAL"
    assert alerts[0].detection_method == "Rule-Based IDS"

# TEST 6: Telnet detection
def test_telnet_detection(db_session):
    src_ip = "198.51.100.77"
    process_single_packet(
        db=db_session,
        source_ip=src_ip,
        destination_ip="10.0.0.1",
        protocol="TCP",
        destination_port=23,
        event_type="TELNET_PROBE"
    )

    alerts = db_session.query(IDSAlert).filter(
        IDSAlert.source_ip == src_ip,
        IDSAlert.alert_type == "SUSPICIOUS_TELNET"
    ).all()
    assert len(alerts) >= 1
    assert alerts[0].severity == "HIGH"
    assert "Telnet" in alerts[0].description

# TEST 7: Port scan detection
def test_port_scan_detection(db_session):
    src_ip = "192.168.1.77"
    # Connect to 10 distinct destination ports within 60 seconds
    for port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 8080]:
        process_single_packet(
            db=db_session,
            source_ip=src_ip,
            destination_ip="10.0.0.5",
            protocol="TCP",
            destination_port=port,
            event_type="PORT_SCAN_PROBE"
        )

    alerts = db_session.query(IDSAlert).filter(
        IDSAlert.source_ip == src_ip,
        IDSAlert.alert_type == "PORT_SCAN"
    ).all()
    assert len(alerts) >= 1
    assert alerts[0].detection_method == "Rule-Based IDS"
    assert "distinct destination ports" in alerts[0].description

# TEST 8: Statistical anomaly detection
def test_statistical_anomaly_detection(db_session):
    base_time = datetime.datetime.utcnow() - datetime.timedelta(seconds=120)
    
    # Establish a stable baseline of 6 time buckets (each with 1 packet)
    for i in range(6):
        t = base_time + datetime.timedelta(seconds=i * 10)
        process_single_packet(
            db=db_session,
            source_ip="192.168.1.10",
            destination_ip="10.0.0.1",
            protocol="TCP",
            destination_port=80,
            event_type="NORMAL_TRAFFIC",
            timestamp=t
        )

    stats_before = calculate_anomaly_stats(db_session, "PACKETS_PER_SECOND")
    assert stats_before["has_sufficient_data"] is True
    assert stats_before["is_anomaly"] is False

    # Now inject a sudden spike of 30 packets in the latest bucket
    now_time = datetime.datetime.utcnow()
    for _ in range(30):
        process_single_packet(
            db=db_session,
            source_ip="192.168.1.10",
            destination_ip="10.0.0.1",
            protocol="TCP",
            destination_port=80,
            event_type="TRAFFIC_SPIKE",
            timestamp=now_time
        )

    stats_after = calculate_anomaly_stats(db_session, "PACKETS_PER_SECOND")
    assert stats_after["is_anomaly"] is True

    # Check alert was created
    alerts = db_session.query(IDSAlert).filter(
        IDSAlert.detection_method == "Statistical Anomaly Detection"
    ).all()
    assert len(alerts) >= 1

# TEST 9: Bastion host persistence
def test_bastion_host_persistence(client, db_session):
    resp = client.post("/api/bastion/hosts", json={
        "name": "JumpBox-Alpha",
        "ip_address": "10.0.0.250",
        "purpose": "Database Tier Access",
        "management_protocol": "SSH",
        "management_port": 22,
        "admin_access_status": "MFA_REQUIRED",
        "monitoring_status": "ACTIVE",
        "is_enabled": True,
        "description": "Secured intermediate bastion"
    })
    assert resp.status_code == 201
    host_id = resp.json()["id"]

    # Verify querying DB directly
    host = db_session.query(BastionHost).filter(BastionHost.id == host_id).first()
    assert host is not None
    assert host.name == "JumpBox-Alpha"
    assert host.ip_address == "10.0.0.250"

# TEST 10: Rule persistence
def test_rule_persistence(client, db_session):
    resp = client.post("/api/firewall/rules", json={
        "name": "Persist-Rule-Test",
        "source_ip": "172.16.0.0/16",
        "destination_ip": "ANY",
        "destination_port": "443",
        "protocol": "TCP",
        "action": "ALLOW",
        "priority": 77,
        "is_enabled": True,
        "description": "Subnet persistence check"
    })
    assert resp.status_code == 201
    rule_id = resp.json()["id"]

    rule = db_session.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
    assert rule is not None
    assert rule.name == "Persist-Rule-Test"
    assert rule.source_ip == "172.16.0.0/16"

# TEST 11: Input validation
def test_input_validation(client):
    # Invalid IP
    resp1 = client.post("/api/firewall/rules", json={
        "name": "Bad IP",
        "source_ip": "999.999.999.999",
        "protocol": "TCP",
        "action": "ALLOW",
        "priority": 10
    })
    assert resp1.status_code == 422

    # Invalid port (out of range)
    resp2 = client.post("/api/firewall/rules", json={
        "name": "Bad Port",
        "source_ip": "192.168.1.1",
        "destination_port": "70000",
        "protocol": "TCP",
        "action": "ALLOW",
        "priority": 10
    })
    assert resp2.status_code == 422

    # Invalid Action
    resp3 = client.post("/api/firewall/rules", json={
        "name": "Bad Action",
        "source_ip": "192.168.1.1",
        "protocol": "TCP",
        "action": "FORWARD",
        "priority": 10
    })
    assert resp3.status_code == 422

# TEST 12: API endpoints and frontend integration
def test_api_endpoints_integration(client):
    # Health
    assert client.get("/api/health").status_code == 200

    # Firewall rules
    assert client.get("/api/firewall/rules").status_code == 200

    # Default policy
    assert client.get("/api/firewall/default-policy").status_code == 200

    # Bastion hosts
    assert client.get("/api/bastion/hosts").status_code == 200

    # Threat encyclopedia
    resp_threats = client.get("/api/educational/threats")
    assert resp_threats.status_code == 200
    assert len(resp_threats.json()) > 0

    # Firewall concepts
    resp_concepts = client.get("/api/educational/firewall-concepts")
    assert resp_concepts.status_code == 200
    assert len(resp_concepts.json()) == 4

    # Traffic stats
    resp_stats = client.get("/api/traffic/stats")
    assert resp_stats.status_code == 200
    assert "total_packets" in resp_stats.json()

    # IDS alerts
    assert client.get("/api/ids/alerts").status_code == 200

    # Anomaly stats
    assert client.get("/api/anomaly/stats").status_code == 200
