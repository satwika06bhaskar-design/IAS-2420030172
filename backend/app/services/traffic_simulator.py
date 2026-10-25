import datetime
import random
import time
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.firewall_rule import FirewallRule
from app.models.traffic_event import TrafficEvent
from app.models.ids_alert import IDSAlert
from app.models.system_config import SystemConfig
from app.services.firewall_engine import evaluate_packet
from app.services.rule_based_ids import evaluate_ids_rules
from app.services.anomaly_detector import check_and_create_anomaly_alert

def get_default_firewall_policy(db: Session) -> str:
    conf = db.query(SystemConfig).filter(SystemConfig.key == "default_firewall_policy").first()
    if conf and conf.value:
        return conf.value.upper()
    return "BLOCK"

def set_default_firewall_policy(db: Session, policy: str) -> str:
    pol = policy.upper()
    conf = db.query(SystemConfig).filter(SystemConfig.key == "default_firewall_policy").first()
    if not conf:
        conf = SystemConfig(
            key="default_firewall_policy",
            value=pol,
            description="Default firewall policy when no rule matches"
        )
        db.add(conf)
    else:
        conf.value = pol
    db.commit()
    db.refresh(conf)
    return conf.value

def process_single_packet(
    db: Session,
    source_ip: str,
    destination_ip: str,
    protocol: str,
    destination_port: Optional[int],
    source_port: Optional[int] = None,
    packet_size: int = 64,
    event_type: str = "GENERIC_PACKET",
    ssh_auth_success: Optional[bool] = None,
    timestamp: Optional[datetime.datetime] = None
) -> Dict[str, Any]:
    """
    Executes the 9-step processing pipeline:
    1. Generate the simulated event data.
    2. Evaluate firewall rules.
    3. Record the ALLOW or BLOCK decision.
    4. Store the event.
    5. Evaluate applicable rule-based IDS conditions.
    6. Run anomaly detection.
    7. Generate alerts when required.
    8. Store results & update event.
    9. Return results.
    """
    if timestamp is None:
        timestamp = datetime.datetime.utcnow()

    # Fetch enabled firewall rules
    rules = db.query(FirewallRule).filter(FirewallRule.is_enabled == True).all()
    default_policy = get_default_firewall_policy(db)

    # 2 & 3. Evaluate firewall rules
    decision, matched_rule_id, matched_rule_name, reason = evaluate_packet(
        rules=rules,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        destination_port=destination_port,
        default_policy=default_policy
    )

    # 4. Create and store TrafficEvent
    event = TrafficEvent(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port or random.randint(49152, 65535),
        destination_port=destination_port,
        protocol=protocol.upper(),
        packet_size=packet_size,
        event_type=event_type,
        ssh_auth_success=ssh_auth_success,
        firewall_decision=decision,
        matched_rule_id=matched_rule_id,
        matched_rule_name=matched_rule_name,
        firewall_reason=reason,
        has_alert=False
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    # 5. Evaluate applicable rule-based IDS conditions
    new_rule_alerts = evaluate_ids_rules(db, event)

    # 6 & 7. Run anomaly detection
    anomaly_alert = check_and_create_anomaly_alert(db, event)

    all_alerts = list(new_rule_alerts)
    if anomaly_alert:
        all_alerts.append(anomaly_alert)

    return {
        "event_id": event.id,
        "timestamp": event.timestamp.isoformat(),
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "source_port": event.source_port,
        "destination_port": event.destination_port,
        "protocol": event.protocol,
        "packet_size": event.packet_size,
        "event_type": event.event_type,
        "ssh_auth_success": event.ssh_auth_success,
        "firewall_decision": event.firewall_decision,
        "matched_rule_id": event.matched_rule_id,
        "matched_rule_name": event.matched_rule_name,
        "firewall_reason": event.firewall_reason,
        "has_alert": len(all_alerts) > 0,
        "alerts_generated": [
            {
                "id": a.id,
                "type": a.alert_type,
                "severity": a.severity,
                "method": a.detection_method,
                "description": a.description
            }
            for a in all_alerts
        ]
    }

def run_scenario(db: Session, scenario_type: str, count: int = 1, custom_source_ip: Optional[str] = None) -> List[Dict[str, Any]]:
    results = []
    base_time = datetime.datetime.utcnow()

    if scenario_type == "NORMAL_HTTP":
        src_ip = custom_source_ip or f"192.168.1.{random.randint(10, 80)}"
        dst_ip = "10.0.0.80"
        ports = [80, 443, 8080]
        for i in range(count):
            res = process_single_packet(
                db=db,
                source_ip=src_ip,
                destination_ip=dst_ip,
                protocol="TCP",
                destination_port=random.choice(ports),
                packet_size=random.randint(300, 1400),
                event_type="HTTP_GET_REQUEST",
                timestamp=base_time + datetime.timedelta(seconds=i * 0.1)
            )
            results.append(res)

    elif scenario_type == "FAILED_SSH":
        src_ip = custom_source_ip or "203.0.113.195"
        dst_ip = "10.0.0.22"
        # Generate requested count (e.g., 5 or more to trigger rule-based SSH alert)
        for i in range(max(1, count)):
            res = process_single_packet(
                db=db,
                source_ip=src_ip,
                destination_ip=dst_ip,
                protocol="TCP",
                destination_port=22,
                packet_size=256,
                event_type="SSH_LOGIN_ATTEMPT",
                ssh_auth_success=False,
                timestamp=base_time + datetime.timedelta(seconds=i * 0.2)
            )
            results.append(res)

    elif scenario_type == "TELNET":
        src_ip = custom_source_ip or "198.51.100.23"
        dst_ip = "10.0.0.1"
        for i in range(count):
            res = process_single_packet(
                db=db,
                source_ip=src_ip,
                destination_ip=dst_ip,
                protocol="TCP",
                destination_port=23,
                packet_size=128,
                event_type="TELNET_PROBE",
                timestamp=base_time + datetime.timedelta(seconds=i * 0.1)
            )
            results.append(res)

    elif scenario_type == "PORT_SCAN":
        src_ip = custom_source_ip or "198.51.100.88"
        dst_ip = "10.0.0.5"
        # Probing sequential/distinct ports to trigger Rule 3
        scan_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 1433, 3306, 3389, 5432, 8080, 8443]
        ports_to_use = scan_ports[:max(10, count)]
        for i, port in enumerate(ports_to_use):
            res = process_single_packet(
                db=db,
                source_ip=src_ip,
                destination_ip=dst_ip,
                protocol="TCP",
                destination_port=port,
                packet_size=64,
                event_type="PORT_SCAN_PROBE",
                timestamp=base_time + datetime.timedelta(seconds=i * 0.1)
            )
            results.append(res)

    elif scenario_type == "HIGH_VOLUME":
        src_ip = custom_source_ip or "203.0.113.66"
        dst_ip = "10.0.0.100"
        # Burst of packets (e.g. 25 packets) to trigger Rule 4 & anomaly detector
        burst_count = max(25, count)
        for i in range(burst_count):
            res = process_single_packet(
                db=db,
                source_ip=src_ip,
                destination_ip=dst_ip,
                protocol="UDP",
                destination_port=53,
                packet_size=128,
                event_type="HIGH_VOLUME_STREAM",
                timestamp=base_time + datetime.timedelta(seconds=i * 0.05)
            )
            results.append(res)

    elif scenario_type == "LARGE_TRANSFER":
        src_ip = custom_source_ip or "192.168.1.150"
        dst_ip = "10.0.0.15"
        for i in range(count):
            res = process_single_packet(
                db=db,
                source_ip=src_ip,
                destination_ip=dst_ip,
                protocol="TCP",
                destination_port=443,
                packet_size=random.randint(45000, 65000),
                event_type="LARGE_FILE_TRANSFER",
                timestamp=base_time + datetime.timedelta(seconds=i * 0.2)
            )
            results.append(res)

    return results
