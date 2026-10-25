import datetime
import json
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models.traffic_event import TrafficEvent
from app.models.ids_alert import IDSAlert
from app.models.system_config import SystemConfig

DEFAULT_IDS_CONFIG = {
    "ssh_failed_threshold": 5,
    "telnet_port": 23,
    "port_scan_distinct_ports_threshold": 10,
    "excessive_packet_threshold": 20,
    "repeated_denials_threshold": 5,
    "rolling_window_seconds": 60
}

def get_ids_config(db: Session) -> dict:
    conf_record = db.query(SystemConfig).filter(SystemConfig.key == "ids_thresholds").first()
    if conf_record and conf_record.value:
        try:
            stored = json.loads(conf_record.value)
            merged = {**DEFAULT_IDS_CONFIG, **stored}
            return merged
        except Exception:
            return DEFAULT_IDS_CONFIG.copy()
    return DEFAULT_IDS_CONFIG.copy()

def update_ids_config(db: Session, new_config: dict) -> dict:
    conf_record = db.query(SystemConfig).filter(SystemConfig.key == "ids_thresholds").first()
    if not conf_record:
        conf_record = SystemConfig(
            key="ids_thresholds",
            value=json.dumps(new_config),
            description="Thresholds for Rule-Based IDS engine"
        )
        db.add(conf_record)
    else:
        conf_record.value = json.dumps(new_config)
    db.commit()
    db.refresh(conf_record)
    return json.loads(conf_record.value)

def evaluate_ids_rules(db: Session, event: TrafficEvent) -> List[IDSAlert]:
    """
    Evaluates rule-based IDS conditions against the simulated event and recent window.
    Returns list of newly generated alerts.
    """
    config = get_ids_config(db)
    rolling_secs = config.get("rolling_window_seconds", 60)
    window_start = event.timestamp - datetime.timedelta(seconds=rolling_secs)
    alerts_to_create = []

    # Helper to check if duplicate alert was already generated in this window
    def has_recent_alert(alert_type: str) -> bool:
        recent = db.query(IDSAlert).filter(
            IDSAlert.source_ip == event.source_ip,
            IDSAlert.alert_type == alert_type,
            IDSAlert.timestamp >= window_start
        ).first()
        return recent is not None

    # RULE 2: Suspicious Telnet traffic (TCP targeting port 23)
    telnet_port = config.get("telnet_port", 23)
    if event.protocol.upper() == "TCP" and event.destination_port == telnet_port:
        # Check duplicate for this specific event
        existing = db.query(IDSAlert).filter(
            IDSAlert.related_event_id == event.id,
            IDSAlert.alert_type == "SUSPICIOUS_TELNET"
        ).first()
        if not existing and not has_recent_alert("SUSPICIOUS_TELNET"):
            alert = IDSAlert(
                timestamp=event.timestamp,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                alert_type="SUSPICIOUS_TELNET",
                severity="HIGH",
                detection_method="Rule-Based IDS",
                description=(
                    f"Suspicious unencrypted Telnet traffic detected targeting port {telnet_port} "
                    f"from source {event.source_ip}. Telnet transmits credentials in cleartext."
                ),
                related_event_id=event.id,
                extra_data=json.dumps({
                    "target_port": telnet_port,
                    "protocol": "TCP",
                    "reason": "Cleartext legacy management protocol access attempt"
                })
            )
            alerts_to_create.append(alert)

    # Fetch recent events from this source IP within the rolling window
    recent_events = db.query(TrafficEvent).filter(
        TrafficEvent.source_ip == event.source_ip,
        TrafficEvent.timestamp >= window_start,
        TrafficEvent.timestamp <= event.timestamp
    ).all()

    # RULE 1: Repeated SSH login failures (>= 5 failed attempts within 60s)
    ssh_threshold = config.get("ssh_failed_threshold", 5)
    ssh_failed_count = sum(
        1 for e in recent_events
        if (e.destination_port == 22 or "SSH" in e.event_type.upper()) and e.ssh_auth_success is False
    )
    if ssh_failed_count >= ssh_threshold:
        if not has_recent_alert("SSH_BRUTE_FORCE"):
            alert = IDSAlert(
                timestamp=event.timestamp,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                alert_type="SSH_BRUTE_FORCE",
                severity="CRITICAL",
                detection_method="Rule-Based IDS",
                description=(
                    f"Potential SSH brute force attack: {ssh_failed_count} failed SSH login attempts "
                    f"observed from {event.source_ip} within the last {rolling_secs} seconds "
                    f"(Threshold: {ssh_threshold})."
                ),
                related_event_id=event.id,
                extra_data=json.dumps({
                    "failed_attempts": ssh_failed_count,
                    "window_seconds": rolling_secs,
                    "threshold": ssh_threshold
                })
            )
            alerts_to_create.append(alert)

    # RULE 3: Port scanning (attempts to >= 10 distinct destination ports within 60s)
    port_scan_threshold = config.get("port_scan_distinct_ports_threshold", 10)
    distinct_ports = {e.destination_port for e in recent_events if e.destination_port is not None}
    if len(distinct_ports) >= port_scan_threshold:
        if not has_recent_alert("PORT_SCAN"):
            alert = IDSAlert(
                timestamp=event.timestamp,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                alert_type="PORT_SCAN",
                severity="HIGH",
                detection_method="Rule-Based IDS",
                description=(
                    f"Port scanning activity detected: {len(distinct_ports)} distinct destination ports "
                    f"probed by {event.source_ip} within {rolling_secs} seconds "
                    f"(Threshold: {port_scan_threshold})."
                ),
                related_event_id=event.id,
                extra_data=json.dumps({
                    "distinct_ports_count": len(distinct_ports),
                    "scanned_ports": sorted(list(distinct_ports))[:20],
                    "threshold": port_scan_threshold
                })
            )
            alerts_to_create.append(alert)

    # RULE 4: Excessive packet volume (> threshold within 60s)
    volume_threshold = config.get("excessive_packet_threshold", 20)
    total_packets_count = len(recent_events)
    if total_packets_count > volume_threshold:
        if not has_recent_alert("EXCESSIVE_VOLUME"):
            alert = IDSAlert(
                timestamp=event.timestamp,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                alert_type="EXCESSIVE_VOLUME",
                severity="MEDIUM",
                detection_method="Rule-Based IDS",
                description=(
                    f"Excessive packet volume detected from {event.source_ip}: {total_packets_count} packets "
                    f"generated in {rolling_secs} seconds (Threshold: >{volume_threshold})."
                ),
                related_event_id=event.id,
                extra_data=json.dumps({
                    "packet_count": total_packets_count,
                    "threshold": volume_threshold,
                    "window_seconds": rolling_secs
                })
            )
            alerts_to_create.append(alert)

    # RULE 5: Repeated firewall denials (>= threshold blocked packets within 60s)
    denials_threshold = config.get("repeated_denials_threshold", 5)
    blocked_count = sum(1 for e in recent_events if e.firewall_decision.upper() == "BLOCK")
    if blocked_count >= denials_threshold:
        if not has_recent_alert("REPEATED_DENIALS"):
            alert = IDSAlert(
                timestamp=event.timestamp,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                alert_type="REPEATED_DENIALS",
                severity="MEDIUM",
                detection_method="Rule-Based IDS",
                description=(
                    f"Repeated firewall denials detected: {blocked_count} packets from {event.source_ip} "
                    f"were dropped by firewall rules within {rolling_secs} seconds "
                    f"(Threshold: {denials_threshold})."
                ),
                related_event_id=event.id,
                extra_data=json.dumps({
                    "blocked_count": blocked_count,
                    "threshold": denials_threshold,
                    "window_seconds": rolling_secs
                })
            )
            alerts_to_create.append(alert)

    for a in alerts_to_create:
        db.add(a)
    
    if alerts_to_create:
        event.has_alert = True
        db.commit()
        for a in alerts_to_create:
            db.refresh(a)

    return alerts_to_create
