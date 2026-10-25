import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from app.database import get_db
from app.models.traffic_event import TrafficEvent
from app.models.ids_alert import IDSAlert
from app.schemas.traffic import (
    ScenarioGenerateRequest, CustomTrafficRequest,
    TrafficStatsOut, TimeSeriesPoint
)
from app.services.traffic_simulator import run_scenario, process_single_packet
from app.services.anomaly_detector import calculate_anomaly_stats

router = APIRouter(prefix="/api/traffic", tags=["Traffic Simulator"])

@router.post("/scenario")
def trigger_scenario(req: ScenarioGenerateRequest, db: Session = Depends(get_db)):
    events = run_scenario(
        db=db,
        scenario_type=req.scenario_type,
        count=req.count,
        custom_source_ip=req.source_ip
    )
    return {
        "message": f"Successfully executed scenario '{req.scenario_type}' with {len(events)} simulated packets",
        "scenario": req.scenario_type,
        "packet_count": len(events),
        "results": events
    }

@router.post("/custom")
def trigger_custom_traffic(req: CustomTrafficRequest, db: Session = Depends(get_db)):
    results = []
    base_time = datetime.datetime.utcnow()
    # Process event_count packets
    for i in range(req.event_count):
        # Stagger timestamp slightly based on rate
        stagger = (1.0 / max(1, req.event_generation_rate)) * i
        evt = process_single_packet(
            db=db,
            source_ip=req.source_ip,
            destination_ip=req.destination_ip,
            protocol=req.protocol,
            destination_port=req.destination_port,
            source_port=req.source_port,
            packet_size=req.packet_size,
            event_type=req.event_type,
            ssh_auth_success=req.ssh_auth_success,
            timestamp=base_time + datetime.timedelta(seconds=stagger)
        )
        results.append(evt)

    return {
        "message": f"Generated {len(results)} custom simulated packets from {req.source_ip} to {req.destination_ip}:{req.destination_port}",
        "count": len(results),
        "results": results
    }

@router.get("/events")
def get_traffic_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    decision: Optional[str] = None,
    protocol: Optional[str] = None,
    source_ip: Optional[str] = None,
    has_alert: Optional[bool] = None,
    db: Session = Depends(get_db)
):
    query = db.query(TrafficEvent)
    if decision:
        query = query.filter(TrafficEvent.firewall_decision == decision.upper())
    if protocol:
        query = query.filter(TrafficEvent.protocol == protocol.upper())
    if source_ip:
        query = query.filter(TrafficEvent.source_ip.ilike(f"%{source_ip}%"))
    if has_alert is not None:
        query = query.filter(TrafficEvent.has_alert == has_alert)

    total = query.count()
    events = query.order_by(desc(TrafficEvent.timestamp), desc(TrafficEvent.id)).offset(offset).limit(limit).all()

    items = []
    for e in events:
        items.append({
            "id": e.id,
            "timestamp": e.timestamp.isoformat(),
            "source_ip": e.source_ip,
            "destination_ip": e.destination_ip,
            "source_port": e.source_port,
            "destination_port": e.destination_port,
            "protocol": e.protocol,
            "packet_size": e.packet_size,
            "event_type": e.event_type,
            "ssh_auth_success": e.ssh_auth_success,
            "firewall_decision": e.firewall_decision,
            "matched_rule_id": e.matched_rule_id,
            "matched_rule_name": e.matched_rule_name,
            "firewall_reason": e.firewall_reason,
            "has_alert": e.has_alert
        })

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": items
    }

@router.get("/stats", response_model=TrafficStatsOut)
def get_traffic_stats(db: Session = Depends(get_db)):
    total_packets = db.query(TrafficEvent).count()
    allowed_packets = db.query(TrafficEvent).filter(TrafficEvent.firewall_decision == "ALLOW").count()
    blocked_packets = db.query(TrafficEvent).filter(TrafficEvent.firewall_decision == "BLOCK").count()
    
    total_alerts = db.query(IDSAlert).count()
    high_severity_alerts = db.query(IDSAlert).filter(
        IDSAlert.severity.in_(["HIGH", "CRITICAL"])
    ).count()

    # Anomaly status
    anomaly_data = calculate_anomaly_stats(db)
    anomaly_status = "ANOMALY_DETECTED" if anomaly_data.get("is_anomaly") else "NORMAL"

    # Aggregated time series points for charts
    events = db.query(TrafficEvent).order_by(TrafficEvent.timestamp.asc()).all()
    alerts = db.query(IDSAlert).order_by(IDSAlert.timestamp.asc()).all()

    # Build time buckets (last 10 buckets or grouped by 10s increments)
    time_series: List[TimeSeriesPoint] = []
    recent_activity_chart = []

    if events:
        # Group into up to 10 chronological slices
        min_time = events[0].timestamp
        max_time = events[-1].timestamp
        total_span = max(10.0, (max_time - min_time).total_seconds())
        slice_seconds = max(5.0, total_span / 10.0)

        for i in range(10):
            slice_start = min_time + datetime.timedelta(seconds=i * slice_seconds)
            slice_end = slice_start + datetime.timedelta(seconds=slice_seconds)
            
            slice_evts = [e for e in events if slice_start <= e.timestamp < slice_end or (i == 9 and e.timestamp >= slice_start)]
            slice_alerts = [a for a in alerts if slice_start <= a.timestamp < slice_end or (i == 9 and a.timestamp >= slice_start)]

            allowed = sum(1 for e in slice_evts if e.firewall_decision == "ALLOW")
            blocked = sum(1 for e in slice_evts if e.firewall_decision == "BLOCK")

            label = slice_start.strftime("%H:%M:%S")
            time_series.append(TimeSeriesPoint(
                time_bucket=label,
                total_packets=len(slice_evts),
                allowed_packets=allowed,
                blocked_packets=blocked,
                alerts_count=len(slice_alerts)
            ))
            recent_activity_chart.append({
                "time": label,
                "allowed": allowed,
                "blocked": blocked,
                "total": len(slice_evts),
                "alerts": len(slice_alerts)
            })

    return {
        "total_packets": total_packets,
        "allowed_packets": allowed_packets,
        "blocked_packets": blocked_packets,
        "total_alerts": total_alerts,
        "high_severity_alerts": high_severity_alerts,
        "anomaly_status": anomaly_status,
        "time_series": time_series,
        "recent_activity_chart": recent_activity_chart
    }

@router.post("/clear-history")
def clear_event_history(db: Session = Depends(get_db)):
    deleted_events = db.query(TrafficEvent).delete()
    db.commit()
    return {"message": f"Cleared {deleted_events} traffic events from history."}

@router.post("/reset")
def reset_simulation(db: Session = Depends(get_db)):
    deleted_alerts = db.query(IDSAlert).delete()
    deleted_events = db.query(TrafficEvent).delete()
    db.commit()
    return {
        "message": "Simulation data completely reset.",
        "cleared_events": deleted_events,
        "cleared_alerts": deleted_alerts
    }
