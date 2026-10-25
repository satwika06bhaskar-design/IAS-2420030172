import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_

from app.database import get_db
from app.models.ids_alert import IDSAlert
from app.models.traffic_event import TrafficEvent
from app.schemas.ids import IDSAlertOut, IDSThresholdsConfig, AlertAcknowledgeRequest
from app.services.rule_based_ids import get_ids_config, update_ids_config

router = APIRouter(prefix="/api/ids", tags=["IDS Dashboard"])

@router.get("/alerts")
def get_alerts(
    severity: Optional[str] = None,
    detection_method: Optional[str] = None,
    is_acknowledged: Optional[bool] = None,
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(IDSAlert)

    if severity:
        query = query.filter(IDSAlert.severity == severity.upper())
    if detection_method:
        query = query.filter(IDSAlert.detection_method == detection_method)
    if is_acknowledged is not None:
        query = query.filter(IDSAlert.is_acknowledged == is_acknowledged)
    if search:
        s = f"%{search.strip()}%"
        query = query.filter(
            or_(
                IDSAlert.source_ip.ilike(s),
                IDSAlert.alert_type.ilike(s),
                IDSAlert.description.ilike(s)
            )
        )

    total = query.count()
    alerts = query.order_by(desc(IDSAlert.timestamp), desc(IDSAlert.id)).offset(offset).limit(limit).all()

    items = []
    for a in alerts:
        rel_evt_dict = None
        if a.related_event:
            e = a.related_event
            rel_evt_dict = {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "source_ip": e.source_ip,
                "destination_ip": e.destination_ip,
                "protocol": e.protocol,
                "destination_port": e.destination_port,
                "packet_size": e.packet_size,
                "firewall_decision": e.firewall_decision,
                "matched_rule_name": e.matched_rule_name,
                "event_type": e.event_type
            }

        items.append({
            "id": a.id,
            "timestamp": a.timestamp.isoformat(),
            "source_ip": a.source_ip,
            "destination_ip": a.destination_ip,
            "alert_type": a.alert_type,
            "severity": a.severity,
            "detection_method": a.detection_method,
            "description": a.description,
            "related_event_id": a.related_event_id,
            "is_acknowledged": a.is_acknowledged,
            "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
            "extra_data": a.extra_data,
            "related_event": rel_evt_dict
        })

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": items
    }

@router.get("/alerts/{alert_id}")
def get_alert_detail(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(IDSAlert).filter(IDSAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    rel_evt = None
    if alert.related_event:
        e = alert.related_event
        rel_evt = {
            "id": e.id,
            "timestamp": e.timestamp.isoformat(),
            "source_ip": e.source_ip,
            "destination_ip": e.destination_ip,
            "protocol": e.protocol,
            "destination_port": e.destination_port,
            "packet_size": e.packet_size,
            "firewall_decision": e.firewall_decision,
            "matched_rule_name": e.matched_rule_name,
            "event_type": e.event_type
        }

    return {
        "id": alert.id,
        "timestamp": alert.timestamp.isoformat(),
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "alert_type": alert.alert_type,
        "severity": alert.severity,
        "detection_method": alert.detection_method,
        "description": alert.description,
        "related_event_id": alert.related_event_id,
        "is_acknowledged": alert.is_acknowledged,
        "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
        "extra_data": alert.extra_data,
        "related_event": rel_evt
    }

@router.post("/alerts/acknowledge")
def acknowledge_alerts(req: AlertAcknowledgeRequest, db: Session = Depends(get_db)):
    now = datetime.datetime.utcnow()
    updated = db.query(IDSAlert).filter(IDSAlert.id.in_(req.alert_ids)).update({
        "is_acknowledged": True,
        "acknowledged_at": now
    }, synchronize_session=False)
    db.commit()
    return {"message": f"Acknowledged {updated} alerts", "count": updated}

@router.post("/alerts/{alert_id}/acknowledge")
def acknowledge_single_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(IDSAlert).filter(IDSAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_acknowledged = True
    alert.acknowledged_at = datetime.datetime.utcnow()
    db.commit()
    return {"message": f"Alert #{alert_id} acknowledged", "id": alert_id}

@router.delete("/alerts/clear")
def clear_all_alerts(db: Session = Depends(get_db)):
    deleted = db.query(IDSAlert).delete()
    db.commit()
    return {"message": f"Successfully cleared {deleted} alerts", "count": deleted}

@router.get("/config", response_model=IDSThresholdsConfig)
def get_rule_thresholds(db: Session = Depends(get_db)):
    return get_ids_config(db)

@router.put("/config", response_model=IDSThresholdsConfig)
def update_rule_thresholds(config_in: IDSThresholdsConfig, db: Session = Depends(get_db)):
    return update_ids_config(db, config_in.model_dump())
