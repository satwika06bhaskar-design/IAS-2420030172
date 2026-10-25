from typing import Optional, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db
from app.models.ids_alert import IDSAlert
from app.schemas.anomaly import AnomalySettings, AnomalyStatsOut
from app.services.anomaly_detector import (
    get_anomaly_config, update_anomaly_config, calculate_anomaly_stats
)

router = APIRouter(prefix="/api/anomaly", tags=["Statistical Anomaly Detection"])

@router.get("/stats", response_model=AnomalyStatsOut)
def get_anomaly_statistics(
    metric: Optional[str] = Query(None, description="PACKETS_PER_SECOND, SSH_ATTEMPTS_PER_MIN, BYTES_TRANSFERRED"),
    db: Session = Depends(get_db)
):
    return calculate_anomaly_stats(db, target_metric=metric)

@router.get("/config")
def get_current_anomaly_settings(db: Session = Depends(get_db)):
    return get_anomaly_config(db)

@router.put("/config")
def set_anomaly_settings(settings: AnomalySettings, db: Session = Depends(get_db)):
    updated = update_anomaly_config(db, settings.model_dump())
    return {
        "message": "Anomaly detection settings updated successfully",
        "settings": updated
    }

@router.get("/events")
def get_anomaly_alerts(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    alerts = db.query(IDSAlert).filter(
        IDSAlert.detection_method == "Statistical Anomaly Detection"
    ).order_by(desc(IDSAlert.timestamp)).limit(limit).all()

    return [
        {
            "id": a.id,
            "timestamp": a.timestamp.isoformat(),
            "source_ip": a.source_ip,
            "destination_ip": a.destination_ip,
            "severity": a.severity,
            "description": a.description,
            "extra_data": a.extra_data,
            "is_acknowledged": a.is_acknowledged
        }
        for a in alerts
    ]
