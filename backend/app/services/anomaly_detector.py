import datetime
import json
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models.traffic_event import TrafficEvent
from app.models.ids_alert import IDSAlert
from app.models.system_config import SystemConfig

DEFAULT_ANOMALY_CONFIG = {
    "metric_name": "PACKETS_PER_SECOND", # PACKETS_PER_SECOND, SSH_ATTEMPTS_PER_MIN, BYTES_TRANSFERRED
    "k_factor": 3.0,
    "two_sided": False,
    "min_baseline_samples": 5,
    "bucket_seconds": 10
}

METRIC_CONFIGS = {
    "PACKETS_PER_SECOND": {
        "display_name": "Packets Per Second",
        "unit": "pkts/sec",
        "description": "Rate of packets generated per time bucket"
    },
    "SSH_ATTEMPTS_PER_MIN": {
        "display_name": "SSH Login Attempts Per Minute",
        "unit": "attempts/min",
        "description": "Frequency of SSH authentication probes"
    },
    "BYTES_TRANSFERRED": {
        "display_name": "Bytes Transferred (Bandwidth Volume)",
        "unit": "bytes/sec",
        "description": "Volume of network payload transferred"
    }
}

def get_anomaly_config(db: Session) -> dict:
    conf = db.query(SystemConfig).filter(SystemConfig.key == "anomaly_settings").first()
    if conf and conf.value:
        try:
            return {**DEFAULT_ANOMALY_CONFIG, **json.loads(conf.value)}
        except Exception:
            return DEFAULT_ANOMALY_CONFIG.copy()
    return DEFAULT_ANOMALY_CONFIG.copy()

def update_anomaly_config(db: Session, settings: dict) -> dict:
    conf = db.query(SystemConfig).filter(SystemConfig.key == "anomaly_settings").first()
    if not conf:
        conf = SystemConfig(
            key="anomaly_settings",
            value=json.dumps(settings),
            description="Statistical anomaly detection engine configuration"
        )
        db.add(conf)
    else:
        conf.value = json.dumps(settings)
    db.commit()
    db.refresh(conf)
    return json.loads(conf.value)

def extract_metric_series(
    events: List[TrafficEvent],
    metric_name: str,
    bucket_seconds: int = 10
) -> List[Dict[str, Any]]:
    """
    Groups events into time buckets of bucket_seconds and computes the metric value for each bucket.
    """
    if not events:
        return []

    # Sort events by timestamp
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    start_time = sorted_events[0].timestamp
    end_time = sorted_events[-1].timestamp
    
    # Bucket mapping
    buckets: Dict[int, List[TrafficEvent]] = {}
    total_buckets = max(1, int((end_time - start_time).total_seconds() // bucket_seconds) + 1)
    
    for i in range(total_buckets):
        buckets[i] = []

    for e in sorted_events:
        delta_sec = (e.timestamp - start_time).total_seconds()
        bucket_idx = min(total_buckets - 1, max(0, int(delta_sec // bucket_seconds)))
        buckets[bucket_idx].append(e)

    series = []
    for idx, bucket_evts in buckets.items():
        bucket_time = start_time + datetime.timedelta(seconds=idx * bucket_seconds)
        time_str = bucket_time.strftime("%H:%M:%S")

        if metric_name == "PACKETS_PER_SECOND":
            # Packets divided by bucket seconds
            val = round(len(bucket_evts) / max(1.0, float(bucket_seconds)), 2)
        elif metric_name == "SSH_ATTEMPTS_PER_MIN":
            # Count SSH login attempts scaled to per minute
            ssh_count = sum(1 for e in bucket_evts if (e.destination_port == 22 or "SSH" in e.event_type.upper()))
            val = round((ssh_count / max(1.0, float(bucket_seconds))) * 60.0, 2)
        elif metric_name == "BYTES_TRANSFERRED":
            # Total bytes in bucket
            total_bytes = sum(e.packet_size for e in bucket_evts)
            val = round(total_bytes / max(1.0, float(bucket_seconds)), 2)
        else:
            val = round(len(bucket_evts) / max(1.0, float(bucket_seconds)), 2)

        series.append({
            "timestamp": time_str,
            "raw_time": bucket_time.isoformat(),
            "observed_value": val,
            "packet_count": len(bucket_evts)
        })

    return series

def calculate_anomaly_stats(db: Session, target_metric: Optional[str] = None) -> Dict[str, Any]:
    config = get_anomaly_config(db)
    metric_name = target_metric or config.get("metric_name", "PACKETS_PER_SECOND")
    k_factor = float(config.get("k_factor", 3.0))
    two_sided = bool(config.get("two_sided", False))
    min_samples = int(config.get("min_baseline_samples", 5))
    bucket_sec = int(config.get("bucket_seconds", 10))

    events = db.query(TrafficEvent).order_by(TrafficEvent.timestamp.asc()).all()
    series = extract_metric_series(events, metric_name, bucket_seconds=bucket_sec)

    display_info = METRIC_CONFIGS.get(metric_name, {
        "display_name": metric_name,
        "unit": "units",
        "description": "Observed metric value"
    })

    if len(series) < min_samples:
        current_val = series[-1]["observed_value"] if series else 0.0
        return {
            "metric_name": metric_name,
            "metric_display_name": display_info["display_name"],
            "metric_unit": display_info["unit"],
            "baseline_samples": len(series),
            "baseline_mean": 0.0,
            "baseline_std": 0.0,
            "current_value": current_val,
            "upper_threshold": 0.0,
            "lower_threshold": 0.0 if two_sided else None,
            "k_factor": k_factor,
            "two_sided": two_sided,
            "is_anomaly": False,
            "z_score": 0.0,
            "status_text": f"Insufficient data: {len(series)}/{min_samples} required baseline samples collected.",
            "has_sufficient_data": False,
            "time_series": series
        }

    # We use all points except the latest point as the baseline, or all historical if steady
    # If len(series) > min_samples, baseline is series[:-1], current is series[-1]
    baseline_values = [p["observed_value"] for p in series[:-1]] if len(series) > 1 else [p["observed_value"] for p in series]
    current_point = series[-1]
    current_value = current_point["observed_value"]

    # NumPy calculations
    arr = np.array(baseline_values, dtype=float)
    baseline_mean = float(np.mean(arr))
    baseline_std = float(np.std(arr, ddof=1)) if len(arr) > 1 else 0.0

    # Handle zero standard deviation explicitly
    effective_std = baseline_std if baseline_std > 1e-6 else 0.0

    upper_threshold = round(baseline_mean + (k_factor * effective_std), 2)
    lower_threshold = round(max(0.0, baseline_mean - (k_factor * effective_std)), 2) if two_sided else None

    # Check anomaly condition
    is_anomaly = False
    z_score = 0.0
    if effective_std > 0:
        z_score = round((current_value - baseline_mean) / effective_std, 2)
        if current_value > upper_threshold:
            is_anomaly = True
        elif two_sided and lower_threshold is not None and current_value < lower_threshold:
            is_anomaly = True
    else:
        # If std is 0 (all baseline values identical):
        if current_value > baseline_mean:
            # Significant deviation beyond identical baseline
            is_anomaly = True
            z_score = 99.9

    status_text = (
        f"Anomaly detected! Current value ({current_value} {display_info['unit']}) "
        f"exceeds upper threshold ({upper_threshold} {display_info['unit']})."
        if is_anomaly and current_value > upper_threshold else
        (f"Anomaly detected! Current value ({current_value} {display_info['unit']}) "
         f"is below lower threshold ({lower_threshold} {display_info['unit']})."
         if is_anomaly and two_sided and lower_threshold and current_value < lower_threshold else
         f"Normal: Current value ({current_value} {display_info['unit']}) within expected statistical baseline.")
    )

    # Annotate series with anomaly markers
    for p in series:
        val = p["observed_value"]
        if effective_std > 0:
            p_anomaly = val > upper_threshold or (two_sided and lower_threshold is not None and val < lower_threshold)
        else:
            p_anomaly = val > baseline_mean and len(series) >= min_samples
        p["is_anomaly"] = p_anomaly

    return {
        "metric_name": metric_name,
        "metric_display_name": display_info["display_name"],
        "metric_unit": display_info["unit"],
        "baseline_samples": len(baseline_values),
        "baseline_mean": round(baseline_mean, 2),
        "baseline_std": round(baseline_std, 2),
        "current_value": round(current_value, 2),
        "upper_threshold": upper_threshold,
        "lower_threshold": lower_threshold,
        "k_factor": k_factor,
        "two_sided": two_sided,
        "is_anomaly": is_anomaly,
        "z_score": z_score,
        "status_text": status_text,
        "has_sufficient_data": True,
        "time_series": series
    }

def check_and_create_anomaly_alert(db: Session, event: TrafficEvent) -> Optional[IDSAlert]:
    """
    Evaluates current traffic against the statistical baseline and creates an IDS alert if an anomaly is detected.
    """
    stats = calculate_anomaly_stats(db)
    if not stats["has_sufficient_data"] or not stats["is_anomaly"]:
        return None

    # Avoid duplicate statistical anomaly alerts within rolling window (60s)
    window_start = event.timestamp - datetime.timedelta(seconds=60)
    existing = db.query(IDSAlert).filter(
        IDSAlert.detection_method == "Statistical Anomaly Detection",
        IDSAlert.alert_type == "STATISTICAL_ANOMALY",
        IDSAlert.timestamp >= window_start
    ).first()

    if existing:
        return None

    metric_name = stats["metric_name"]
    curr_val = stats["current_value"]
    thresh = stats["upper_threshold"]
    k_fact = stats["k_factor"]
    mean_val = stats["baseline_mean"]
    std_val = stats["baseline_std"]

    alert = IDSAlert(
        timestamp=event.timestamp,
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        alert_type="STATISTICAL_ANOMALY",
        severity="HIGH",
        detection_method="Statistical Anomaly Detection",
        description=(
            f"Observed {stats['metric_display_name']} ({curr_val}) exceeded the configured statistical threshold "
            f"({thresh}) [Mean: {mean_val}, StdDev: {std_val}, K: {k_fact}]. Note: Statistical anomaly distinguishes "
            f"unusual traffic patterns from confirmed attacks."
        ),
        related_event_id=event.id,
        extra_data=json.dumps({
            "metric_name": metric_name,
            "current_value": curr_val,
            "upper_threshold": thresh,
            "baseline_mean": mean_val,
            "baseline_std": std_val,
            "k_factor": k_fact,
            "z_score": stats["z_score"]
        })
    )
    db.add(alert)
    event.has_alert = True
    db.commit()
    db.refresh(alert)
    return alert
