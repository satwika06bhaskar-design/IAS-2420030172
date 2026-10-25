from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class AnomalySettings(BaseModel):
    metric_name: str = Field("PACKETS_PER_SECOND", description="PACKETS_PER_SECOND, SSH_ATTEMPTS_PER_MIN, BYTES_TRANSFERRED")
    k_factor: float = Field(3.0, ge=1.0, le=10.0, description="Number of standard deviations from mean")
    two_sided: bool = Field(False, description="Enable two-sided detection (both high and unusually low)")
    min_baseline_samples: int = Field(5, ge=3, le=100, description="Minimum samples before baseline is reliable")

class AnomalyTimeSeriesPoint(BaseModel):
    timestamp: str
    observed_value: float
    is_anomaly: bool
    source_ip: Optional[str] = None

class AnomalyStatsOut(BaseModel):
    metric_name: str
    metric_display_name: str
    baseline_samples: int
    baseline_mean: float
    baseline_std: float
    current_value: float
    upper_threshold: float
    lower_threshold: Optional[float]
    k_factor: float
    two_sided: bool
    is_anomaly: bool
    status_text: str
    has_sufficient_data: bool
    time_series: List[AnomalyTimeSeriesPoint]
