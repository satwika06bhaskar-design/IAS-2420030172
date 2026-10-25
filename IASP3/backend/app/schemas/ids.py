from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class IDSAlertOut(BaseModel):
    id: int
    timestamp: str
    source_ip: str
    destination_ip: Optional[str]
    alert_type: str
    severity: str
    detection_method: str
    description: str
    related_event_id: Optional[int]
    is_acknowledged: bool
    acknowledged_at: Optional[str]
    extra_data: Optional[str]
    related_event: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True

class IDSThresholdsConfig(BaseModel):
    ssh_failed_threshold: int = Field(5, ge=1, le=50, description="Failed SSH attempts in 60s window")
    telnet_port: int = Field(23, ge=1, le=65535, description="Port for Telnet alert")
    port_scan_distinct_ports_threshold: int = Field(10, ge=2, le=100, description="Distinct ports in 60s window")
    excessive_packet_threshold: int = Field(20, ge=5, le=500, description="Packets from single source IP in 60s window")
    repeated_denials_threshold: int = Field(5, ge=2, le=50, description="Blocked packets from single source IP in 60s window")
    rolling_window_seconds: int = Field(60, ge=10, le=300, description="Rolling time window in seconds")

class AlertAcknowledgeRequest(BaseModel):
    alert_ids: List[int]
