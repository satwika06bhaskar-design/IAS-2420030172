from typing import Optional, List
from pydantic import BaseModel, Field, field_validator
import ipaddress

def validate_ip(v: str) -> str:
    val = v.strip()
    try:
        ipaddress.ip_address(val)
        return val
    except ValueError:
        raise ValueError(f"Invalid IP address: '{val}'")

class ScenarioGenerateRequest(BaseModel):
    scenario_type: str = Field(..., description="NORMAL_HTTP, FAILED_SSH, TELNET, PORT_SCAN, HIGH_VOLUME, LARGE_TRANSFER")
    count: int = Field(1, ge=1, le=100)
    source_ip: Optional[str] = None

class CustomTrafficRequest(BaseModel):
    source_ip: str = "192.168.1.50"
    destination_ip: str = "10.0.0.10"
    protocol: str = "TCP"
    destination_port: int = 80
    source_port: Optional[int] = 49152
    event_count: int = Field(1, ge=1, le=100)
    packet_size: int = Field(64, ge=20, le=65535)
    event_type: str = "CUSTOM_TRAFFIC"
    ssh_auth_success: Optional[bool] = None
    event_generation_rate: int = Field(1, ge=1, le=50, description="Packets per second simulation rate")

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def check_ip(cls, v):
        return validate_ip(v)

    @field_validator("destination_port", "source_port")
    @classmethod
    def check_port(cls, v):
        if v is not None and not (1 <= v <= 65535):
            raise ValueError("Port must be between 1 and 65535")
        return v

    @field_validator("protocol")
    @classmethod
    def check_proto(cls, v):
        p = v.strip().upper()
        if p not in ["TCP", "UDP", "ICMP"]:
            raise ValueError("Protocol must be TCP, UDP, or ICMP")
        return p

class TrafficEventOut(BaseModel):
    id: int
    timestamp: str
    source_ip: str
    destination_ip: str
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: str
    packet_size: int
    event_type: str
    ssh_auth_success: Optional[bool]
    firewall_decision: str
    matched_rule_id: Optional[int]
    matched_rule_name: Optional[str]
    firewall_reason: str
    has_alert: bool

    class Config:
        from_attributes = True

class TimeSeriesPoint(BaseModel):
    time_bucket: str
    total_packets: int
    allowed_packets: int
    blocked_packets: int
    alerts_count: int

class TrafficStatsOut(BaseModel):
    total_packets: int
    allowed_packets: int
    blocked_packets: int
    total_alerts: int
    high_severity_alerts: int
    anomaly_status: str
    time_series: List[TimeSeriesPoint]
    recent_activity_chart: List[dict]
