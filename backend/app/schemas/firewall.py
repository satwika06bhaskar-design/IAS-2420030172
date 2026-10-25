import ipaddress
import re
from typing import Optional, List
from pydantic import BaseModel, Field, field_validator

def validate_ip_or_cidr(value: Optional[str]) -> Optional[str]:
    if not value or value.upper() == "ANY" or value.strip() == "*":
        return "ANY"
    val = value.strip()
    try:
        if "/" in val:
            ipaddress.ip_network(val, strict=False)
        else:
            ipaddress.ip_address(val)
        return val
    except ValueError:
        raise ValueError(f"Invalid IP address or CIDR range: '{val}'")

def validate_port_spec(value: Optional[str]) -> Optional[str]:
    if not value or str(value).upper() == "ANY" or str(value).strip() == "*":
        return "ANY"
    val = str(value).strip()
    if "-" in val:
        parts = val.split("-")
        if len(parts) != 2:
            raise ValueError(f"Invalid port range format: '{val}' (expected start-end)")
        try:
            start, end = int(parts[0]), int(parts[1])
            if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                raise ValueError
        except ValueError:
            raise ValueError(f"Port range must be within 1-65535 and start <= end: '{val}'")
    else:
        try:
            p = int(val)
            if not (1 <= p <= 65535):
                raise ValueError
        except ValueError:
            raise ValueError(f"Port must be an integer between 1 and 65535: '{val}'")
    return val

class FirewallRuleBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    source_ip: Optional[str] = Field("ANY", max_length=50)
    destination_ip: Optional[str] = Field("ANY", max_length=50)
    destination_port: Optional[str] = Field("ANY", max_length=50)
    protocol: str = Field("ANY", max_length=10)
    action: str = Field("ALLOW", max_length=10)
    priority: int = Field(100, ge=1, le=9999)
    is_enabled: bool = True
    description: Optional[str] = Field(None, max_length=255)

    @field_validator("source_ip")
    @classmethod
    def check_source_ip(cls, v):
        return validate_ip_or_cidr(v)

    @field_validator("destination_ip")
    @classmethod
    def check_destination_ip(cls, v):
        return validate_ip_or_cidr(v)

    @field_validator("destination_port")
    @classmethod
    def check_destination_port(cls, v):
        return validate_port_spec(v)

    @field_validator("protocol")
    @classmethod
    def check_protocol(cls, v):
        proto = v.strip().upper()
        if proto not in ["TCP", "UDP", "ICMP", "ANY"]:
            raise ValueError(f"Protocol must be TCP, UDP, ICMP, or ANY, got '{v}'")
        return proto

    @field_validator("action")
    @classmethod
    def check_action(cls, v):
        act = v.strip().upper()
        if act not in ["ALLOW", "BLOCK"]:
            raise ValueError(f"Action must be ALLOW or BLOCK, got '{v}'")
        return act

class FirewallRuleCreate(FirewallRuleBase):
    pass

class FirewallRuleUpdate(BaseModel):
    name: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[str] = None
    protocol: Optional[str] = None
    action: Optional[str] = None
    priority: Optional[int] = None
    is_enabled: Optional[bool] = None
    description: Optional[str] = None

    @field_validator("source_ip")
    @classmethod
    def check_source_ip(cls, v):
        return validate_ip_or_cidr(v) if v is not None else None

    @field_validator("destination_ip")
    @classmethod
    def check_destination_ip(cls, v):
        return validate_ip_or_cidr(v) if v is not None else None

    @field_validator("destination_port")
    @classmethod
    def check_destination_port(cls, v):
        return validate_port_spec(v) if v is not None else None

    @field_validator("protocol")
    @classmethod
    def check_protocol(cls, v):
        if v is None:
            return None
        proto = v.strip().upper()
        if proto not in ["TCP", "UDP", "ICMP", "ANY"]:
            raise ValueError(f"Protocol must be TCP, UDP, ICMP, or ANY, got '{v}'")
        return proto

    @field_validator("action")
    @classmethod
    def check_action(cls, v):
        if v is None:
            return None
        act = v.strip().upper()
        if act not in ["ALLOW", "BLOCK"]:
            raise ValueError(f"Action must be ALLOW or BLOCK, got '{v}'")
        return act

class FirewallRuleOut(FirewallRuleBase):
    id: int

    class Config:
        from_attributes = True

class DefaultPolicyUpdate(BaseModel):
    policy: str

    @field_validator("policy")
    @classmethod
    def check_policy(cls, v):
        pol = v.strip().upper()
        if pol not in ["ALLOW", "BLOCK"]:
            raise ValueError("Default policy must be either ALLOW or BLOCK")
        return pol

class DefaultPolicyOut(BaseModel):
    policy: str
    description: str

class PacketSimulateRequest(BaseModel):
    source_ip: str
    destination_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: str = "TCP"
    packet_size: int = 64
    event_type: Optional[str] = "CUSTOM_PACKET_TEST"

    @field_validator("source_ip")
    @classmethod
    def check_source_ip(cls, v):
        return validate_ip_or_cidr(v)

    @field_validator("destination_ip")
    @classmethod
    def check_destination_ip(cls, v):
        return validate_ip_or_cidr(v)

    @field_validator("protocol")
    @classmethod
    def check_protocol(cls, v):
        proto = v.strip().upper()
        if proto not in ["TCP", "UDP", "ICMP"]:
            raise ValueError(f"Packet protocol must be TCP, UDP, or ICMP, got '{v}'")
        return proto

    @field_validator("destination_port", "source_port")
    @classmethod
    def check_port(cls, v):
        if v is not None and not (1 <= v <= 65535):
            raise ValueError("Port must be between 1 and 65535")
        return v

class EvaluationStep(BaseModel):
    rule_id: int
    rule_name: str
    priority: int
    is_enabled: bool
    matched: bool
    reason: str

class PacketSimulateResponse(BaseModel):
    decision: str
    matched_rule_id: Optional[int]
    matched_rule_name: Optional[str]
    reason: str
    packet_details: dict
    timestamp: str
    evaluation_steps: List[EvaluationStep]
