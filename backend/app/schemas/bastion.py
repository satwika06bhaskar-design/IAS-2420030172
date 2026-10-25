from typing import Optional
from pydantic import BaseModel, Field, field_validator
import ipaddress

class BastionHostBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    ip_address: str = Field(..., max_length=50)
    purpose: str = Field(..., max_length=150)
    management_protocol: str = Field("SSH", max_length=20)
    management_port: int = Field(22, ge=1, le=65535)
    admin_access_status: str = Field("MFA_REQUIRED", max_length=50)
    monitoring_status: str = Field("ACTIVE", max_length=50)
    is_enabled: bool = True
    description: Optional[str] = None

    @field_validator("ip_address")
    @classmethod
    def check_ip(cls, v):
        val = v.strip()
        try:
            ipaddress.ip_address(val)
            return val
        except ValueError:
            raise ValueError(f"Invalid IP address: '{val}'")

    @field_validator("management_protocol")
    @classmethod
    def check_protocol(cls, v):
        proto = v.strip().upper()
        if proto not in ["SSH", "HTTPS", "RDP", "VPN", "TELNET", "CUSTOM"]:
            raise ValueError(f"Unsupported management protocol: '{v}'")
        return proto

class BastionHostCreate(BastionHostBase):
    pass

class BastionHostUpdate(BaseModel):
    name: Optional[str] = None
    ip_address: Optional[str] = None
    purpose: Optional[str] = None
    management_protocol: Optional[str] = None
    management_port: Optional[int] = None
    admin_access_status: Optional[str] = None
    monitoring_status: Optional[str] = None
    is_enabled: Optional[bool] = None
    description: Optional[str] = None

    @field_validator("ip_address")
    @classmethod
    def check_ip(cls, v):
        if v is None:
            return None
        val = v.strip()
        try:
            ipaddress.ip_address(val)
            return val
        except ValueError:
            raise ValueError(f"Invalid IP address: '{val}'")

class BastionHostOut(BastionHostBase):
    id: int

    class Config:
        from_attributes = True

class BastionTestRequest(BaseModel):
    host_id: int
    source_ip: str = "203.0.113.45"
    attempted_port: int = 22
    protocol: str = "SSH"
    auth_credentials_valid: bool = True

class BastionTestResponse(BaseModel):
    host_id: int
    host_name: str
    is_enabled: bool
    connection_status: str # "ACCEPTED", "REJECTED_PORT", "REJECTED_HOST_DISABLED", "MFA_CHALLENGE_REQUIRED"
    explanation: str
    security_checks: list[dict]
