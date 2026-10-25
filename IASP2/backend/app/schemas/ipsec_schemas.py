from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

class IPPacketData(BaseModel):
    src_ip: str = Field(default="192.168.1.100", description="Source IP address")
    dst_ip: str = Field(default="10.0.0.50", description="Destination IP address")
    protocol: str = Field(default="TCP", description="Transport layer protocol: TCP or UDP")
    src_port: int = Field(default=52431, ge=1, le=65535)
    dst_port: int = Field(default=443, ge=1, le=65535)
    payload: str = Field(default="GET /secure-finance HTTP/1.1\r\nHost: portal.internal", max_length=1000)

class IPsecEncapsulateRequest(BaseModel):
    mode: str = Field(default="tunnel", description="'transport' or 'tunnel'")
    packet: IPPacketData = Field(default_factory=IPPacketData)
    spi: int = Field(default=0x10002000, description="Security Parameters Index (32-bit integer)")
    seq_num: int = Field(default=1, ge=1, description="Sequence Number (32-bit anti-replay counter)")
    tunnel_gateway_src: Optional[str] = Field(default="203.0.113.1", description="Outer Gateway Source IP (Tunnel mode)")
    tunnel_gateway_dst: Optional[str] = Field(default="198.51.100.1", description="Outer Gateway Destination IP (Tunnel mode)")
    cipher: Optional[str] = Field(default="AES-256-GCM", description="ESP encryption/AEAD algorithm")

class IPsecInspectRequest(BaseModel):
    field_id: str
    mode: str = "tunnel"

class PacketFieldInspection(BaseModel):
    field_id: str
    name: str
    layer: str
    size_bytes: int
    is_encrypted: bool
    is_authenticated: bool
    summary: str
    educational_note: str

class IPsecEncapsulateResponse(BaseModel):
    mode: str
    cipher: str
    original_packet: Dict[str, Any]
    encapsulated_packet: Dict[str, Any]
    crypto_details: Dict[str, Any]
    explanation: str
    diagram_nodes: List[Dict[str, Any]]
