from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

class SSHStartRequest(BaseModel):
    client_version: Optional[str] = "SSH-2.0-SecureTunnel_Client_1.0"

class SSHStepRequest(BaseModel):
    step: int = Field(ge=1, le=7, description="SSH step number (1 to 7)")
    host_key_scenario: Optional[str] = Field(default="trusted", description="'trusted', 'unknown_first_time', or 'changed_mismatch'")
    simulate_failure: Optional[bool] = Field(default=False, description="Simulate failure for the step")

class SSHAuthRequest(BaseModel):
    auth_method: str = Field(description="'password' or 'publickey'")
    username: str = Field(default="student", max_length=50)
    password: Optional[str] = Field(default=None, max_length=100)
    public_key_authorized: Optional[bool] = Field(default=True)
    simulate_failure: Optional[bool] = Field(default=False)

class SSHCommandRequest(BaseModel):
    command: str = Field(min_length=1, max_length=500, description="Command to execute in simulated SSH terminal")
    tamper_packet: Optional[bool] = Field(default=False, description="Simulate packet tampering in transit")

class SSHSessionResponse(BaseModel):
    session_id: str
    current_step: int
    step_title: str
    message_direction: str
    protocol_state: str
    explanation: str
    crypto_values: Dict[str, Any]
    technical_details: Dict[str, Any]
    verification_status: Dict[str, Any]
    can_advance: bool
    is_complete: bool
    error: Optional[str] = None
