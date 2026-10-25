from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

class TLSStartRequest(BaseModel):
    mode: str = Field(default="tls12_rsa", description="Handshake mode: 'tls12_rsa' or 'tls13_dhe'")

class TLSStepRequest(BaseModel):
    step: int = Field(ge=1, le=7, description="Step number to execute")
    simulate_failure: Optional[bool] = Field(default=False, description="Simulate an error or tampering for this step")

class TLSAppDataRequest(BaseModel):
    message: str = Field(min_length=1, max_length=1000, description="Plaintext application message")
    tamper_ciphertext: Optional[bool] = Field(default=False, description="Whether to tamper with the ciphertext before decryption")

class TLSSessionResponse(BaseModel):
    session_id: str
    mode: str
    current_step: int
    step_title: str
    message_direction: str  # "client_to_server", "server_to_client", "internal", etc.
    protocol_state: str     # "in_progress", "established", "failed"
    explanation: str
    crypto_values: Dict[str, Any]
    technical_details: Dict[str, Any]
    verification_status: Dict[str, Any]
    can_advance: bool
    is_complete: bool
    error: Optional[str] = None
