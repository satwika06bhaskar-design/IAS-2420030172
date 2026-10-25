from fastapi import APIRouter, HTTPException, Path
from typing import Dict, Any
from app.schemas.ssh_schemas import (
    SSHStartRequest,
    SSHStepRequest,
    SSHAuthRequest,
    SSHCommandRequest,
    SSHSessionResponse
)
from app.services.ssh_service import ssh_service
from app.utils.validation import sanitize_input_text

router = APIRouter(prefix="/api/ssh", tags=["SSH"])

@router.post("/start")
def start_ssh_session(req: SSHStartRequest) -> Dict[str, Any]:
    """Initialize an educational SSH session."""
    session = ssh_service.create_session(client_version=req.client_version or "SSH-2.0-SecureTunnel_Client_1.0")
    return {
        "session_id": session.session_id,
        "current_step": 0,
        "client_version": session.client_version,
        "server_version": session.server_version,
        "step_title": "SSH Connection Initialized",
        "message": "Ready to begin SSH protocol sequence.",
        "can_advance": True,
        "is_complete": False
    }

@router.post("/{session_id}/step")
def execute_ssh_step(
    session_id: str = Path(...),
    req: SSHStepRequest = ...
) -> Dict[str, Any]:
    """Advance to the requested SSH handshake step."""
    try:
        result = ssh_service.execute_step(
            session_id,
            req.step,
            host_key_scenario=req.host_key_scenario or "trusted",
            simulate_failure=req.simulate_failure or False
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SSH protocol error: {str(e)}")

@router.get("/{session_id}/status")
def get_ssh_status(session_id: str = Path(...)) -> Dict[str, Any]:
    """Get current status of SSH session."""
    session = ssh_service.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="SSH session not found.")

    return {
        "session_id": session.session_id,
        "current_step": session.current_step,
        "protocol_state": session.protocol_state,
        "user_authenticated": session.user_authenticated,
        "authenticated_user": session.authenticated_user,
        "auth_method_used": session.auth_method_used,
        "error": session.error
    }

@router.post("/{session_id}/authenticate")
def authenticate_ssh_user(
    session_id: str = Path(...),
    req: SSHAuthRequest = ...
) -> Dict[str, Any]:
    """Authenticate SSH user with password or public key."""
    try:
        result = ssh_service.authenticate_user(
            session_id=session_id,
            auth_method=req.auth_method,
            username=req.username,
            password=req.password,
            public_key_authorized=req.public_key_authorized if req.public_key_authorized is not None else True,
            simulate_failure=req.simulate_failure or False
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SSH user authentication error: {str(e)}")

@router.post("/{session_id}/application-data")
def send_ssh_command(
    session_id: str = Path(...),
    req: SSHCommandRequest = ...
) -> Dict[str, Any]:
    """Execute command in simulated SSH remote terminal."""
    clean_cmd = sanitize_input_text(req.command, max_length=500)
    try:
        result = ssh_service.execute_command(
            session_id=session_id,
            command=clean_cmd,
            tamper_packet=req.tamper_packet or False
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SSH terminal error: {str(e)}")

@router.post("/{session_id}/reset")
def reset_ssh_session(session_id: str = Path(...)) -> Dict[str, Any]:
    """Reset SSH session back to initial state."""
    session = ssh_service.reset_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="SSH session not found.")
    return {
        "session_id": session.session_id,
        "current_step": 0,
        "message": "SSH session reset successfully."
    }
