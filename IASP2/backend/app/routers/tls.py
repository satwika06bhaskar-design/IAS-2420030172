from fastapi import APIRouter, HTTPException, Path
from typing import Dict, Any
from app.schemas.tls_schemas import TLSStartRequest, TLSStepRequest, TLSAppDataRequest, TLSSessionResponse
from app.services.tls_service import tls_service
from app.utils.validation import sanitize_input_text

router = APIRouter(prefix="/api/tls", tags=["TLS"])

@router.post("/start")
def start_tls_session(req: TLSStartRequest) -> Dict[str, Any]:
    """Initialize a new educational TLS session."""
    if req.mode not in ("tls12_rsa", "tls13_dhe"):
        raise HTTPException(status_code=400, detail="Invalid TLS mode. Choose 'tls12_rsa' or 'tls13_dhe'.")

    session = tls_service.create_session(mode=req.mode)
    return {
        "session_id": session.session_id,
        "mode": session.mode,
        "current_step": 0,
        "step_title": "Session Initialized",
        "message": f"Ready to begin {session.mode} handshake simulation.",
        "can_advance": True,
        "is_complete": False
    }

@router.post("/{session_id}/step")
def execute_tls_step(
    session_id: str = Path(..., description="Active session ID"),
    req: TLSStepRequest = ...
) -> Dict[str, Any]:
    """Execute the next handshake step."""
    try:
        result = tls_service.execute_step(session_id, req.step, simulate_failure=req.simulate_failure)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Handshake error: {str(e)}")

@router.get("/{session_id}/status")
def get_tls_status(session_id: str = Path(...)) -> Dict[str, Any]:
    """Retrieve the current state of a TLS session."""
    session = tls_service.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="TLS session not found or expired.")

    return {
        "session_id": session.session_id,
        "mode": session.mode,
        "current_step": session.current_step,
        "protocol_state": session.protocol_state,
        "has_keys": bool(session.client_write_key),
        "error": session.error,
        "messages_count": len(session.messages_exchanged)
    }

@router.post("/{session_id}/application-data")
def send_tls_application_data(
    session_id: str = Path(...),
    req: TLSAppDataRequest = ...
) -> Dict[str, Any]:
    """Demonstrate authenticated symmetric encryption using derived session keys."""
    clean_message = sanitize_input_text(req.message, max_length=1000)
    try:
        result = tls_service.process_application_data(session_id, clean_message, tamper_ciphertext=req.tamper_ciphertext)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Application data error: {str(e)}")

@router.post("/{session_id}/verify")
def verify_tls_handshake(session_id: str = Path(...)) -> Dict[str, Any]:
    """Re-verify transcript and session keys."""
    session = tls_service.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="TLS session not found.")
    return {
        "session_id": session.session_id,
        "current_step": session.current_step,
        "protocol_state": session.protocol_state,
        "keys_derived": bool(session.client_write_key),
        "transcript_length": len(session.transcript)
    }

@router.post("/{session_id}/reset")
def reset_tls_session(session_id: str = Path(...)) -> Dict[str, Any]:
    """Reset the session back to step 0."""
    session = tls_service.reset_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found.")
    return {
        "session_id": session.session_id,
        "mode": session.mode,
        "current_step": 0,
        "message": "Session reset successfully."
    }
