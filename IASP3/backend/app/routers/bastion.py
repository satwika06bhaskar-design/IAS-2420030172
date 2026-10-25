from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.bastion_host import BastionHost
from app.schemas.bastion import (
    BastionHostCreate, BastionHostUpdate, BastionHostOut,
    BastionTestRequest, BastionTestResponse
)

router = APIRouter(prefix="/api/bastion", tags=["Bastion Host"])

@router.get("/hosts", response_model=List[BastionHostOut])
def get_bastion_hosts(db: Session = Depends(get_db)):
    return db.query(BastionHost).order_by(BastionHost.id.asc()).all()

@router.post("/hosts", response_model=BastionHostOut, status_code=status.HTTP_201_CREATED)
def create_bastion_host(host_in: BastionHostCreate, db: Session = Depends(get_db)):
    host = BastionHost(**host_in.model_dump())
    db.add(host)
    db.commit()
    db.refresh(host)
    return host

@router.get("/hosts/{host_id}", response_model=BastionHostOut)
def get_bastion_host(host_id: int, db: Session = Depends(get_db)):
    host = db.query(BastionHost).filter(BastionHost.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Bastion host configuration not found")
    return host

@router.put("/hosts/{host_id}", response_model=BastionHostOut)
def update_bastion_host(host_id: int, host_in: BastionHostUpdate, db: Session = Depends(get_db)):
    host = db.query(BastionHost).filter(BastionHost.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Bastion host configuration not found")
    
    update_data = host_in.model_dump(exclude_unset=True)
    for field, val in update_data.items():
        setattr(host, field, val)

    db.commit()
    db.refresh(host)
    return host

@router.delete("/hosts/{host_id}")
def delete_bastion_host(host_id: int, db: Session = Depends(get_db)):
    host = db.query(BastionHost).filter(BastionHost.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Bastion host configuration not found")
    db.delete(host)
    db.commit()
    return {"message": f"Bastion host '{host.name}' deleted successfully", "id": host_id}

@router.patch("/hosts/{host_id}/toggle", response_model=BastionHostOut)
def toggle_bastion_host(host_id: int, db: Session = Depends(get_db)):
    host = db.query(BastionHost).filter(BastionHost.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Bastion host configuration not found")
    
    host.is_enabled = not host.is_enabled
    db.commit()
    db.refresh(host)
    return host

@router.post("/test-connection", response_model=BastionTestResponse)
def test_bastion_connection(req: BastionTestRequest, db: Session = Depends(get_db)):
    host = db.query(BastionHost).filter(BastionHost.id == req.host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Target bastion host not found")

    checks = []

    # Check 1: Host enabled
    if not host.is_enabled:
        checks.append({
            "check": "Host Operational Status",
            "passed": False,
            "detail": f"Bastion host '{host.name}' is currently offline/disabled in configuration."
        })
        return {
            "host_id": host.id,
            "host_name": host.name,
            "is_enabled": host.is_enabled,
            "connection_status": "REJECTED_HOST_DISABLED",
            "explanation": f"Connection dropped: Bastion host '{host.name}' is disabled.",
            "security_checks": checks
        }
    else:
        checks.append({
            "check": "Host Operational Status",
            "passed": True,
            "detail": "Bastion host is operational and listening."
        })

    # Check 2: Protocol & Port match
    proto_match = req.protocol.upper() == host.management_protocol.upper()
    port_match = req.attempted_port == host.management_port
    if not (proto_match and port_match):
        checks.append({
            "check": "Service Port & Protocol Binding",
            "passed": False,
            "detail": (
                f"Attempted connection on {req.protocol}:{req.attempted_port}. Bastion only listens on "
                f"{host.management_protocol}:{host.management_port}. Unnecessary ports are stripped by hardening."
            )
        })
        return {
            "host_id": host.id,
            "host_name": host.name,
            "is_enabled": host.is_enabled,
            "connection_status": "REJECTED_PORT",
            "explanation": f"Connection refused: Bastion only exposes {host.management_protocol} on port {host.management_port}.",
            "security_checks": checks
        }
    else:
        checks.append({
            "check": "Service Port & Protocol Binding",
            "passed": True,
            "detail": f"Matched configured management port {host.management_port} ({host.management_protocol})."
        })

    # Check 3: Authentication and Access policy
    if host.admin_access_status == "DISABLED":
        checks.append({
            "check": "Administrative Access Policy",
            "passed": False,
            "detail": "Administrative ingress is completely disabled on this bastion node."
        })
        return {
            "host_id": host.id,
            "host_name": host.name,
            "is_enabled": host.is_enabled,
            "connection_status": "REJECTED_DISABLED_ACCESS",
            "explanation": "Administrative access is currently locked down for this host.",
            "security_checks": checks
        }
    elif host.admin_access_status == "MFA_REQUIRED":
        checks.append({
            "check": "Authentication & MFA Verification",
            "passed": True,
            "detail": "Primary credentials valid. Step-up Multi-Factor Authentication (TOTP/FIDO2) challenge verified."
        })
        checks.append({
            "check": "Audit & Session Recording",
            "passed": True,
            "detail": f"Session ingress logged to SIEM with status: {host.monitoring_status}."
        })
        return {
            "host_id": host.id,
            "host_name": host.name,
            "is_enabled": host.is_enabled,
            "connection_status": "ACCEPTED",
            "explanation": f"Secure administrative tunnel successfully brokered through Bastion '{host.name}' to internal enclave.",
            "security_checks": checks
        }
    else:
        checks.append({
            "check": "Authentication Policy",
            "passed": True,
            "detail": f"Access granted under policy: {host.admin_access_status}."
        })
        return {
            "host_id": host.id,
            "host_name": host.name,
            "is_enabled": host.is_enabled,
            "connection_status": "ACCEPTED",
            "explanation": f"Connection brokered successfully through '{host.name}'.",
            "security_checks": checks
        }
