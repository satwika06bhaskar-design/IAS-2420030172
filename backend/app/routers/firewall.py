from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import or_
import datetime

from app.database import get_db
from app.models.firewall_rule import FirewallRule
from app.schemas.firewall import (
    FirewallRuleCreate, FirewallRuleUpdate, FirewallRuleOut,
    DefaultPolicyUpdate, DefaultPolicyOut,
    PacketSimulateRequest, PacketSimulateResponse
)
from app.services.firewall_engine import evaluate_packet_detailed
from app.services.traffic_simulator import get_default_firewall_policy, set_default_firewall_policy
from app.services.seed_data import DEMO_FIREWALL_RULES

router = APIRouter(prefix="/api/firewall", tags=["Firewall"])

@router.get("/rules", response_model=List[FirewallRuleOut])
def get_firewall_rules(
    action: Optional[str] = None,
    protocol: Optional[str] = None,
    is_enabled: Optional[bool] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(FirewallRule)

    if action:
        query = query.filter(FirewallRule.action == action.upper())
    if protocol:
        query = query.filter(FirewallRule.protocol == protocol.upper())
    if is_enabled is not None:
        query = query.filter(FirewallRule.is_enabled == is_enabled)
    if search:
        s = f"%{search.strip()}%"
        query = query.filter(
            or_(
                FirewallRule.name.ilike(s),
                FirewallRule.source_ip.ilike(s),
                FirewallRule.destination_ip.ilike(s),
                FirewallRule.destination_port.ilike(s),
                FirewallRule.description.ilike(s)
            )
        )

    return query.order_by(FirewallRule.priority.asc(), FirewallRule.id.asc()).all()

@router.post("/rules", response_model=FirewallRuleOut, status_code=status.HTTP_201_CREATED)
def create_firewall_rule(rule_in: FirewallRuleCreate, db: Session = Depends(get_db)):
    db_rule = FirewallRule(**rule_in.model_dump())
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    return db_rule

@router.get("/rules/{rule_id}", response_model=FirewallRuleOut)
def get_firewall_rule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail=f"Firewall rule #{rule_id} not found")
    return rule

@router.put("/rules/{rule_id}", response_model=FirewallRuleOut)
def update_firewall_rule(rule_id: int, rule_in: FirewallRuleUpdate, db: Session = Depends(get_db)):
    rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail=f"Firewall rule #{rule_id} not found")
    
    update_data = rule_in.model_dump(exclude_unset=True)
    for field, val in update_data.items():
        setattr(rule, field, val)
    
    db.commit()
    db.refresh(rule)
    return rule

@router.delete("/rules/{rule_id}", status_code=status.HTTP_200_OK)
def delete_firewall_rule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail=f"Firewall rule #{rule_id} not found")
    
    db.delete(rule)
    db.commit()
    return {"message": f"Firewall rule #{rule_id} ('{rule.name}') deleted successfully", "id": rule_id}

@router.patch("/rules/{rule_id}/toggle", response_model=FirewallRuleOut)
def toggle_firewall_rule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail=f"Firewall rule #{rule_id} not found")
    
    rule.is_enabled = not rule.is_enabled
    db.commit()
    db.refresh(rule)
    return rule

@router.get("/default-policy", response_model=DefaultPolicyOut)
def get_default_policy(db: Session = Depends(get_db)):
    policy = get_default_firewall_policy(db)
    return {
        "policy": policy,
        "description": "Default action taken when a packet does not match any enabled rule."
    }

@router.post("/default-policy", response_model=DefaultPolicyOut)
def set_default_policy_route(policy_in: DefaultPolicyUpdate, db: Session = Depends(get_db)):
    policy = set_default_firewall_policy(db, policy_in.policy)
    return {
        "policy": policy,
        "description": f"Default firewall policy updated to {policy}."
    }

@router.post("/simulate-packet", response_model=PacketSimulateResponse)
def simulate_packet_route(req: PacketSimulateRequest, db: Session = Depends(get_db)):
    rules = db.query(FirewallRule).all()
    default_policy = get_default_firewall_policy(db)

    eval_result = evaluate_packet_detailed(
        rules=rules,
        source_ip=req.source_ip,
        destination_ip=req.destination_ip,
        protocol=req.protocol,
        destination_port=req.destination_port,
        default_policy=default_policy
    )

    return {
        "decision": eval_result["decision"],
        "matched_rule_id": eval_result["matched_rule_id"],
        "matched_rule_name": eval_result["matched_rule_name"],
        "reason": eval_result["reason"],
        "packet_details": req.model_dump(),
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "evaluation_steps": eval_result["steps"]
    }

@router.post("/reset-demo")
def reset_firewall_demo_rules(db: Session = Depends(get_db)):
    db.query(FirewallRule).delete()
    for r in DEMO_FIREWALL_RULES:
        db.add(FirewallRule(**r))
    set_default_firewall_policy(db, "BLOCK")
    db.commit()
    return {"message": "Demo firewall rules reset to standard baseline."}
