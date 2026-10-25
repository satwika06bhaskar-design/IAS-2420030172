from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.firewall_rule import FirewallRule
from app.models.bastion_host import BastionHost
from app.models.traffic_event import TrafficEvent
from app.models.ids_alert import IDSAlert
from app.services.seed_data import seed_demo_data, DEMO_FIREWALL_RULES, DEMO_BASTION_HOSTS
from app.services.traffic_simulator import run_scenario

router = APIRouter(prefix="/api/demo", tags=["Demo & System"])

@router.post("/load-sample-simulation")
def load_sample_simulation(db: Session = Depends(get_db)):
    """
    Populates sample baseline traffic and a few realistic events so the dashboard
    immediately displays rich, meaningful charts and stats upon launch.
    """
    seed_demo_data(db, force_reset=False)
    
    # Generate baseline normal traffic
    run_scenario(db, "NORMAL_HTTP", count=8, custom_source_ip="192.168.1.45")
    run_scenario(db, "NORMAL_HTTP", count=5, custom_source_ip="192.168.1.102")
    # Generate Telnet probe
    run_scenario(db, "TELNET", count=2, custom_source_ip="198.51.100.23")
    # Generate SSH failed attempt
    run_scenario(db, "FAILED_SSH", count=5, custom_source_ip="203.0.113.195")

    return {
        "message": "Demo rules, bastion host, and sample simulation traffic populated successfully."
    }

@router.post("/load-demo-config")
def load_demo_config(db: Session = Depends(get_db)):
    """
    Loads standard demo firewall rules and bastion hosts without erasing non-conflicting user items.
    """
    inserted_rules = 0
    existing_rule_names = {r.name for r in db.query(FirewallRule.name).all()}
    for r in DEMO_FIREWALL_RULES:
        if r["name"] not in existing_rule_names:
            db.add(FirewallRule(**r))
            inserted_rules += 1

    inserted_hosts = 0
    existing_host_names = {b.name for b in db.query(BastionHost.name).all()}
    for b in DEMO_BASTION_HOSTS:
        if b["name"] not in existing_host_names:
            db.add(BastionHost(**b))
            inserted_hosts += 1

    db.commit()
    return {
        "message": f"Demo configuration loaded. Added {inserted_rules} rules and {inserted_hosts} bastion hosts.",
        "rules_added": inserted_rules,
        "hosts_added": inserted_hosts
    }

@router.post("/reset-all")
def reset_all_data(db: Session = Depends(get_db)):
    """
    Complete reset: clears all traffic events, alerts, custom rules and re-seeds default demo setup.
    """
    db.query(IDSAlert).delete()
    db.query(TrafficEvent).delete()
    db.query(FirewallRule).delete()
    db.query(BastionHost).delete()
    db.commit()

    seed_demo_data(db, force_reset=True)
    return {"message": "All database records have been reset to factory demo state."}
