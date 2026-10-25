from typing import List, Optional
from fastapi import APIRouter, Query
from app.schemas.educational import ThreatItem, FirewallConceptItem
from app.services.seed_data import THREAT_ENCYCLOPEDIA_DATA, FIREWALL_CONCEPTS_DATA

router = APIRouter(prefix="/api/educational", tags=["Educational Content"])

@router.get("/threats", response_model=List[ThreatItem])
def get_threat_encyclopedia(
    category: Optional[str] = Query(None, description="Intruder, Virus, Worm, Concept"),
    search: Optional[str] = None
):
    results = THREAT_ENCYCLOPEDIA_DATA
    if category:
        results = [t for t in results if t["category"].lower() == category.lower()]
    if search:
        s = search.lower()
        results = [
            t for t in results
            if s in t["title"].lower() or s in t["summary"].lower() or any(s in tag.lower() for tag in t["tags"])
        ]
    return results

@router.get("/threats/{threat_id}", response_model=ThreatItem)
def get_threat_detail(threat_id: str):
    for t in THREAT_ENCYCLOPEDIA_DATA:
        if t["id"] == threat_id:
            return t
    return THREAT_ENCYCLOPEDIA_DATA[0]

@router.get("/firewall-concepts", response_model=List[FirewallConceptItem])
def get_firewall_concepts():
    return FIREWALL_CONCEPTS_DATA
