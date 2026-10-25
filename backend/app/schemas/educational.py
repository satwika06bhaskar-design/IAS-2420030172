from typing import List, Optional
from pydantic import BaseModel

class ThreatItem(BaseModel):
    id: str
    title: str
    category: str # "Intruder", "Virus", "Worm", "Concept"
    summary: str
    definition: str
    propagation_or_behavior: str
    potential_effects: str
    prevention: str
    detection: str
    recovery: str
    tags: List[str]

class FirewallConceptItem(BaseModel):
    id: str
    name: str
    definition: str
    how_it_works: str
    what_it_examines: str
    advantages: List[str]
    limitations: List[str]
    practical_example: str
    sentinel_simulation_note: str

class HardeningPractice(BaseModel):
    title: str
    description: str
    category: str
    recommendation: str
