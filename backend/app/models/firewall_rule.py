import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from app.database import Base

class FirewallRule(Base):
    __tablename__ = "firewall_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    source_ip = Column(String(50), nullable=True, default="ANY")
    destination_ip = Column(String(50), nullable=True, default="ANY")
    destination_port = Column(String(50), nullable=True, default="ANY")
    protocol = Column(String(10), nullable=False, default="ANY")
    action = Column(String(10), nullable=False, default="ALLOW")
    priority = Column(Integer, nullable=False, default=100)
    is_enabled = Column(Boolean, nullable=False, default=True)
    description = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
