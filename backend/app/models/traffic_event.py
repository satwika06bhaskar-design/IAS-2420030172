import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import relationship
from app.database import Base

class TrafficEvent(Base):
    __tablename__ = "traffic_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    source_ip = Column(String(50), nullable=False, index=True)
    destination_ip = Column(String(50), nullable=False)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=False)
    packet_size = Column(Integer, nullable=False, default=64)
    event_type = Column(String(50), nullable=False)
    ssh_auth_success = Column(Boolean, nullable=True)
    
    firewall_decision = Column(String(10), nullable=False)
    matched_rule_id = Column(Integer, nullable=True)
    matched_rule_name = Column(String(100), nullable=True)
    firewall_reason = Column(String(255), nullable=False)
    has_alert = Column(Boolean, default=False)

    alerts = relationship("IDSAlert", back_populates="related_event", cascade="all, delete-orphan")
