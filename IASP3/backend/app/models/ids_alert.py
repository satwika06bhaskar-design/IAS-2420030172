import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base

class IDSAlert(Base):
    __tablename__ = "ids_alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    source_ip = Column(String(50), nullable=False, index=True)
    destination_ip = Column(String(50), nullable=True)
    alert_type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    detection_method = Column(String(50), nullable=False)
    description = Column(Text, nullable=False)
    related_event_id = Column(Integer, ForeignKey("traffic_events.id", ondelete="SET NULL"), nullable=True)
    is_acknowledged = Column(Boolean, default=False)
    acknowledged_at = Column(DateTime, nullable=True)
    extra_data = Column(Text, nullable=True)

    related_event = relationship("TrafficEvent", back_populates="alerts")
