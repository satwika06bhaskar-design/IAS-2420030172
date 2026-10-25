import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from app.database import Base

class BastionHost(Base):
    __tablename__ = "bastion_hosts"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    ip_address = Column(String(50), nullable=False)
    purpose = Column(String(150), nullable=False)
    management_protocol = Column(String(20), nullable=False, default="SSH")
    management_port = Column(Integer, nullable=False, default=22)
    admin_access_status = Column(String(50), nullable=False, default="MFA_REQUIRED")
    monitoring_status = Column(String(50), nullable=False, default="ACTIVE")
    is_enabled = Column(Boolean, nullable=False, default=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
