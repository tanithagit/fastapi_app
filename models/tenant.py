import enum

from sqlalchemy import Column, Integer, String, DateTime, Enum, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from core.database import Base

class TenantStatus(str, enum.Enum):
    ACTIVE = "active"
    SUSPENDED = " suspended"
    INACTIVE = "inactive"

class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True, index=True)
    organization_name = Column(String(255), nullable=False)
    owner_user_id = Column(Integer, ForeignKey("users.id"), nullable=False, unique=True)
    status = Column(Enum(TenantStatus), default=TenantStatus.ACTIVE, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


    #Relationships
    owner = relationship("User", back_populates="owned_tenant")