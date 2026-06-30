
import enum

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from core.database import Base

class AccountType(str, enum.Enum):
    INDIVIDUAL = "individual"
    ORGANIZATION = "organization"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String(255), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    account_type = Column(Enum(AccountType), nullable=False)
    is_active = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    #Relationships
    owned_tenant = relationship("Tenant", back_populates="owner", uselist=False)
    refresh_tokens = relationship("RefreshToken", back_populates="user")