import enum
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Enum
from sqlalchemy.sql import func

from core.database import Base
from models.user import AccountType

class OTPPurpose(str, enum.Enum):
    REGISTRATION = "registration"
    PASSWORD_RESET = "password_reset"

class OTPVerification(Base):
    __tablename__ = "otp_verifications"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), index=True, nullable=False)
    otp = Column(String(6), nullable=False)
    purpose = Column(Enum(OTPPurpose), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    verified = Column(Boolean, default=False)
    retry_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    pending_full_name = Column(String(255), nullable=True)
    pending_password_hash = Column(String(255), nullable=True)
    pending_account_type = Column(Enum(AccountType), nullable=True)
    pending_organization_name = Column(String(255), nullable=True)