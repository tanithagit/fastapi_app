import uuid
from datetime import datetime, timedelta, timezone

from jose import jwt, JWTError

from core.config import settings

def create_otp_token(email: str, purpose: str) -> str:
    expire =datetime.now(timezone.utc) + timedelta(minutes=settings.OTP_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": email,
        "purpose": purpose,
        "type": "otp",
        "exp": expire,
    }
    return jwt.encode(payload, settings.OTP_TOKEN_SECRET_KEY, algorithm=settings.ALGORITHM)

def decode_otp_token(token: str) -> dict:
    return jwt.decode(token, settings.OTP_TOKEN_SECRET_KEY, algorithms=[settings.ALGORITHM])

#Access Token

def create_access_token(user_id: int, email: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "email": email,
        "type": "access",
        "exp": expire,
    }
    return jwt.encode(payload, settings.ACCESS_TOKEN_SECRET_KEY, algorithm=settings.ALGORITHM)

def decode_access_token(token: str) -> dict:
    return jwt.decode(token, settings.ACCESS_TOKEN_SECRET_KEY, algorithms=[settings.ALGORITHM])

# Refresh Token

def create_refresh_token(user_id: int) -> str:

    expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "sub": str(user_id),
        "type": "refresh",
        "exp": expire,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.REFRESH_TOKEN_SECRET_KEY, algorithm=settings.ALGORITHM)

def decode_refresh_token(token: str) -> dict:
    return jwt.decode(token, settings.REFRESH_TOKEN_SECRET_KEY, algorithms=[settings.ALGORITHM])

