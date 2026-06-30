import re

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def validate_password_policy(password: str) -> list[str]:

    errors = []

    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")

    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")

    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")

    if not re.search(r"[0-9]", password):
        errors.append("Password must contain at least one digit.")

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=]", password):
        errors.append("Password must contain at least one special character.")

    return errors

