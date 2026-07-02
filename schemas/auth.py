from typing import Optional
from pydantic import BaseModel, EmailStr, field_validator, model_validator

from models.user import AccountType
from core.security import validate_password_policy


FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "rediffmail.com", "icould.com", "aol.com", "protonmail.com",
}

ACCEPTED_PERSONAL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
}

class RegisterRequest(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    confirm_password: str
    account_type: AccountType
    organization_name: Optional[str] = None

    @field_validator("full_name")
    @classmethod

    def full_name_not_blanks(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Full name cannot be empty.")
        return v.strip()
    
    @model_validator(mode='after')
    def validate_passwords_match(self) -> "RegisterRequest":
        if self.password != self.confirm_password:
            raise ValueError("Password and Confirm Password do not match.")
        return self

    @model_validator(mode="after")
    def validate_password_strength(self) -> "RegisterRequest":
        errors = validate_password_policy(self.password)
        if errors:
            raise ValueError("".join(errors))
        return self
    
    @model_validator(mode="after")
    def validate_email_by_account_type(self) -> "RegisterRequest":
        domain = self.email.split("@")[-1].lower()

        if self.account_type == AccountType.INDIVIDUAL:
            # Individual accounts MUST use a personal/free email provider
            if domain not in ACCEPTED_PERSONAL_DOMAINS:
                raise ValueError(
                    "Individual accounts must use a personal email address "
                    "(e.g. @gmail.com, @yahoo.com, @outlook.com, @hotmail.com, @icloud.com)."
                )

        elif self.account_type == AccountType.ORGANIZATION:
            # Organization accounts MUST use an official business email
            if not self.organization_name or not self.organization_name.strip():
                raise ValueError(
                    "Organization Name is required for Organization accounts."
                )
            if domain in FREE_EMAIL_DOMAINS:
                raise ValueError(
                    "Organization accounts must use an official business email address "
                    "(e.g. @yourcompany.com). Personal email providers are not accepted."
                )

        return self

    @model_validator(mode="after")
    def validate_organization_fields(self) -> "RegisterRequest":
        if self.account_type == AccountType.ORGANIZATION:
            if not self.organization_name or not self.organization_name.strip():
                raise ValueError("Organization Name is required for Organization accounts.")

            domain = self.email.split("@")[-1].lower()
            if domain in FREE_EMAIL_DOMAINS:
                raise ValueError(
                    "Please use an official business email address for Organization accounts."
                )
        return self
    
class RegisterResponse(BaseModel):  
    message: str
    email: str

class VerifyOTPRequest(BaseModel):
    otp: str

class VerifyOTPResponse(BaseModel):
    message: str
    email: str
    account_type: AccountType

class ResendOTPResponse(BaseModel):
    message: str
    email: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class LoginResponse(BaseModel):
    message: str
    email: str
    full_name: str
    account_type: AccountType
        
class LogoutResponse(BaseModel):
    message: str

class RefreshTokenResponse(BaseModel):
    message: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ForgotPasswordResponse(BaseModel):
    message: str
    email: str

class VerifyForgotOTPRequest(BaseModel):
    otp: str

class VerifyForgotOTPResponse(BaseModel):
    message: str

class ResetPasswordRequest(BaseModel):
    new_password: str
    confirm_new_password: str

    @model_validator(mode="after")
    def validate_passwords_match(self) -> "ResetPasswordRequest":
        if self.new_password != self.confirm_new_password:
            raise ValueError("New Password and Confirm New Password do not match.")
        errors = validate_password_policy(self.new_password)
        if errors:
            raise ValueError(" ".join(errors))
        return self
    
class ResetPasswordResponse(BaseModel):
    message: str