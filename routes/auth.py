from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Response, Request, HTTPException, status, Cookie
from sqlalchemy.orm import Session

from jose import JWTError
from fastapi import Cookie


from core.database import get_db
from core.config import settings
from core.security import hash_password, verify_password
from core.jwt_handler import create_otp_token, decode_refresh_token, decode_otp_token, create_access_token, create_refresh_token
from core.otp_handler import generate_otp, send_otp_email
from models.user import User, AccountType
from models.otp_verification import OTPVerification, OTPPurpose

from models.tenant import Tenant, TenantStatus

from models.refresh_token import RefreshToken
from schemas.auth import (
    RegisterRequest, RegisterResponse,
    LoginRequest, LoginResponse, LogoutResponse, 
    RefreshTokenResponse,
    VerifyOTPRequest, 
    VerifyOTPResponse,
    ResendOTPResponse,
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    VerifyForgotOTPRequest,
    VerifyForgotOTPResponse,
    ResetPasswordRequest,
    ResetPasswordResponse,
    
)

router = APIRouter()

@router.post("/register", 
             response_model=RegisterResponse,
             status_code=status.HTTP_201_CREATED,
             tags=["Authentication APIs"],
             responses={
                 409: {"description": "An account with this email already exists."},
                 422: {"description": "Validation error - password policy, mismatched passwords, or missing organization name."},
    },
)
                 
             
def register(payload: RegisterRequest, response: Response, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == payload.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )
    
    otp_code = generate_otp()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.OTP_TOKEN_EXPIRE_MINUTES)
    
    db.query(OTPVerification).filter(
        OTPVerification.email == payload.email,
        OTPVerification.purpose == OTPPurpose.REGISTRATION,
        OTPVerification.verified == False,  # noqa: E712
    ).delete()
    db.commit()

    otp_record = OTPVerification(
        email=payload.email,
        otp=otp_code,
        purpose=OTPPurpose.REGISTRATION,
        expires_at=expires_at,
        verified=False,
        retry_count=0,
        pending_full_name=payload.full_name,
        pending_password_hash=hash_password(payload.password),
        pending_account_type=payload.account_type,
        pending_organization_name=payload.organization_name,
    )
    db.add(otp_record)
    db.commit()

    
    otp_token = create_otp_token(email=payload.email, purpose=OTPPurpose.REGISTRATION.value)
    response.set_cookie(
        key="otp_token",
        value=otp_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        max_age=settings.OTP_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )

    send_otp_email(email=payload.email, otp=otp_code, purpose="registration")

    return RegisterResponse(
        message="OTP sent to your email. Please verify to complete registration.",
        email=payload.email,
    )



@router.post(
    "/verify-otp", 
     response_model=VerifyOTPResponse,
     tags=["Authentication APIs"],
     responses={
         400: {"description": "Invalid OTP, expired OTP, invalid token purpose, or no pending registration found."},
         401: {"description": "OTP session cookie missing, invalid, or expired."},
         429: {"description": "Maximum OTP attempts exceeded."},
    },
)
def verify_otp(
    payload: VerifyOTPRequest, 
    request: Request, 
    response: Response, 
    db: Session = Depends(get_db),
    otp_token: str = Cookie(None, description="Short-lived JWT issued during registration, identifies which email this OTP belongs to."),
):
    otp_token = request.cookies.get("otp_token")
    if not otp_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OTP session not found or expired. Please register again.",
        )

    # 2. Decode and validate the OTP JWT
    try:
        token_payload = decode_otp_token(otp_token)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OTP session expired or invalid. Please register again.",
        )

    email = token_payload.get("sub")
    purpose = token_payload.get("purpose")

    if purpose != OTPPurpose.REGISTRATION.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP token purpose.",
        )

    # 3. Fetch the latest unverified registration OTP record for this email
    otp_record = (
        db.query(OTPVerification)
        .filter(
            OTPVerification.email == email,
            OTPVerification.purpose == OTPPurpose.REGISTRATION,
            OTPVerification.verified == False,  # noqa: E712
        )
        .order_by(OTPVerification.id.desc())
        .first()
    )

    if not otp_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending registration found. Please register again.",
        )

    # 4. Check expiry
    if datetime.now(timezone.utc) > otp_record.expires_at.replace(tzinfo=timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP has expired. Please request a new one.",
        )

    # 5. Check max retry count
    if otp_record.retry_count >= settings.OTP_MAX_RETRY:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Maximum OTP attempts exceeded. Please request a new OTP.",
        )

    # 6. Check OTP correctness
    if payload.otp != otp_record.otp:
        otp_record.retry_count += 1
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP.",
        )

    # 7. OTP is correct - create the real User
    new_user = User(
        full_name=otp_record.pending_full_name,
        email=otp_record.email,
        password_hash=otp_record.pending_password_hash,
        account_type=otp_record.pending_account_type,
        is_active=True,
    )
    db.add(new_user)
    db.flush()  # get new_user.id without committing yet

    # 8. If Organization account, create the Tenant and assign this user as owner
    if otp_record.pending_account_type == AccountType.ORGANIZATION:
        new_tenant = Tenant(
            organization_name=otp_record.pending_organization_name,
            owner_user_id=new_user.id,
            status=TenantStatus.ACTIVE,
        )
        db.add(new_tenant)

    # 9. Mark OTP record as verified (keep for audit trail rather than deleting)
    otp_record.verified = True
    db.commit()

    # 10. Clear the otp_token cookie - it's no longer needed
    response.delete_cookie(key="otp_token", path="/")

    return VerifyOTPResponse(
        message="Account verified and activated successfully.",
        email=new_user.email,
        account_type=new_user.account_type,
    )
    
    from schemas.auth import ResendOTPResponse


@router.post(
    "/resend-otp", 
    response_model=ResendOTPResponse,
    tags=["Authentication APIs"],
    responses={
        400: {"description": "No pending verification found."},
        401: {"description": "OTP session cookie missing, invalid, or expired."},
    },
)

def resend_otp(
    request: Request, 
    response: Response, 
    db: Session = Depends(get_db),
    otp_token: str = Cookie(None, description="Set by /register or a previous /resend-otp call."),
):

    otp_token = request.cookies.get("otp_token")
    if not otp_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OTP session not found or expired. Please register again.",
        )

    # 2. Decode and validate the OTP JWT
    try:
        token_payload = decode_otp_token(otp_token)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OTP session expired or invalid. Please register again.",
        )

    email = token_payload.get("sub")
    purpose = token_payload.get("purpose")

    # 3. Find the existing pending OTP record for this email + purpose
    otp_record = (
        db.query(OTPVerification)
        .filter(
            OTPVerification.email == email,
            OTPVerification.purpose == purpose,
            OTPVerification.verified == False,  # noqa: E712
        )
        .order_by(OTPVerification.id.desc())
        .first()
    )

    if not otp_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending verification found. Please register again.",
        )

    # 4. Generate a new OTP, reset expiry and retry count on the SAME record
    #    (keeps pending_* registration data intact)
    new_otp_code = generate_otp()
    otp_record.otp = new_otp_code
    otp_record.expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=settings.OTP_TOKEN_EXPIRE_MINUTES
    )
    otp_record.retry_count = 0
    db.commit()

    # 5. Issue a fresh OTP JWT (refreshes the 5-minute expiry window) + cookie
    new_otp_token = create_otp_token(email=email, purpose=purpose)
    response.set_cookie(
        key="otp_token",
        value=new_otp_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        max_age=settings.OTP_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )

    # 6. "Resend" the OTP email (mocked)
    send_otp_email(email=email, otp=new_otp_code, purpose=purpose)

    return ResendOTPResponse(
        message="A new OTP has been sent to your email.",
        email=email,
    )
@router.post(
    "/login", 
    response_model=LoginResponse,
    tags=["Authentication APIs"],
    responses={
        401: {"description": "Invalid email or password."},
        403: {"description": "Account is not active."},
    },
)
def login(payload: LoginRequest, response: Response, db: Session = Depends(get_db)):
    # 1. Find the user
    user = db.query(User).filter(User.email == payload.email).first()

    # 2. Validate credentials (generic error message - don't reveal whether
    #    the email exists or the password was wrong, to avoid email enumeration)
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    # 3. Check account is active (should always be true post-OTP-verification,
    #    but guards against edge cases / future admin-disable features)
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is not active. Please complete registration verification.",
        )

    # 4. Generate Access Token + Refresh Token
    access_token = create_access_token(user_id=user.id, email=user.email)
    refresh_token_str = create_refresh_token(user_id=user.id)

    # 5. Store refresh token in DB (so we can revoke it later on logout)
    refresh_token_record = RefreshToken(
        user_id=user.id,
        token=refresh_token_str,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        is_revoked=False,
    )
    db.add(refresh_token_record)
    db.commit()

    # 6. Set both tokens as HttpOnly cookies
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token_str,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        path="/",
    )

    return LoginResponse(
        message="Login successful.",
        email=user.email,
        full_name=user.full_name,
        account_type=user.account_type,
    )  

@router.post(
    "/logout", 
    response_model=LogoutResponse,
    tags=["Authentication APIs"],
)
def logout(
    request: Request, 
    response: Response, 
    db: Session = Depends(get_db),
    refresh_token: str = Cookie(None, description="Set by /login. Used to revoke the session server-side."),
):
    # 1. Read the refresh_token cookie
    refresh_token_str = request.cookies.get("refresh_token")

    # 2. If present, revoke it in the DB (mark used, don't delete - audit trail)
    if refresh_token_str:
        token_record = (
            db.query(RefreshToken)
            .filter(RefreshToken.token == refresh_token_str)
            .first()
        )
        if token_record:
            token_record.is_revoked = True
            db.commit()

    # 3. Clear both cookies regardless of whether a valid token was found
    response.delete_cookie(key="access_token", path="/")
    response.delete_cookie(key="refresh_token", path="/")

    return LogoutResponse(message="Logged out successfully.")  

@router.post(
    "/refresh-token", 
    response_model=RefreshTokenResponse,
    tags=["Authentication APIs"],
    responses={
        401: {"description": "Refresh token missing, invalid, expired, or revoked."},
        403: {"description": "Account is not active."},
    },
)
def refresh_token_endpoint(
    request: Request, 
    response: Response, 
    db: Session = Depends(get_db),
    refresh_token: str = Cookie(None, description="Set by /login. Used to issue a new access token (rotates this token too)."),
):
    # 1. Read the refresh_token cookie
    refresh_token_str = request.cookies.get("refresh_token")
    if not refresh_token_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found. Please log in again.",
        )

    # 2. Decode and validate the JWT itself (signature + expiry)
    try:
        payload = decode_refresh_token(refresh_token_str)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token is invalid or expired. Please log in again.",
        )

    user_id = int(payload.get("sub"))

    # 3. Validate against the DB record (catches logged-out / revoked tokens
    #    even if the JWT itself hasn't expired yet)
    token_record = (
        db.query(RefreshToken)
        .filter(
            RefreshToken.token == refresh_token_str,
            RefreshToken.user_id == user_id,
        )
        .first()
    )

    if not token_record or token_record.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked. Please log in again.",
        )

    # 4. Fetch the user (in case the account was deactivated since login)
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is not active.",
        )

    # 5. Rotate the refresh token: revoke the old one, issue a new one
    token_record.is_revoked = True

    new_refresh_token_str = create_refresh_token(user_id=user.id)
    new_refresh_token_record = RefreshToken(
        user_id=user.id,
        token=new_refresh_token_str,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        is_revoked=False,
    )
    db.add(new_refresh_token_record)
    db.commit()

    # 6. Issue a new access token
    new_access_token = create_access_token(user_id=user.id, email=user.email)

    # 7. Set both new cookies
    response.set_cookie(
        key="access_token",
        value=new_access_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )
    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token_str,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        path="/",
    )

    return RefreshTokenResponse(message="Token refreshed successfully.")


@router.post(
    "/forgot-password", 
    response_model=ForgotPasswordResponse,
    tags=["Password Management APIs"],
)
def forgot_password(payload: ForgotPasswordRequest, response: Response, db: Session = Depends(get_db)):
    # 1. Check the user exists. We still return a generic success message either way
    #    (see note below) to avoid leaking which emails are registered.
    user = db.query(User).filter(User.email == payload.email).first()

    if user:
        # 2. Generate OTP + expiry
        otp_code = generate_otp()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.OTP_TOKEN_EXPIRE_MINUTES)

        # 3. Remove any old, unverified password-reset OTPs for this email
        db.query(OTPVerification).filter(
            OTPVerification.email == payload.email,
            OTPVerification.purpose == OTPPurpose.PASSWORD_RESET,
            OTPVerification.verified == False,  # noqa: E712
        ).delete()
        db.commit()

        # 4. Store the OTP record (no pending_* fields needed here -
        #    we're resetting an EXISTING user's password, not creating one)
        otp_record = OTPVerification(
            email=payload.email,
            otp=otp_code,
            purpose=OTPPurpose.PASSWORD_RESET,
            expires_at=expires_at,
            verified=False,
            retry_count=0,
        )
        db.add(otp_record)
        db.commit()

        # 5. Create OTP JWT cookie
        otp_token = create_otp_token(email=payload.email, purpose=OTPPurpose.PASSWORD_RESET.value)
        response.set_cookie(
            key="otp_token",
            value=otp_token,
            httponly=True,
            secure=settings.COOKIE_SECURE,
            samesite=settings.COOKIE_SAMESITE,
            max_age=settings.OTP_TOKEN_EXPIRE_MINUTES * 60,
            path="/",
        )

        # 6. "Send" OTP email (mocked)
        send_otp_email(email=payload.email, otp=otp_code, purpose="password_reset")

    # 7. Always return the same generic message, whether or not the email existed
    return ForgotPasswordResponse(
        message="If an account exists with this email, an OTP has been sent.",
        email=payload.email,
    )


@router.post(
    "/verify-forgot-otp", 
    response_model=VerifyForgotOTPResponse,
    tags=["Password Management APIs"],
    responses={
        400: {"description": "Invalid OTP, expired OTP, invalid token purpose, or no pending reset request found."},
        401: {"description": "OTP session cookie missing, invalid, or expired."},
        429: {"description": "Maximum OTP attempts exceeded."},
    },
)
def verify_forgot_otp(
    payload: VerifyForgotOTPRequest, 
    request: Request, 
    db: Session = Depends(get_db),
    otp_token: str = Cookie(None, description="Set by /forgot-password. Identifies which email this reset OTP belongs to."),
):
    # 1. Read the otp_token cookie
    otp_token = request.cookies.get("otp_token")
    if not otp_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OTP session not found or expired. Please request a new one.",
        )

    # 2. Decode and validate the OTP JWT
    try:
        token_payload = decode_otp_token(otp_token)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OTP session expired or invalid. Please request a new one.",
        )

    email = token_payload.get("sub")
    purpose = token_payload.get("purpose")

    if purpose != OTPPurpose.PASSWORD_RESET.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP token purpose.",
        )

    # 3. Fetch the latest unverified password-reset OTP record for this email
    otp_record = (
        db.query(OTPVerification)
        .filter(
            OTPVerification.email == email,
            OTPVerification.purpose == OTPPurpose.PASSWORD_RESET,
            OTPVerification.verified == False,  # noqa: E712
        )
        .order_by(OTPVerification.id.desc())
        .first()
    )

    if not otp_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending password reset request found.",
        )

    # 4. Check expiry
    if datetime.now(timezone.utc) > otp_record.expires_at.replace(tzinfo=timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP has expired. Please request a new one.",
        )

    # 5. Check max retry count
    if otp_record.retry_count >= settings.OTP_MAX_RETRY:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Maximum OTP attempts exceeded. Please request a new OTP.",
        )

    # 6. Check OTP correctness
    if payload.otp != otp_record.otp:
        otp_record.retry_count += 1
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP.",
        )

    # 7. Mark OTP as verified - this "unlocks" the reset-password step.
    #    We deliberately do NOT clear the otp_token cookie here, since
    #    reset-password still needs it to know which email is authorized.
    otp_record.verified = True
    db.commit()

    return VerifyForgotOTPResponse(message="OTP verified. You may now reset your password.")


@router.post(
        "/reset-password", 
        response_model=ResetPasswordResponse,
        tags=["Password Management APIs"],
        responses={
        400: {"description": "OTP verification step has not been completed."},
        401: {"description": "OTP session cookie missing, invalid, or expired."},
        404: {"description": "User not found."},
        422: {"description": "Password validation error (mismatch or policy violation)."},
    },
)
def reset_password(
    payload: ResetPasswordRequest, 
    request: Request, 
    response: Response, 
    db: Session = Depends(get_db),
     otp_token: str = Cookie(None, description="Set by /forgot-password, confirmed by /verify-forgot-otp."),
):
    # 1. Read the otp_token cookie
    otp_token = request.cookies.get("otp_token")
    if not otp_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OTP session not found or expired. Please start the password reset process again.",
        )

    # 2. Decode and validate the OTP JWT
    try:
        token_payload = decode_otp_token(otp_token)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OTP session expired or invalid. Please start the password reset process again.",
        )

    email = token_payload.get("sub")
    purpose = token_payload.get("purpose")

    if purpose != OTPPurpose.PASSWORD_RESET.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP token purpose.",
        )

    # 3. Confirm the OTP was actually verified in the previous step
    otp_record = (
        db.query(OTPVerification)
        .filter(
            OTPVerification.email == email,
            OTPVerification.purpose == OTPPurpose.PASSWORD_RESET,
            OTPVerification.verified == True,  # noqa: E712
        )
        .order_by(OTPVerification.id.desc())
        .first()
    )

    if not otp_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP verification step has not been completed.",
        )

    # 4. Find the user and update their password
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    user.password_hash = hash_password(payload.new_password)
    db.commit()

    # 5. Revoke ALL existing refresh tokens for this user - forces re-login
    #    everywhere, in case the password was compromised
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user.id,
        RefreshToken.is_revoked == False,  # noqa: E712
    ).update({"is_revoked": True})
    db.commit()

    # 6. Clear the otp_token cookie - the reset flow is complete
    response.delete_cookie(key="otp_token", path="/")

    return ResetPasswordResponse(message="Password has been reset successfully. Please log in again.")
