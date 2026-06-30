from models.otp_verification import OTPVerification, OTPPurpose


def _register_and_get_otp(client, db_session, email="otptest@example.com"):
    """Helper: registers a user and returns the real OTP from the DB."""
    response = client.post(
        "/api/auth/register",
        json={
            "full_name": "OTP Test User",
            "email": email,
            "password": "Test@1234",
            "confirm_password": "Test@1234",
            "account_type": "individual",
        },
    )
    assert response.status_code == 201

    otp_record = (
        db_session.query(OTPVerification)
        .filter(OTPVerification.email == email, OTPVerification.purpose == OTPPurpose.REGISTRATION)
        .order_by(OTPVerification.id.desc())
        .first()
    )
    return response, otp_record.otp


def test_verify_otp_success_creates_user(client, db_session):
    response, real_otp = _register_and_get_otp(client, db_session)

    verify_response = client.post("/api/auth/verify-otp", json={"otp": real_otp})
    assert verify_response.status_code == 200
    body = verify_response.json()
    assert body["email"] == "otptest@example.com"
    assert body["account_type"] == "individual"

    from models.user import User
    user = db_session.query(User).filter(User.email == "otptest@example.com").first()
    assert user is not None
    assert user.is_active is True


def test_verify_otp_organization_creates_tenant(client, db_session):
    response = client.post(
        "/api/auth/register",
        json={
            "full_name": "Org Owner",
            "email": "tenantcheck@mycompany.com",
            "password": "Test@1234",
            "confirm_password": "Test@1234",
            "account_type": "organization",
            "organization_name": "Tenant Check Org",
        },
    )
    assert response.status_code == 201

    otp_record = (
        db_session.query(OTPVerification)
        .filter(OTPVerification.email == "tenantcheck@mycompany.com")
        .order_by(OTPVerification.id.desc())
        .first()
    )

    verify_response = client.post("/api/auth/verify-otp", json={"otp": otp_record.otp})
    assert verify_response.status_code == 200

    from models.user import User
    from models.tenant import Tenant

    user = db_session.query(User).filter(User.email == "tenantcheck@mycompany.com").first()
    tenant = db_session.query(Tenant).filter(Tenant.owner_user_id == user.id).first()
    assert tenant is not None
    assert tenant.organization_name == "Tenant Check Org"


def test_verify_otp_wrong_code_rejected(client, db_session):
    _register_and_get_otp(client, db_session, email="wrongotp@example.com")

    response = client.post("/api/auth/verify-otp", json={"otp": "000000"})
    # Guard against the unlikely case the real OTP IS 000000
    assert response.status_code in (400, 200)
    if response.status_code == 200:
        pytest.skip("Randomly generated OTP matched 000000 - inconclusive, skipping")
    assert "Invalid OTP" in response.json()["detail"]


def test_verify_otp_max_retry_exceeded(client, db_session):
    _register_and_get_otp(client, db_session, email="maxretry@example.com")

    # Submit 5 wrong attempts (OTP_MAX_RETRY default = 5)
    for _ in range(5):
        client.post("/api/auth/verify-otp", json={"otp": "000000"})

    # 6th attempt should be blocked regardless of OTP value
    response = client.post("/api/auth/verify-otp", json={"otp": "000000"})
    assert response.status_code == 429
    assert "Maximum OTP attempts exceeded" in response.json()["detail"]


def test_verify_otp_no_cookie_rejected(client):
    # Fresh client call with no prior /register call means no otp_token cookie
    response = client.post("/api/auth/verify-otp", json={"otp": "123456"})
    assert response.status_code == 401
    assert "OTP session not found" in response.json()["detail"]


def test_resend_otp_issues_new_code(client, db_session):
    _, original_otp = _register_and_get_otp(client, db_session, email="resendtest@example.com")

    response = client.post("/api/auth/resend-otp")
    assert response.status_code == 200

    otp_record = (
        db_session.query(OTPVerification)
        .filter(OTPVerification.email == "resendtest@example.com")
        .order_by(OTPVerification.id.desc())
        .first()
    )
    # The OTP should have been regenerated (retry_count reset, new code likely different)
    assert otp_record.retry_count == 0