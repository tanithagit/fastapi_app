from models.otp_verification import OTPVerification, OTPPurpose


def _register_and_verify(client, db_session, email="forgotpw@example.com", password="Test@1234"):
    """Helper: full registration + OTP verification, returns nothing (user now exists)."""
    client.post(
        "/api/auth/register",
        json={
            "full_name": "Forgot PW User",
            "email": email,
            "password": password,
            "confirm_password": password,
            "account_type": "individual",
        },
    )
    otp_record = (
        db_session.query(OTPVerification)
        .filter(OTPVerification.email == email)
        .order_by(OTPVerification.id.desc())
        .first()
    )
    client.post("/api/auth/verify-otp", json={"otp": otp_record.otp})


def test_forgot_password_existing_email_returns_generic_message(client, db_session):
    _register_and_verify(client, db_session)
    response = client.post("/api/auth/forgot-password", json={"email": "forgotpw@example.com"})
    assert response.status_code == 200
    assert "otp_token" in response.cookies


def test_forgot_password_nonexistent_email_returns_same_generic_message(client):
    # Should NOT reveal whether the email exists - same message either way
    response = client.post("/api/auth/forgot-password", json={"email": "doesnotexist@example.com"})
    assert response.status_code == 200
    assert "If an account exists" in response.json()["message"]


def test_full_forgot_password_flow_changes_password(client, db_session):
    email = "fullflow@example.com"
    old_password = "Test@1234"
    new_password = "NewSecure@123"

    _register_and_verify(client, db_session, email=email, password=old_password)

    # Step 1: forgot-password
    client.post("/api/auth/forgot-password", json={"email": email})
    otp_record = (
        db_session.query(OTPVerification)
        .filter(OTPVerification.email == email, OTPVerification.purpose == OTPPurpose.PASSWORD_RESET)
        .order_by(OTPVerification.id.desc())
        .first()
    )

    # Step 2: verify-forgot-otp
    verify_response = client.post("/api/auth/verify-forgot-otp", json={"otp": otp_record.otp})
    assert verify_response.status_code == 200

    # Step 3: reset-password
    reset_response = client.post(
        "/api/auth/reset-password",
        json={"new_password": new_password, "confirm_new_password": new_password},
    )
    assert reset_response.status_code == 200

    # Step 4: old password should no longer work
    old_login = client.post("/api/auth/login", json={"email": email, "password": old_password})
    assert old_login.status_code == 401

    # Step 5: new password should work
    new_login = client.post("/api/auth/login", json={"email": email, "password": new_password})
    assert new_login.status_code == 200


def test_reset_password_revokes_all_existing_sessions(client, db_session):
    email = "revoketest@example.com"
    old_password = "Test@1234"
    new_password = "NewSecure@123"

    _register_and_verify(client, db_session, email=email, password=old_password)

    # Log in first to create a refresh token
    login_response = client.post("/api/auth/login", json={"email": email, "password": old_password})
    assert login_response.status_code == 200

    from models.refresh_token import RefreshToken
    from models.user import User
    user = db_session.query(User).filter(User.email == email).first()

    # Go through forgot-password flow
    client.post("/api/auth/forgot-password", json={"email": email})
    otp_record = (
        db_session.query(OTPVerification)
        .filter(OTPVerification.email == email, OTPVerification.purpose == OTPPurpose.PASSWORD_RESET)
        .order_by(OTPVerification.id.desc())
        .first()
    )
    client.post("/api/auth/verify-forgot-otp", json={"otp": otp_record.otp})
    client.post(
        "/api/auth/reset-password",
        json={"new_password": new_password, "confirm_new_password": new_password},
    )

    # The refresh token issued at login should now be revoked
    db_session.expire_all()
    tokens = db_session.query(RefreshToken).filter(RefreshToken.user_id == user.id).all()
    assert all(t.is_revoked for t in tokens)


def test_reset_password_without_verified_otp_rejected(client, db_session):
    email = "noverify@example.com"
    _register_and_verify(client, db_session, email=email)

    # Call forgot-password to get a cookie, but skip verify-forgot-otp
    client.post("/api/auth/forgot-password", json={"email": email})

    response = client.post(
        "/api/auth/reset-password",
        json={"new_password": "NewSecure@123", "confirm_new_password": "NewSecure@123"},
    )
    assert response.status_code == 400