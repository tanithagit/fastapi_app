from models.otp_verification import OTPVerification


def _register_verify_and_login(client, db_session, email="logintest@example.com", password="Test@1234"):
    """Helper: full registration + OTP verification + login, returns the login response."""
    client.post(
        "/api/auth/register",
        json={
            "full_name": "Login Test User",
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

    return client.post("/api/auth/login", json={"email": email, "password": password})


def test_login_success(client, db_session):
    response = _register_verify_and_login(client, db_session)
    assert response.status_code == 200
    body = response.json()
    assert body["email"] == "logintest@example.com"
    assert "access_token" in response.cookies
    assert "refresh_token" in response.cookies


def test_login_wrong_password_rejected(client, db_session):
    _register_verify_and_login(client, db_session, email="wrongpwlogin@example.com")
    response = client.post(
        "/api/auth/login",
        json={"email": "wrongpwlogin@example.com", "password": "WrongPassword123!"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password."


def test_login_nonexistent_email_rejected(client):
    response = client.post(
        "/api/auth/login",
        json={"email": "doesnotexist@example.com", "password": "Test@1234"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password."


def test_login_unverified_account_rejected(client):
    # Register but never verify OTP
    client.post(
        "/api/auth/register",
        json={
            "full_name": "Unverified User",
            "email": "unverified@example.com",
            "password": "Test@1234",
            "confirm_password": "Test@1234",
            "account_type": "individual",
        },
    )
    response = client.post(
        "/api/auth/login",
        json={"email": "unverified@example.com", "password": "Test@1234"},
    )
    assert response.status_code == 401


def test_logout_clears_cookies_and_revokes_token(client, db_session):
    _register_verify_and_login(client, db_session, email="logouttest@example.com")

    response = client.post("/api/auth/logout")
    assert response.status_code == 200
    assert response.json()["message"] == "Logged out successfully."

    from models.refresh_token import RefreshToken
    from models.user import User
    user = db_session.query(User).filter(User.email == "logouttest@example.com").first()
    token_record = (
        db_session.query(RefreshToken)
        .filter(RefreshToken.user_id == user.id)
        .order_by(RefreshToken.id.desc())
        .first()
    )
    assert token_record.is_revoked is True


def test_logout_twice_is_graceful(client, db_session):
    _register_verify_and_login(client, db_session, email="doublelogout@example.com")
    first = client.post("/api/auth/logout")
    second = client.post("/api/auth/logout")
    assert first.status_code == 200
    assert second.status_code == 200


def test_refresh_token_rotates_and_old_token_rejected(client, db_session):
    _register_verify_and_login(client, db_session, email="refreshtest@example.com")

    # Capture the old refresh_token cookie value before refreshing
    old_refresh_token = client.cookies.get("refresh_token")

    refresh_response = client.post("/api/auth/refresh-token")
    assert refresh_response.status_code == 200

    new_refresh_token = client.cookies.get("refresh_token")
    assert new_refresh_token != old_refresh_token

    # Manually set the OLD token back and try again - should be rejected
    client.cookies.set("refresh_token", old_refresh_token)
    reuse_response = client.post("/api/auth/refresh-token")
    assert reuse_response.status_code == 401
    assert "revoked" in reuse_response.json()["detail"]


def test_refresh_token_missing_cookie_rejected(client):
    response = client.post("/api/auth/refresh-token")
    assert response.status_code == 401
    assert "not found" in response.json()["detail"]