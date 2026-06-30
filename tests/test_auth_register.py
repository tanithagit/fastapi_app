def test_register_individual_success(client):
    response = client.post(
        "/api/auth/register",
        json={
            "full_name": "John Doe",
            "email": "john@example.com",
            "password": "Test@1234",
            "confirm_password": "Test@1234",
            "account_type": "individual",
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "john@example.com"
    assert "OTP sent" in body["message"]
    # Confirm the otp_token cookie was set
    assert "otp_token" in response.cookies


def test_register_organization_success(client):
    response = client.post(
        "/api/auth/register",
        json={
            "full_name": "Org Owner",
            "email": "owner@mycompany.com",
            "password": "Test@1234",
            "confirm_password": "Test@1234",
            "account_type": "organization",
            "organization_name": "My Company Pvt Ltd",
        },
    )
    assert response.status_code == 201
    assert response.json()["email"] == "owner@mycompany.com"


def test_register_duplicate_email_rejected(client, db_session):
    # First, create and verify a real user directly in the DB
    from core.security import hash_password
    from models.user import User, AccountType

    existing_user = User(
        full_name="Existing User",
        email="duplicate@example.com",
        password_hash=hash_password("Test@1234"),
        account_type=AccountType.INDIVIDUAL,
        is_active=True,
    )
    db_session.add(existing_user)
    db_session.commit()

    # Now try to register again with the same email
    response = client.post(
        "/api/auth/register",
        json={
            "full_name": "Someone Else",
            "email": "duplicate@example.com",
            "password": "Test@1234",
            "confirm_password": "Test@1234",
            "account_type": "individual",
        },
    )
    assert response.status_code == 409
    assert "already exists" in response.json()["detail"]


def test_register_password_mismatch_rejected(client):
    response = client.post(
        "/api/auth/register",
        json={
            "full_name": "Test User",
            "email": "mismatch@example.com",
            "password": "Test@1234",
            "confirm_password": "Different@123",
            "account_type": "individual",
        },
    )
    assert response.status_code == 422


def test_register_weak_password_rejected(client):
    response = client.post(
        "/api/auth/register",
        json={
            "full_name": "Test User",
            "email": "weakpw@example.com",
            "password": "abc123",
            "confirm_password": "abc123",
            "account_type": "individual",
        },
    )
    assert response.status_code == 422


def test_register_organization_missing_name_rejected(client):
    response = client.post(
        "/api/auth/register",
        json={
            "full_name": "Test User",
            "email": "noname@mycompany.com",
            "password": "Test@1234",
            "confirm_password": "Test@1234",
            "account_type": "organization",
        },
    )
    assert response.status_code == 422


def test_register_organization_free_email_rejected(client):
    response = client.post(
        "/api/auth/register",
        json={
            "full_name": "Test User",
            "email": "test@gmail.com",
            "password": "Test@1234",
            "confirm_password": "Test@1234",
            "account_type": "organization",
            "organization_name": "Some Org",
        },
    )
    assert response.status_code == 422