def test_register_individual_success(client):
    # Individual with personal email - should succeed
    response = client.post(
        "/api/auth/register",
        json={
            "full_name": "John Doe",
            "email": "john@gmail.com",
            "password": "Test@1234",
            "confirm_password": "Test@1234",
            "account_type": "individual",
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "john@gmail.com"
    assert "OTP sent" in body["message"]
    assert "otp_token" in response.cookies


def test_register_individual_yahoo_email_success(client):
    # Individual with yahoo email - should succeed
    response = client.post(
        "/api/auth/register",
        json={
            "full_name": "Jane Doe",
            "email": "jane@yahoo.com",
            "password": "Test@1234",
            "confirm_password": "Test@1234",
            "account_type": "individual",
        },
    )
    assert response.status_code == 201
    assert response.json()["email"] == "jane@yahoo.com"


def test_register_individual_business_email_rejected(client):
    # Individual with business email - should be rejected
    response = client.post(
        "/api/auth/register",
        json={
            "full_name": "Test User",
            "email": "admin@company.com",
            "password": "Test@1234",
            "confirm_password": "Test@1234",
            "account_type": "individual",
        },
    )
    assert response.status_code == 422
    assert "personal email" in response.json()["detail"][0]["msg"].lower()


def test_register_organization_success(client):
    # Organization with business email - should succeed
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


def test_register_organization_personal_email_rejected(client):
    # Organization with Gmail - should be rejected
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
    assert "business email" in response.json()["detail"][0]["msg"].lower()


def test_register_duplicate_email_rejected(client, db_session):
    from core.security import hash_password
    from models.user import User, AccountType

    existing_user = User(
        full_name="Existing User",
        email="duplicate@gmail.com",
        password_hash=hash_password("Test@1234"),
        account_type=AccountType.INDIVIDUAL,
        is_active=True,
    )
    db_session.add(existing_user)
    db_session.commit()

    response = client.post(
        "/api/auth/register",
        json={
            "full_name": "Someone Else",
            "email": "duplicate@gmail.com",
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
            "email": "mismatch@gmail.com",
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
            "email": "weakpw@gmail.com",
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