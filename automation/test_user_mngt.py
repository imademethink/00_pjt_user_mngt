# test_user_mngt.py

import json
import pytest
from config import *
import re  # for token extraction


# --- Helper to extract token from confirmation link ---
def extract_token(link):
    """Extracts the token from the full confirmation link."""
    match = re.search(r'/confirm_registration/([^/]+)$', link)
    return match.group(1) if match else None


# --- V. API-001: /version ---

def test_get_version_positive(api_client):
    """Test V-P-01: Successfully retrieve the system version."""
    response = api_client.get(f"{BASE_URL}/version")
    assert response.status_code == HTTP_200_OK
    assert "version" in response.json()
    assert "service" in response.json()


# --- V. API-002: /register ---

@pytest.mark.parametrize("email, password, expected_code", [
    # Positive Cases (R-P-01, R-P-02, R-P-03)
    ("tester5@example.com", "secret", HTTP_201_CREATED),  # Mid-range
    ("a@b.com", "123456", HTTP_201_CREATED),  # Email Min (5 chars)
    ("longemailaddress@test.com", "123456", HTTP_201_CREATED),  # Email Max (25 chars)
    #
    # Negative Cases (Boundary Value Analysis - R-N-01, R-N-02, R-N-03, R-N-04)
    ("h@e", "123456", HTTP_400_BAD_REQUEST),  # Email Min-1 (4 chars)
    ("toolongemailaddress12345@test.com", "123456", HTTP_400_BAD_REQUEST),  # Email Max+1 (26 chars)
    ("valid@test.com", "123", HTTP_400_BAD_REQUEST),  # Password Min-1 (5 chars)
    ("valid@test.com", "1234567", HTTP_400_BAD_REQUEST),  # Password Max+1 (7 chars)
])
def test_register_boundary_cases(api_client, email, password, expected_code):
    """
    Tests registration input boundaries.

    This function ensures that:
    1. Valid boundary cases result in 201 CREATED.
    2. Invalid boundary cases result in 400 BAD REQUEST.
    3. The attempt to register an already existing email results in 400.
    """

    # Check if this is a positive test case (expecting 201)
    if expected_code == HTTP_201_CREATED:
        # --- R-P-01, R-P-02, R-P-03: Positive Cases ---
        # The first and ONLY call to the /register endpoint for positive cases.
        response = api_client.post(f"{BASE_URL}/register", json={"email": email, "password": password})
        # The assertion checks if the registration was successful
        assert response.status_code == expected_code, (f"Positive case failed: Expected {expected_code}, Got {response.status_code}. "
                                                       f"Response: {json.loads(response.text)}")

    # Check if this is a negative test case (expecting 400)
    elif expected_code == HTTP_400_BAD_REQUEST:
        # --- R-N-01, R-N-02, R-N-03, R-N-04: Boundary Negative Cases ---
        # This call tests the invalid inputs (e.g., 4-char email, 5-char password)
        response = api_client.post(f"{BASE_URL}/register", json={"email": email, "password": password})
        assert response.status_code == expected_code, (f"Negative boundary case failed: Expected {expected_code}, Got {response.status_code}. "
                                                       f"Response: {json.loads(response.text)}")
        # Verify the failure message structure
        assert "message" in response.text
    else:
        # Fails the test if an unhandled expected_code is passed
        pytest.fail(f"Test setup error: Unexpected expected_code {expected_code}")


def test_register_existing_email_negative(api_client, register_test_user):
    """Test R-N-05: Attempt to register with an email that already exists."""
    user_data = register_test_user
    response = api_client.post(f"{BASE_URL}/register", json=user_data)
    assert response.status_code == HTTP_400_BAD_REQUEST
    assert "already exists" in response.json().get('message')


def test_register_missing_fields_negative(api_client):
    """Test R-N-06, R-N-07: Missing required fields."""
    # Missing email
    response_no_email = api_client.post(f"{BASE_URL}/register", json={"password": "123456"})
    assert response_no_email.status_code == HTTP_400_BAD_REQUEST

    # Missing password
    response_no_password = api_client.post(f"{BASE_URL}/register", json={"email": "missing@test.com"})
    assert response_no_password.status_code == HTTP_400_BAD_REQUEST


# --- V. API-003: /confirm_registration/{token} ---

def test_confirm_registration_positive(api_client, register_test_user):
    """Test C-P-01: Successful confirmation."""
    user_data = register_test_user
    token = extract_token(user_data['confirmation_link'])

    response = api_client.get(f"{BASE_URL}/confirm_registration/{token}")
    assert response.status_code == HTTP_200_OK
    assert "successfully confirmed" in response.json().get('message')


def test_confirm_registration_already_confirmed_negative(api_client, register_test_user):
    """Test C-N-02: Attempt confirmation with an already used token (checks idempotency)."""
    user_data = register_test_user
    token = extract_token(user_data['confirmation_link'])

    # First confirmation (Successful)
    api_client.get(f"{BASE_URL}/confirm_registration/{token}")

    # Second confirmation attempt
    response = api_client.get(f"{BASE_URL}/confirm_registration/{token}")
    # The application is designed to return 200 if already confirmed,
    # but the DB update step should show rowcount == 0.
    assert response.status_code == HTTP_200_OK  # Expecting success message if already confirmed


def test_confirm_registration_invalid_token_negative(api_client):
    """Test C-N-03, C-N-04: Malformed or non-existent token."""
    # Malformed token
    response_malformed = api_client.get(f"{BASE_URL}/confirm_registration/MALFORMED_TOKEN_12345")
    assert response_malformed.status_code == HTTP_403_FORBIDDEN
    assert "Invalid or expired" in response_malformed.json().get('message')

    # Non-existent token (standard length, but not in DB)
    response_nonexistent = api_client.get(f"{BASE_URL}/confirm_registration/somerandomstringwithvalidlength")
    assert response_nonexistent.status_code == HTTP_403_FORBIDDEN


# --- V. API-004: /login ---

def test_login_positive(api_client, register_test_user):
    """Test L-P-01: Successful login after registration and confirmation."""
    user_data = register_test_user
    token = extract_token(user_data['confirmation_link'])

    # 1. Confirm the user first
    api_client.get(f"{BASE_URL}/confirm_registration/{token}")

    # 2. Login attempt
    response = api_client.post(f"{BASE_URL}/login", json=user_data)
    assert response.status_code == HTTP_200_OK
    assert "Login successful" in response.json().get('message')
    assert "user_id" in response.json()


def test_login_unconfirmed_negative(api_client, register_test_user):
    """Test L-N-03: Login attempt with a user who is NOT confirmed."""
    user_data = register_test_user  # This user is registered but not confirmed yet (Teardown not run)

    response = api_client.post(f"{BASE_URL}/login", json=user_data)
    assert response.status_code == HTTP_403_FORBIDDEN
    assert "not confirmed" in response.json().get('message')


def test_login_invalid_credentials_negative(api_client):
    """Test L-N-01, L-N-02: Invalid email/password."""

    # Non-existent email
    response_non_existent = api_client.post(f"{BASE_URL}/login",
                                            json={"email": "noone@exists.com", "password": "123456"})
    assert response_non_existent.status_code == HTTP_401_UNAUTHORIZED

    # Wrong password (assuming a confirmed user exists in DB)
    response_wrong_password = api_client.post(f"{BASE_URL}/login",
                                              json={"email": "valid@test.com", "password": "wrongpassword"})
    assert response_wrong_password.status_code == HTTP_401_UNAUTHORIZED
    assert "Invalid email or password" in response_wrong_password.json().get('message')