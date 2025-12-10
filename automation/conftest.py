# conftest.py

import pytest
import requests
import json
from config import BASE_URL
import uuid


@pytest.fixture(scope="session")
def api_client():
    """Fixture to provide a reusable requests session."""
    session = requests.Session()
    session.base_url = BASE_URL
    return session


@pytest.fixture(scope="function")
def register_test_user(api_client):
    """Fixture to register and return a user's details for testing."""

    # Generate unique test user data
    # 1. Use a short, unique identifier (first 8 chars of a UUID)
    unique_id = uuid.uuid4().hex[:8]
    # 2. Construct the email, ensuring the total length is manageable.
    # Total Length: 8 (id) + 1 (@) + 7 (test.com) = 16 characters. This is safe (max 25).
    email = f"u_{unique_id}@test.com"
    password = "pYtEsT"  # 6 chars

    # 1. Registration (Pre-confirmation)
    response = api_client.post(f"{BASE_URL}/register", json={"email": email, "password": password})
    assert response.status_code == 201, f"Registration failed during setup: Expected 201. Response: {json.loads(response.text)}"

    confirmation_link = json.loads(response.text)['confirmation_link']
    assert confirmation_link, "Confirmation link missing from registration response."

    user_data = {
        "email": email,
        "password": password,
        "confirmation_link": confirmation_link
    }

    yield user_data

    # --- Teardown (Cleanup logic would go here if we were not using SQLite in-memory/Docker volume)
    # For a simple file-based SQLite, manual teardown is impractical in the app layer
    # The Docker volume should be cleared between full runs, or a separate cleanup API would be needed.