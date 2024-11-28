import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import os

from app.main import app
from app.database import Base, get_db
from app.totp import TOTP

# Create in-memory SQLite database for testing
# Set test environment variables
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["ENCRYPTION_KEY"] = "test_key"

engine = create_engine(
    os.environ["DATABASE_URL"],
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture
def client():
    Base.metadata.create_all(bind=engine)
    yield TestClient(app)
    Base.metadata.drop_all(bind=engine)


def test_valid_totp_flow(client):
    # Create a user
    user_data = {"email": "test@example.com", "name": "Test User"}
    response = client.post("/users/", json=user_data)
    assert response.status_code == 200
    user_id = response.json()["id"]

    # Generate secret for user
    response = client.post(f"/users/{user_id}/generate-secret")
    assert response.status_code == 200
    secret = response.json()["secret"]

    # Generate valid TOTP code
    totp_generator = TOTP()
    valid_code = totp_generator.generate_totp(secret)

    # Validate TOTP
    validation_data = {"user_id": user_id, "totp_code": valid_code}
    response = client.post("/validate-totp", json=validation_data)
    assert response.status_code == 200
    assert response.json()["valid"] is True


def test_invalid_totp_flow(client):
    # Create a user
    user_data = {"email": "test2@example.com", "name": "Test User 2"}
    response = client.post("/users/", json=user_data)
    assert response.status_code == 200
    user_id = response.json()["id"]

    # Generate secret for user
    response = client.post(f"/users/{user_id}/generate-secret")
    assert response.status_code == 200
    secret = response.json()["secret"]

    # Use invalid TOTP code
    invalid_code = "000000"  # Using a fixed invalid code

    # Validate TOTP
    validation_data = {"user_id": user_id, "totp_code": invalid_code}
    response = client.post("/validate-totp", json=validation_data)
    assert response.status_code == 200
    assert response.json()["valid"] is False
