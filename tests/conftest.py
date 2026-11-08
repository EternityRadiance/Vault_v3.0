from __future__ import annotations
import os
from collections.abc import Generator
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from uuid import uuid4

from app.core.jwt import create_access_token
from app.core.passwords import hash_password
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.user import User
from app.models.audit_event import AuditEvent
from app.models.oauth_client import OAuthClient

TEST_DB_PATH = "./test_vault.db"
TEST_DB_URL = f"sqlite:///{TEST_DB_PATH}"

@pytest.fixture(scope="session")
def engine():
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)

    eng = create_engine(
        TEST_DB_URL,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)

@pytest.fixture(scope="session")
def TestingSessionLocal(engine):
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)

@pytest.fixture
def db_session(engine, TestingSessionLocal) -> Generator[Session, None, None]:

    session = TestingSessionLocal()

    session.query(AuditEvent).delete()
    session.query(OAuthClient).delete()
    session.query(User).delete()
    session.commit()

    try: 
        yield session
    finally:
        session.close()

@pytest.fixture
def client(engine, TestingSessionLocal) -> Generator[TestClient, None, None]:
    from app.db import session as db_session_module

    original_session_local = db_session_module.SessionLocal
    db_session_module.SessionLocal = TestingSessionLocal

    def override_get_db() -> Generator[Session, None, None]:
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()
    db_session_module.SessionLocal = original_session_local

@pytest.fixture
def admin_user(db_session: Session) -> User:

    user = User(
        email="admin@example.com",
        hashed_password=hash_password("Very strong admin password"),
        is_active=True,
        is_admin=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user

@pytest.fixture
def regular_user(db_session: Session) -> User:
    user = User(
        email="user@example.com",
        hashed_password=hash_password("Very strong user password"),
        is_active=True,
        is_admin=False,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user

@pytest.fixture
def admin_token(admin_user: User) -> str:
    return create_access_token(sub=admin_user.id)

@pytest.fixture
def regular_token(regular_user: User) -> str:
    return create_access_token(sub=regular_user.id)

def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def oauth_client(db_session: Session) -> OAuthClient:
    client = OAuthClient(
        client_id="test-oauth-client-" + uuid4().hex[:8],
        name="Test OAuth Client",
        is_confidential=False,
        hashed_secret=None,
        redirect_uris=["http://localhost:8001/callback"],
        scopes=["openid", "profile", "email"],
        grant_types=["authorization_code", "refresh_token", "password"],
        is_active=True,
    )
    db_session.add(client)
    db_session.commit()
    db_session.refresh(client)
    return client


@pytest.fixture
def oauth_confidential_client(db_session: Session) -> OAuthClient:
    client = OAuthClient(
        client_id="test-conf-client-" + uuid4().hex[:8],
        name="Test Conf Client",
        is_confidential=True,
        hashed_secret=hash_password("test-conf-secret-12345"),
        redirect_uris=[],
        scopes=["openid", "email"],
        grant_types=["client_credentials", "password"],
        is_active=True,
    )
    db_session.add(client)
    db_session.commit()
    db_session.refresh(client)
    return client