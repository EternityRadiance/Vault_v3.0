from __future__ import annotations
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.audit_event import AuditEvent
from app.models.oauth_client import OAuthClient


class TestRefreshRotation:
    def test_refresh_rotation_and_reuse(
        self,
        client: TestClient,
        oauth_client: OAuthClient,
        regular_user,
        db_session: Session,
    ):
        resp = client.post(
            "/oauth/token",
            data={
                "grant_type": "password",
                "client_id": oauth_client.client_id,
                "username": regular_user.email,
                "password": "Very strong user password",
                "scope": "openid email",
            },
        )
        assert resp.status_code == 200, f"password grant failed: {resp.text}"

        rt1 = resp.json()["refresh_token"]

        resp = client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": oauth_client.client_id,
                "refresh_token": rt1,
            },
        )
        assert resp.status_code == 200
        rt2 = resp.json()["refresh_token"]
        assert rt2 != rt1

        resp = client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": oauth_client.client_id,
                "refresh_token": rt1,
            },
        )
        assert resp.status_code == 400

        resp = client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": oauth_client.client_id,
                "refresh_token": rt2,
            },
        )
        assert resp.status_code == 400

        events = (
            db_session.query(AuditEvent)
            .filter_by(event_type="token.reuse_detected")
            .all()
        )
        assert len(events) >= 1