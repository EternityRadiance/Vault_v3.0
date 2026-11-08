from __future__ import annotations
import re
from urllib.parse import parse_qs, urlparse
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.audit_event import AuditEvent
from app.models.oauth_client import OAuthClient


VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def _extract_csrf(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m
    return m.group(1)


def _web_login(client: TestClient, email: str, password: str) -> None:
    page = client.get("/web/login")
    csrf = _extract_csrf(page.text)
    client.post(
        "/web/login",
        data={"csrf_token": csrf, "email": email, "password": password, "next": ""},
        follow_redirects=False,
    )


def _get_code(client: TestClient, client_id: str, redirect_uri: str) -> str:
    resp = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid email",
            "state": "xyz",
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/web/consent?request_id=")
    request_id = parse_qs(urlparse(resp.headers["location"]).query)["request_id"][0]

    consent_page = client.get(f"/web/consent?request_id={request_id}")
    assert consent_page.status_code == 200
    csrf = _extract_csrf(consent_page.text)

    resp = client.post(
        "/web/consent",
        data={"csrf_token": csrf, "request_id": request_id, "decision": "allow"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    loc = resp.headers["location"]
    assert loc.startswith(redirect_uri + "?")
    code = parse_qs(urlparse(loc).query)["code"][0]
    return code


class TestAuthCodeSingleUse:
    def test_code_cannot_be_used_twice(
        self,
        client: TestClient,
        oauth_client: OAuthClient,
        regular_user,
        db_session: Session,
    ):
        _web_login(client, regular_user.email, "Very strong user password")
        code = _get_code(client, oauth_client.client_id, oauth_client.redirect_uris[0])

        # Обмен code → токены
        resp = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": oauth_client.client_id,
                "code": code,
                "redirect_uri": oauth_client.redirect_uris[0],
                "code_verifier": VERIFIER,
            },
        )
        assert resp.status_code == 200
        assert "access_token" in resp.json()

        resp = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": oauth_client.client_id,
                "code": code,
                "redirect_uri": oauth_client.redirect_uris[0],
                "code_verifier": VERIFIER,
            },
        )
        assert resp.status_code == 400
        assert "already been used" in resp.json()["detail"]["error_description"].lower()

        events = (
            db_session.query(AuditEvent)
            .filter_by(event_type="auth_code.reuse_detected")
            .all()
        )
        assert len(events) >= 1