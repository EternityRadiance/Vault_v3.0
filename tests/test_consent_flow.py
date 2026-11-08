from __future__ import annotations
import re
from urllib.parse import parse_qs, urlparse
from fastapi.testclient import TestClient

from app.models.oauth_client import OAuthClient

VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def _extract_csrf(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m
    return m.group(1)


def _login(client: TestClient, email: str, password: str) -> None:
    page = client.get("/web/login")
    csrf = _extract_csrf(page.text)
    client.post(
        "/web/login",
        data={"csrf_token": csrf, "email": email, "password": password, "next": ""},
        follow_redirects=False,
    )


def _authorize_params(client_id: str, redirect_uri: str, state="xyz") -> dict:
    return {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid email",
        "state": state,
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
    }


class TestConsentFlow:
    def test_authorize_redirects_to_login_when_anonymous(
        self, client: TestClient, oauth_client: OAuthClient,
    ):
        resp = client.get(
            "/oauth/authorize",
            params=_authorize_params(
                oauth_client.client_id, oauth_client.redirect_uris[0]
            ),
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"].startswith("/web/login?next=")

    def test_authorize_redirects_to_consent_when_logged_in(
        self, client: TestClient, oauth_client: OAuthClient, regular_user,
    ):
        _login(client, regular_user.email, "Very strong user password")
        resp = client.get(
            "/oauth/authorize",
            params=_authorize_params(
                oauth_client.client_id, oauth_client.redirect_uris[0]
            ),
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"].startswith("/web/consent?request_id=")

    def test_consent_allow_issues_code(
        self, client: TestClient, oauth_client: OAuthClient, regular_user,
    ):
        _login(client, regular_user.email, "Very strong user password")
        resp = client.get(
            "/oauth/authorize",
            params=_authorize_params(
                oauth_client.client_id, oauth_client.redirect_uris[0], state="my-state"
            ),
            follow_redirects=False,
        )
        request_id = parse_qs(urlparse(resp.headers["location"]).query)["request_id"][0]

        page = client.get(f"/web/consent?request_id={request_id}")
        assert page.status_code == 200
        assert oauth_client.name in page.text
        assert "Вход через Vault" in page.text
        assert "Просмотр email" in page.text
        csrf = _extract_csrf(page.text)

        resp = client.post(
            "/web/consent",
            data={"csrf_token": csrf, "request_id": request_id, "decision": "allow"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        loc = resp.headers["location"]
        assert loc.startswith(oauth_client.redirect_uris[0] + "?")
        params = parse_qs(urlparse(loc).query)
        assert "code" in params
        assert params.get("state") == ["my-state"]

    def test_consent_deny_returns_access_denied(
        self, client: TestClient, oauth_client: OAuthClient, regular_user,
    ):
        _login(client, regular_user.email, "Very strong user password")
        resp = client.get(
            "/oauth/authorize",
            params=_authorize_params(
                oauth_client.client_id, oauth_client.redirect_uris[0], state="deny-state"
            ),
            follow_redirects=False,
        )
        request_id = parse_qs(urlparse(resp.headers["location"]).query)["request_id"][0]

        page = client.get(f"/web/consent?request_id={request_id}")
        csrf = _extract_csrf(page.text)

        resp = client.post(
            "/web/consent",
            data={"csrf_token": csrf, "request_id": request_id, "decision": "deny"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        loc = resp.headers["location"]
        params = parse_qs(urlparse(loc).query)
        assert params.get("error") == ["access_denied"]
        assert params.get("state") == ["deny-state"]
        assert "code" not in params

    def test_consent_request_id_is_single_use(
        self, client: TestClient, oauth_client: OAuthClient, regular_user,
    ):
        _login(client, regular_user.email, "Very strong user password")
        resp = client.get(
            "/oauth/authorize",
            params=_authorize_params(
                oauth_client.client_id, oauth_client.redirect_uris[0]
            ),
            follow_redirects=False,
        )
        request_id = parse_qs(urlparse(resp.headers["location"]).query)["request_id"][0]

        page = client.get(f"/web/consent?request_id={request_id}")
        csrf = _extract_csrf(page.text)

        resp = client.post(
            "/web/consent",
            data={"csrf_token": csrf, "request_id": request_id, "decision": "allow"},
            follow_redirects=False,
        )
        assert resp.status_code == 302

        resp = client.post(
            "/web/consent",
            data={"csrf_token": csrf, "request_id": request_id, "decision": "allow"},
            follow_redirects=False,
        )
        assert resp.status_code == 400