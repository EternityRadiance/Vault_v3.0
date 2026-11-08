from __future__ import annotations
import re
from fastapi.testclient import TestClient

from app.models.oauth_client import OAuthClient
from app.models.user import User


def _extract_csrf(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, "csrf_token not found in HTML"
    return m.group(1)


def _login(client: TestClient, email: str, password: str) -> None:
    page = client.get("/web/login")
    csrf = _extract_csrf(page.text)
    client.post(
        "/web/login",
        data={
            "csrf_token": csrf,
            "email": email,
            "password": password,
            "next": "",
        },
        follow_redirects=False,
    )


class TestAdminAccess:
    def test_admin_redirects_anonymous_to_login(self, client: TestClient):
        resp = client.get("/web/admin", follow_redirects=False)
        assert resp.status_code == 303
        assert "/web/login" in resp.headers["location"]

    def test_admin_forbids_regular_user(
        self, client: TestClient, regular_user: User,
    ):
        _login(client, regular_user.email, "Very strong user password")
        resp = client.get("/web/admin", follow_redirects=False)
        assert resp.status_code == 403

    def test_admin_allows_admin(
        self, client: TestClient, admin_user: User,
    ):
        _login(client, admin_user.email, "Very strong admin password")
        resp = client.get("/web/admin")
        assert resp.status_code == 200
        assert "<h1>Админ-консоль</h1>" in resp.text

    def test_admin_users_list(
        self, client: TestClient, admin_user: User, regular_user: User,
    ):
        _login(client, admin_user.email, "Very strong admin password")
        resp = client.get("/web/admin/users")
        assert resp.status_code == 200
        assert regular_user.email in resp.text
        assert admin_user.email in resp.text

    def test_admin_clients_list(
        self, client: TestClient, admin_user: User, oauth_client: OAuthClient,
    ):
        _login(client, admin_user.email, "Very strong admin password")
        resp = client.get("/web/admin/clients")
        assert resp.status_code == 200
        assert oauth_client.name in resp.text

    def test_admin_audit_list(self, client: TestClient, admin_user: User):
        _login(client, admin_user.email, "Very strong admin password")
        resp = client.get("/web/admin/audit")
        assert resp.status_code == 200
        assert "Аудит</h1>" in resp.text
        assert 'name="event_type"' in resp.text

    def test_admin_audit_csv(self, client: TestClient, admin_user: User):
        _login(client, admin_user.email, "Very strong admin password")
        resp = client.get("/web/admin/audit/export.csv")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")
        assert "attachment" in resp.headers["content-disposition"]
        first_line = resp.text.splitlines()[0]
        assert first_line.startswith("id,created_at,event_type")

    def test_admin_dashboard_stats_json(
        self, client: TestClient, admin_user: User,
    ):
        _login(client, admin_user.email, "Very strong admin password")
        resp = client.get("/web/admin/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert set(data.keys()) == {
            "users", "clients", "active_sessions", "events_24h",
        }
        for v in data.values():
            assert isinstance(v, int)