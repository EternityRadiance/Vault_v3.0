from __future__ import annotations
import re
from fastapi.testclient import TestClient

from app.models.user import User

def _extract_csrf(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, "csrf_token not found in HTML"
    return m.group(1)

class TestWebLoginFlow:
    def test_get_login_renders_form(self, client: TestClient):
        resp = client.get("/web/login")
        assert resp.status_code == 200
        assert "<h1>Вход</h1>" in resp.text
        assert 'name="email"' in resp.text
        assert 'name="password"' in resp.text
        assert 'name="csrf_token"' in resp.text

    def test_login_wrong_password_renders_error_no_session(
            self, client: TestClient, regular_user: User,
    ):
        page = client.get("/web/login")
        csrf = _extract_csrf(page.text)

        resp = client.post(
            "/web/login",
            data = {
                "csrf_token": csrf,
                "email": regular_user.email,
                "password": "wrong password",
                "next": "",
            },
        )
        assert resp.status_code == 200
        assert "Неверный email или пароль" in resp.text

        acc = client.get("/web/account", follow_redirects=False)
        assert acc.status_code == 303
        assert "/web/login" in acc.headers["location"]

    def test_login_correct_redirects_and_sets_session(
            self, client: TestClient, regular_user: User,
    ):
        page = client.get("/web/login")
        csrf = _extract_csrf(page.text)

        resp = client.post(
            "/web/login",
            data = {
                "csrf_token": csrf,
                "email": regular_user.email,
                "password": "Very strong user password",
                "next": "",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/web/account"

        acc = client.get("/web/account")
        assert acc.status_code == 200
        assert regular_user.email in acc.text

    def test_logout_clears_session(
            self, client: TestClient, regular_user: User,
    ):
        page = client.get("/web/login")
        csrf = _extract_csrf(page.text)
        client.post(
            "/web/login",
            data = {
                "csrf_token": csrf,
                "email": regular_user.email,
                "password": "Very strong user password",
                "next": "",
            },
            follow_redirects=False,
        )

        acc = client.get("/web/account")
        assert acc.status_code == 200

        csrf2 = _extract_csrf(acc.text)
        resp = client.post(
            "/web/logout",
            data={"csrf_token": csrf2},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/web/login"

        acc2 = client.get("/web/account", follow_redirects=False)
        assert acc2.status_code == 303
        assert "/web/login" in acc2.headers["location"]

    def test_account_requires_login(self, client: TestClient):
        resp = client.get("/web/account", follow_redirects=False)
        assert "/web/login" in resp.headers["location"]
        assert "next=" in resp.headers["location"]