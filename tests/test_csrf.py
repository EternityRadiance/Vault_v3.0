from __future__ import annotations
import re
from fastapi.testclient import TestClient

from app.models.user import User


def _extract_csrf(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, "csrf_token not found in HTML"
    return m.group(1)


class TestCSRF:
    def test_login_without_csrf_returns_403(
        self, client: TestClient, regular_user: User,
    ):
        client.get("/web/login")

        resp = client.post(
            "/web/login",
            data={
                "email": regular_user.email,
                "password": "Very strong user password",
            },
        )
        assert resp.status_code == 403

    def test_login_with_wrong_csrf_returns_403(
        self, client: TestClient, regular_user: User,
    ):
        client.get("/web/login")
        resp = client.post(
            "/web/login",
            data={
                "csrf_token": "definitely-wrong-token",
                "email": regular_user.email,
                "password": "Very strong user password",
            },
        )
        assert resp.status_code == 403

    def test_admin_disable_without_csrf_returns_403(
        self, client: TestClient, admin_user: User, regular_user: User,
    ):
        page = client.get("/web/login")
        csrf = _extract_csrf(page.text)
        client.post(
            "/web/login",
            data={
                "csrf_token": csrf,
                "email": admin_user.email,
                "password": "Very strong admin password",
                "next": "",
            },
            follow_redirects=False,
        )

        resp = client.post(f"/web/admin/users/{regular_user.id}/disable")
        assert resp.status_code == 403