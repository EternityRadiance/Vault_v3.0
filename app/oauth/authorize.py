from __future__ import annotations
import json
import secrets
from urllib.parse import quote, urlencode
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.events import OAuthEvents
from app.audit.service import get_client_info, write_event
from app.config import settings
from app.db.session import get_db
from app.models.oauth_client import OAuthClient
from app.oauth.errors import (
    INVALID_REQUEST,
    INVALID_SCOPE,
    UNAUTHORIZED_CLIENT,
    UNSUPPORTED_RESPONSE_TYPE,
    oauth_json_error,
    oauth_redirect_error,
)
from app.redis_client import get_redis
from app.web.session import get_web_user

router = APIRouter(tags=["oauth"])

CONSENT_KEY_PREFIX = "consent:"


@router.get("/oauth/authorize", include_in_schema=False)
def authorize(
    request: Request,
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query(default=""),
    state: str | None = Query(default=None),
    code_challenge: str | None = Query(default=None),
    code_challenge_method: str | None = Query(default=None),
    nonce: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    info = get_client_info(request)

    web_user = get_web_user(db, request)
    if web_user is None:
        original_query = request.url.query
        next_url = "/oauth/authorize"
        if original_query:
            next_url += "?" + original_query
        return RedirectResponse(
            "/web/login?next=" + quote(next_url, safe=""),
            status_code=303,
        )

    client = db.execute(
        select(OAuthClient).where(OAuthClient.client_id == client_id)
    ).scalar_one_or_none()

    if client is None or not client.is_active:
        write_event(
            db,
            OAuthEvents.AUTHORIZE_FAILURE,
            actor_id=web_user.id,
            ip=info["ip"],
            user_agent=info["user_agent"],
            metadata={
                "client_id": client_id,
                "reason": "unknown_or_inactive_client",
            },
        )
        oauth_json_error(INVALID_REQUEST, "Unknown or inactive client")

    if redirect_uri not in (client.redirect_uris or []):
        write_event(
            db,
            OAuthEvents.AUTHORIZE_FAILURE,
            actor_id=web_user.id,
            client_id=client.client_id,
            ip=info["ip"],
            user_agent=info["user_agent"],
            metadata={
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "reason": "invalid_redirect_uri",
            },
        )
        oauth_json_error(INVALID_REQUEST, "Invalid redirect_uri")

    if response_type != "code":
        return oauth_redirect_error(
            redirect_uri, UNSUPPORTED_RESPONSE_TYPE, state,
            f"Only 'code' is supported, got {response_type!r}",
        )

    if not state:
        return oauth_redirect_error(
            redirect_uri, INVALID_REQUEST, None,
            "state is required",
        )

    requested_scopes = scope.split() if scope else []
    allowed_scopes = set(client.scopes or [])
    if not set(requested_scopes).issubset(allowed_scopes):
        return oauth_redirect_error(
            redirect_uri, INVALID_SCOPE, state,
            f"Allowed scopes: {sorted(allowed_scopes)}",
        )

    if "authorization_code" not in (client.grant_types or []):
        write_event(
            db,
            OAuthEvents.AUTHORIZE_FAILURE,
            actor_id=web_user.id,
            client_id=client.client_id,
            ip=info["ip"],
            user_agent=info["user_agent"],
            metadata={
                "client_id": client_id,
                "reason": "grant_not_allowed",
            },
        )
        return oauth_redirect_error(
            redirect_uri, UNAUTHORIZED_CLIENT, state,
            "authorization_code grant not allowed for this client",
        )

    if client.is_confidential is False and settings.pkce_required_for_public:
        if not code_challenge:
            return oauth_redirect_error(
                redirect_uri, INVALID_REQUEST, state,
                "code_challenge is required for public clients",
            )
        if code_challenge_method != "S256":
            return oauth_redirect_error(
                redirect_uri, INVALID_REQUEST, state,
                "code_challenge_method must be S256",
            )

    pending_id = secrets.token_urlsafe(32)
    payload = {
        "client_id": client.client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(requested_scopes),
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "user_id": web_user.id,
    }
    get_redis().setex(
        f"{CONSENT_KEY_PREFIX}{pending_id}",
        settings.consent_ttl_sec,
        json.dumps(payload, ensure_ascii=False),
    )

    write_event(
        db,
        OAuthEvents.AUTHORIZE_SUCCESS,
        actor_id=web_user.id,
        client_id=client.client_id,
        ip=info["ip"],
        user_agent=info["user_agent"],
        metadata={
            "client_id": client.client_id,
            "scope": " ".join(requested_scopes),
            "redirect_uri": redirect_uri,
            "has_pkce": bool(code_challenge),
            "stage": "consent_pending",
        },
    )

    return RedirectResponse(
        f"/web/consent?request_id={pending_id}",
        status_code=303,
    )