from __future__ import annotations
from datetime import datetime, timezone
from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.events import OAuthEvents
from app.audit.service import get_client_info, write_event
from app.core.security.pkce import verify_pkce
from app.models.auth_code import AuthCode
from app.models.oauth_client import OAuthClient
from app.models.user import User
from app.models.user_session import UserSession
from app.oauth.errors import (
    INVALID_GRANT,
    INVALID_REQUEST,
    oauth_json_error,
)
from app.oauth.tokens import generate_refresh_token, issue_token_response, sha256_hex

def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

def handle_authorization_code_grant(
        db: Session,
        request: Request,
        *,
        client: OAuthClient,
        code: str | None,
        redirect_uri: str | None,
        code_verifier: str | None,
) -> dict:
    if not code:
        oauth_json_error(INVALID_REQUEST, "code is required")
    if not redirect_uri:
        oauth_json_error(INVALID_REQUEST, "redirect_uri is required")

    code_hash = sha256_hex(code)
    auth_code = db.execute(
        select(AuthCode).where(AuthCode.code_hash == code_hash)
    ).scalar_one_or_none()

    info = get_client_info(request)

    if auth_code is None:
        write_event(
            db,
            OAuthEvents.AUTH_CODE_REUSE_DETECTED,
            actor_id=None,
            client_id=client.client_id,
            ip=info["ip"],
            user_agent=info["user_agent"],
            metadata={"reason": "unknown_code", "grant_type": "authorization_code"},
        )
        oauth_json_error(INVALID_GRANT, "Invalid or unknown code")

    if auth_code.used_at is not None:
        write_event(
            db,
            OAuthEvents.AUTH_CODE_REUSE_DETECTED,
            actor_id=auth_code.user_id,
            client_id=client.client_id,
            ip=info["ip"],
            user_agent=info["user_agent"],
            metadata={"grant_type": "authorization_code", "reason": "code_already_used"},
        )
        oauth_json_error(INVALID_GRANT, "Code has already been used")

    if auth_code.expires_at < _utcnow():
        oauth_json_error(INVALID_GRANT, "Code has expired")

    if auth_code.client_id != client.client_id:
        oauth_json_error(INVALID_GRANT, "client_id mismatch")

    if auth_code.redirect_uri != redirect_uri:
        oauth_json_error(INVALID_GRANT, "redirect_uri mismatch")

    if auth_code.code_challenge:
        if not verify_pkce(
            code_verifier,
            auth_code.code_challenge,
            auth_code.code_challenge_method,
        ):
            write_event(
                db,
                OAuthEvents.AUTHORIZE_FAILURE,
                actor_id=auth_code.user_id,
                client_id=client.client_id,
                ip=info["ip"],
                user_agent=info["user_agent"],
                metadata={"grant_type": "authorization_code", "reason": "pkce_failed"},
            )
            oauth_json_error(INVALID_GRANT, "PKCE verification failed")
    elif client.is_confidential is False:
        oauth_json_error(INVALID_GRANT, "PKCE required for public clients")

    auth_code.used_at = _utcnow()

    user = db.execute(
        select(User).where(User.id == auth_code.user_id)
    ).scalar_one_or_none()

    if user is None or not user.is_active:
        oauth_json_error(INVALID_GRANT, "User not found or inactive")

    scopes = auth_code.scope.split() if auth_code.scope else []

    raw_refresh, refresh_record = generate_refresh_token(
        db,
        user_id=user.id,
        client_id=client.client_id,
        scope=" ".join(scopes),
    )

    session = UserSession(
        user_id=user.id,
        client_id=client.client_id,
        family_id=refresh_record.family_id,
        ip=info["ip"],
        user_agent=info["user_agent"],
    )
    db.add(session)
    db.commit()

    write_event(
        db,
        OAuthEvents.TOKEN_ISSUED,
        actor_id=user.id,
        client_id=client.client_id,
        ip=info["ip"],
        user_agent=info["user_agent"],
        metadata={
            "grant_type": "authorization_code",
            "scope": " ".join(scopes),
            "family_id": refresh_record.family_id,
        },
    )

    return issue_token_response(
        user=user,
        client_id=client.client_id,
        scopes=scopes,
        raw_refresh=raw_refresh,
        include_id_token=True,
        nonce=auth_code.nonce,
    )