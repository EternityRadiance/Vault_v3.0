from __future__ import annotations
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app.auth.router import router as auth_router
from app.config import settings
from app.graphql.schema import graphql_app

from app.oauth.discovery import router as discovery_router
from app.oauth.jwks import router as jwks_router
from app.oauth.router import router as oauth_router
from app.web.router import router as web_router

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
)

class NoCacheMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        if request.url.path.startswith(("/admin", "/account")):
            response.headers["Cache-Control"] = "no-store"
        return response

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    session_cookie=settings.session_cookie_name,
    max_age=settings.session_ttl_min * 60,
    https_only=settings.session_cookie_secure,               
    same_site="lax",
)

app.add_middleware(NoCacheMiddleware)

app.include_router(auth_router)
app.include_router(jwks_router)
app.include_router(discovery_router)
app.include_router(oauth_router)
app.include_router(web_router)

@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "app": settings.app_name}

app.mount("/graphql", graphql_app)
app.mount("/web/static", StaticFiles(directory="app/web/static"), name="web_static")