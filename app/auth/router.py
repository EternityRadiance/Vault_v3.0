from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.auth.schemas import Credentials, MeResponse, TokenResponse
from app.auth.service import (
    EmailAlreadyExistsError,
    InvalidCredentialsError,
    authenticate_user,
    register_user,
)
from app.core.deps import get_current_user
from app.core.passwords import WeakPasswordError
from app.db.session import get_db
from app.models.user import User

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    body: Credentials,
    request: Request,
    db: Session = Depends(get_db),
):
    try:
        user, token = register_user(
            db,
            email=body.email,
            password=body.password,
            request=request,
        )
    except EmailAlreadyExistsError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )
    except WeakPasswordError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    return TokenResponse(access_token=token)


@router.post("/login", response_model=TokenResponse)
def login(
    body: Credentials,
    request: Request,
    db: Session = Depends(get_db),
):
    try:
        user, token = authenticate_user(
            db,
            email=body.email,
            password=body.password,
            request=request,
        )
    except InvalidCredentialsError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return TokenResponse(access_token=token)


@router.get("/me", response_model=MeResponse)
def me(current_user: User = Depends(get_current_user)):
    return MeResponse(
        id=current_user.id,
        email=current_user.email,
        is_admin=current_user.is_admin,
    )


@router.post("/logout", include_in_schema=False)
def logout():
    return {"status": "ok"}