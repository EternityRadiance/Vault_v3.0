from __future__ import annotations
from fastapi import Request

def flash(request: Request, message: str, category: str = "info") -> None:
    messages = request.session.get("flash", [])
    messages.append({"category": category, "message": message})
    request.session["flash"] = messages

def pop_flashed_messages(request: Request) -> list[dict]:
    messages = request.session.get("flash", [])
    request.session["flash"] = []
    return messages