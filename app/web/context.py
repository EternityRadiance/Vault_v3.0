from __future__ import annotations
from pathlib import Path
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse

from app.config import settings
from app.web.filters import register_filters

WEB_DIR = Path(__file__).resolve().parent

templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))

register_filters(templates)

def render(request, template_name: str, **kwargs) -> "HTMLResponse":

    from app.web.csrf import get_csrf_token
    from app.web.flash import pop_flashed_messages

    context = {
        "app_name": settings.app_name,
        "version": "0.4.0",
        "current_user": kwargs.pop("current_user", None),
        "csrf_token": get_csrf_token(request),
        "theme": request.cookies.get("theme", "light"),
        "flash_messages": pop_flashed_messages(request),
        **kwargs,
    }
    
    return templates.TemplateResponse(template_name, {"request": request, **context})