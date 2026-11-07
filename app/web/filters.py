from __future__ import annotations
from datetime import datetime, timezone

def datetime_format(value: datetime | None) -> str:
    if value is None:
        return "-"

    months = [
        "января", "февраля", "марта", "апреля", "мая", "июня",
        "июля", "августа", "сентября", "октября", "ноября", "декабря",
    ]
    return f"{value.day} {months[value.month - 1]} {value.year}, {value:%H:%M}"

def humanize(value: datetime | None) -> str:
    if value is None:
        return "-"

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    delta = now - value
    seconds = int(delta.total_seconds())

    if seconds < 0:
        return "только что"
    if seconds < 60: 
        return "только что"
    if seconds < 3600:
        return f"{seconds // 60} мин назад"
    if seconds < 86400:
        return f"{seconds // 3600} ч назад"
    if seconds < 86400 * 2:
        return "вчера"
    if seconds < 86400 * 7:
        return f"{seconds // 86400} дн назад"

    return datetime_format(value)

def mask_secret(value: str | None) -> str:
    if not value:
        return "-"
    if len(value) <= 10:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"

def short_id(value: str | None) -> str:
    if not value:
        return "-"
    if len(value) <= 12:
        return value
    return f"{value[:6]}...{value[-4:]}"

def register_filters(templates) -> None:
    templates.env.filters["datetime_format"] = datetime_format
    templates.env.filters["humanize"] = humanize
    templates.env.filters["mask_secret"] = mask_secret
    templates.env.filters["short_id"] = short_id