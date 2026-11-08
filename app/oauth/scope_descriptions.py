from __future__ import annotations

SCOPE_LABELS: dict[str, tuple[str, str]] = {
    "openid": (
        "Вход через Vault",
        "Приложение сможет аутентифицировать вас через Vault и получить ваш уникальный идентификатор.",
    ),
    "profile": (
        "Просмотр профиля",
        "Имя пользователя и предпочитаемое имя (username).",
    ),
    "email": (
        "Просмотр email",
        "Ваш email-адрес и признак, что он подтверждён.",
    ),
    "offline_access": (
        "Offline-доступ",
        "Приложение сможет действовать от вашего имени, пока вы не отзовёте доступ. "
        "Это даёт доступ даже когда вы не в браузере (через refresh-токен).",
    ),
}

def describe_scope(scope: str) -> tuple[str, str]:
    return SCOPE_LABELS.get(scope, (scope, ""))