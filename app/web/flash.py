from __future__ import annotations
from fastapi import Request

def flash(request: Request, message: str, category: str = "info") -> None:
    """Добавляет временное сообщение в веб-сессию.

    Параметры:
        request (Request): HTTP-запрос, переданный веб-фреймворком.
        message (str): текст сообщения.
        category (str): категория flash-сообщения, используемая при его отображении..

    Возвращает:
        None (значение не возвращается).
    """
    messages = request.session.get("flash", [])
    messages.append({"category": category, "message": message})
    request.session["flash"] = messages

def pop_flashed_messages(request: Request) -> list[dict]:
    """Извлекает и удаляет из веб-сессии ожидающие flash-сообщения.

    Параметры:
        request (Request): HTTP-запрос, переданный веб-фреймворком.

    Возвращает:
        Результат выполнения операции (тип: list[dict]).
    """
    messages = request.session.get("flash", [])
    request.session["flash"] = []
    return messages