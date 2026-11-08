from __future__ import annotations
from typing import NoReturn
from urllib.parse import urlencode
from fastapi import HTTPException
from fastapi.responses import RedirectResponse

INVALID_REQUEST = "invalid_request"
INVALID_CLIENT = "invalid_client"
INVALID_GRANT = "invalid_grant"
UNAUTHORIZED_CLIENT = "unauthorized_client"
UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
INVALID_SCOPE = "invalid_scope"
ACCESS_DENIED = "access_denied"
UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type"
SERVER_ERROR = "server_error"

def oauth_json_error(
        error: str,
        description: str | None = None,
        status_code: int = 400,
) -> NoReturn:
    """Формирует OAuth-ошибку в JSON-ответе с указанным HTTP-статусом.

    Параметры:
        error (str): код OAuth-ошибки.
        description (str | None): дополнительное описание ошибки.
        status_code (int): HTTP-код статуса ответа.

    Возвращает:
        Обычное значение не возвращается; функция завершается исключением (тип: NoReturn).
    """
    if error == INVALID_CLIENT:
        status_code = 401

    body = {"error": error}
    if description:
        body["error_description"] = description

    raise HTTPException(status_code=status_code, detail=body)

def oauth_redirect_error(
        redirect_uri: str,
        error: str, 
        state: str | None = None,
        description: str | None = None,
) -> RedirectResponse:
    """Формирует перенаправление с параметрами OAuth-ошибки и состоянием запроса.

    Параметры:
        redirect_uri (str): адрес возврата OAuth-клиента.
        error (str): код OAuth-ошибки.
        state (str | None): значение state для связывания запроса и ответа OAuth.
        description (str | None): дополнительное описание ошибки.

    Возвращает:
        Результат выполнения операции (тип: RedirectResponse).
    """
    params = {"error": error}
    if description:
        params["error_description"] = description
    if state:
        params["state"] = state

    location = f"{redirect_uri}?{urlencode(params)}"
    return RedirectResponse(url=location, status_code=302)