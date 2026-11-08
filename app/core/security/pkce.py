from __future__ import annotations
import base64
import hashlib
import hmac

VERIFIER_MIN_LEN = 43
VERIFIER_MAX_LEN = 128

def _b64url_no_pad(data: bytes) -> str:
    """Кодирует байты в Base64 URL-safe без завершающего padding.

    Параметры:
        data (bytes): данные выполнения GraphQL-запроса.

    Возвращает:
        Результат выполнения операции (тип: str).
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def compute_challenge(code_verifier: str, method: str = "S256") -> str:
    """Вычисляет PKCE challenge для указанного verifier и метода.

    Параметры:
        code_verifier (str): PKCE code verifier, полученный от клиента.
        method (str): метод кодирования или проверки.

    Возвращает:
        Результат выполнения операции (тип: str).
    """
    if method == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        return _b64url_no_pad(digest)
    if method == "plain":
        return code_verifier
    raise ValueError(f"Unsupported code_challenge_method: {method!r}")

def verify_pkce(
        code_verifier: str | None,
        code_challenge: str | None,
        method: str | None,
) -> bool:
    """Проверяет соответствие PKCE verifier сохранённому challenge.

    Параметры:
        code_verifier (str | None): PKCE code verifier, полученный от клиента.
        code_challenge (str | None): сохранённый PKCE challenge.
        method (str | None): метод кодирования или проверки.

    Возвращает:
        Результат выполнения операции (тип: bool).
    """
    if not code_verifier or not code_challenge:
        return False

    if not isinstance(code_verifier, str):
        return False

    if not (VERIFIER_MIN_LEN <= len(code_verifier) <= VERIFIER_MAX_LEN):
        return False

    method = method or "S256"

    try:
        expected = compute_challenge(code_verifier, method)
    except ValueError:
        return False

    return hmac.compare_digest(expected, code_challenge)