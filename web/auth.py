"""Подписанные токены доступа к дашборду (ADR 0014).

Веб больше не доверяет сырому owner_tg_id из запроса (любой мог перебрать чужой
id). Вместо этого бот выдаёт пользователю персональную ссылку с токеном, в
котором tg_id и срок годности подписаны HMAC-SHA256 на общем секрете
(WEB_SECRET). Веб проверяет подпись и срок и только тогда доверяет tg_id.

Формат токена: base64url("<tg_id>:<exp>") + "." + base64url(hmac). Компактно,
без внешних зависимостей (стандартная библиотека).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import time

# Срок жизни токена по умолчанию — сутки. Ссылку легко перевыпустить в боте,
# поэтому короткий срок ограничивает ущерб от утечки ссылки.
DEFAULT_TTL_SEC = 24 * 3600


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _sign(payload: str, secret: str) -> str:
    mac = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest()
    return _b64(mac)


def make_token(tg_id: int, secret: str, *, ttl_sec: int = DEFAULT_TTL_SEC,
               now: int | None = None) -> str:
    """Выдать подписанный токен доступа для tg_id со сроком ttl_sec."""
    exp = (now if now is not None else int(time.time())) + ttl_sec
    payload = f"{tg_id}:{exp}"
    body = _b64(payload.encode())
    return f"{body}.{_sign(body, secret)}"


def verify_token(token: str, secret: str, *, now: int | None = None) -> int | None:
    """Проверить токен и вернуть tg_id, либо None (подделан/просрочен/битый).

    Подпись сверяем в постоянном времени (hmac.compare_digest). Секрет пустой
    или токен любой формы, не прошедшей проверку, → None: вызывающий отдаёт 401.
    """
    if not secret or not token or "." not in token:
        return None
    body, sig = token.rsplit(".", 1)
    if not hmac.compare_digest(sig, _sign(body, secret)):
        return None
    try:
        payload = _unb64(body).decode()
        tg_id_str, exp_str = payload.split(":", 1)
        tg_id, exp = int(tg_id_str), int(exp_str)
    except (ValueError, UnicodeDecodeError):
        return None
    if exp < (now if now is not None else int(time.time())):
        return None
    return tg_id
