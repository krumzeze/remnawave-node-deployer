"""Регистрация пользователей: открытый доступ, тенант заводится при первом контакте.

Раньше здесь был белый список владельцев (single-tenant). Теперь бот публичный
(ADR 0014): любой, кто написал, становится тенантом с free-тарифом. Middleware
на каждом апдейте гарантирует строку User и прокидывает её в хендлеры (ключ
`user` в data) — так им доступны премиум-статус и признак админа без повторного
запроса к БД.

Логика вынесена в инъектируемые швы (upsert-функция, набор админов), чтобы
покрыть тестом без Telegram и без живой БД.
"""
from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable

from aiogram import BaseMiddleware
from aiogram.types import TelegramObject

logger = logging.getLogger(__name__)


class RegistrationMiddleware(BaseMiddleware):
    """Регистрирует отправителя и кладёт его User в data['user'].

    upsert(tg_id, is_admin) -> User: заводит или возвращает пользователя.
    admin_ids() -> set[int]: кто из отправителей считается админом.

    Апдейты без from_user (служебные) пропускаем как есть — регистрировать
    некого, пользовательских данных они не трогают.
    """

    def __init__(
        self,
        upsert: Callable[[int, bool], Awaitable[Any]],
        admin_ids: Callable[[], set[int]],
    ) -> None:
        self._upsert = upsert
        self._admin_ids = admin_ids

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        user = getattr(event, "from_user", None)
        user_id = getattr(user, "id", None)
        if user_id is None:
            return await handler(event, data)

        try:
            data["user"] = await self._upsert(user_id, user_id in self._admin_ids())
        except Exception:  # noqa: BLE001 — сбой регистрации не должен ронять апдейт
            logger.exception("registration: не удалось завести пользователя %s", user_id)
        return await handler(event, data)
