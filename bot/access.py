"""Барьер доступа к боту: пускаем только владельцев из белого списка.

Проверка вынесена в чистую функцию access_decision, чтобы покрыть тестом без
поднятия Telegram. Класс WhitelistMiddleware вешается внешним (outer) middleware
на диспетчер и закрывает и сообщения, и callback'и до того, как апдейт дойдёт до
хендлеров.
"""
from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Awaitable, Callable

from aiogram import BaseMiddleware
from aiogram.types import CallbackQuery, TelegramObject

logger = logging.getLogger(__name__)

# Текст для незарегистрированного бота и для чужих. Чужим отвечаем явным отказом
# (а не молчим): так понятнее, что бот работает, но доступ закрыт, и не плодим
# догадок «бот сломался».
NOT_CONFIGURED_TEXT = "Бот не настроен: задайте ALLOWED_TELEGRAM_IDS"
FORBIDDEN_TEXT = "Доступ запрещён"


class AccessDecision(Enum):
    ALLOW = "allow"              # пользователь в списке — пропускаем
    NOT_CONFIGURED = "denied"    # список пуст — бот ненастроен
    FORBIDDEN = "forbidden"      # пользователь не в списке


def access_decision(user_id: int | None, allowed_ids: set[int]) -> AccessDecision:
    """Решение по доступу для апдейта от user_id при заданном белом списке.

    Пустой список = бот ненастроен (закрыт для всех). Иначе пускаем, только если
    user_id в списке. Отсутствие user_id (служебные апдейты без отправителя)
    трактуем как отказ — пускать аноним нельзя."""
    if not allowed_ids:
        return AccessDecision.NOT_CONFIGURED
    if user_id is not None and user_id in allowed_ids:
        return AccessDecision.ALLOW
    return AccessDecision.FORBIDDEN


async def _reply(event: TelegramObject, text: str) -> None:
    """Короткий ответ пользователю на отклонённый апдейт (сообщение/коллбек).

    У callback'а ответ — всплывающий алерт (show_alert), у сообщения — обычный
    текст. Тип определяем по наличию метода answer, чтобы не зависеть от точных
    классов aiogram (это же делает фейк в тестах)."""
    answer = getattr(event, "answer", None)
    if answer is None:
        return
    if isinstance(event, CallbackQuery):
        await answer(text, show_alert=True)
    else:
        await answer(text)


class WhitelistMiddleware(BaseMiddleware):
    """Пропускает апдейт дальше только для владельцев из белого списка.

    Список ID берётся лениво из колбэка get_allowed_ids — так настройку можно
    перечитать без пересборки middleware и легко подменить в тесте.
    """

    def __init__(self, get_allowed_ids: Callable[[], set[int]]) -> None:
        self._get_allowed_ids = get_allowed_ids

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        user = getattr(event, "from_user", None)
        user_id = getattr(user, "id", None)
        decision = access_decision(user_id, self._get_allowed_ids())

        if decision is AccessDecision.ALLOW:
            return await handler(event, data)

        if decision is AccessDecision.NOT_CONFIGURED:
            logger.warning(
                "апдейт отклонён: ALLOWED_TELEGRAM_IDS не задан (user_id=%s)",
                user_id,
            )
            await _reply(event, NOT_CONFIGURED_TEXT)
        else:
            logger.info("апдейт отклонён: user_id=%s не в белом списке", user_id)
            await _reply(event, FORBIDDEN_TEXT)
        return None
