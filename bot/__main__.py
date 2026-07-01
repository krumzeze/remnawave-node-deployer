"""Точка входа бота: python -m bot.

При старте создаём таблицы (init_models) — иначе на чистой базе первое же
обращение упало бы. FSM-состояние мастера держим в Redis, а не в памяти, чтобы
незавершённый диалог переживал перезапуск бота; саму базу нод и привязанную
панель хранят Postgres и Vault. Для FSM берём отдельную базу Redis (db=1), чтобы
не пересекаться с очередью arq (db=0).
"""
import asyncio
import logging

from aiogram import Bot, Dispatcher
from aiogram.fsm.storage.redis import RedisStorage
from aiogram.types import BotCommand

from bot.access import RegistrationMiddleware
from bot.handlers import router
from config import settings
from db import get_sessionmaker, init_models
from db.repo import upsert_user


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    await init_models()

    storage = RedisStorage.from_url(
        f"redis://{settings.redis_host}:{settings.redis_port}/1"
    )
    bot = Bot(token=settings.bot_token)
    dp = Dispatcher(storage=storage)

    # Открытая регистрация (ADR 0014): каждый отправитель заводится как тенант
    # с free-тарифом, его User прокидывается в хендлеры. Вешаем внешним
    # middleware и на сообщения, и на callback'и. Список админов читаем лениво
    # из settings — он один на процесс.
    sm = get_sessionmaker()

    async def _upsert(tg_id: int, is_admin: bool):
        return await upsert_user(sm, tg_id, is_admin=is_admin)

    registration = RegistrationMiddleware(_upsert, lambda: settings.admin_telegram_ids)
    dp.message.outer_middleware(registration)
    dp.callback_query.outer_middleware(registration)

    dp.include_router(router)

    await bot.set_my_commands([
        BotCommand(command="menu", description="Открыть меню"),
        BotCommand(command="start", description="Открыть меню"),
    ])
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
