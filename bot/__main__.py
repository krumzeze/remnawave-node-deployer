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

from bot.access import WhitelistMiddleware
from bot.handlers import router
from config import settings
from db import init_models


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    await init_models()

    storage = RedisStorage.from_url(
        f"redis://{settings.redis_host}:{settings.redis_port}/1"
    )
    bot = Bot(token=settings.bot_token)
    dp = Dispatcher(storage=storage)

    # Барьер доступа: пускаем только владельцев из ALLOWED_TELEGRAM_IDS. Вешаем
    # внешним middleware и на сообщения, и на callback'и, чтобы отсечь чужих до
    # хендлеров. Список читаем лениво из settings — он один на процесс.
    access = WhitelistMiddleware(lambda: settings.allowed_telegram_ids)
    dp.message.outer_middleware(access)
    dp.callback_query.outer_middleware(access)

    dp.include_router(router)

    await bot.set_my_commands([
        BotCommand(command="menu", description="Открыть меню"),
        BotCommand(command="start", description="Открыть меню"),
    ])
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
