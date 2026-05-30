"""Точка входа бота: python -m bot."""
import asyncio
import logging

from aiogram import Bot, Dispatcher

from config import settings
from bot.handlers import router


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    bot = Bot(token=settings.bot_token)
    dp = Dispatcher()
    dp.include_router(router)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
