"""Async-движок и фабрика сессий SQLAlchemy.

Движок создаётся лениво (а не на импорте пакета): драйвер asyncpg тянется
только при первом реальном обращении к БД. Так модули, которым БД не нужна
(и тесты на фейках/sqlite), импортируют `db` без установленного asyncpg и без
попытки соединения.

`get_sessionmaker()` отдаёт боевую фабрику на postgres из настроек. Код, который
надо тестировать (`db.repo`), фабрику принимает параметром — в тестах туда
подставляется sqlite. Сам пакет ни к какой конкретной БД не привязан.
"""
from __future__ import annotations

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    async_sessionmaker,
    create_async_engine,
)

from config import settings

from db.models import Base

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker | None = None


def get_engine() -> AsyncEngine:
    """Боевой движок на postgres из настроек. Создаётся один раз, лениво."""
    global _engine
    if _engine is None:
        _engine = create_async_engine(settings.postgres_dsn, pool_pre_ping=True)
    return _engine


def get_sessionmaker() -> async_sessionmaker:
    """Фабрика сессий поверх боевого движка."""
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(get_engine(), expire_on_commit=False)
    return _sessionmaker


async def init_models() -> None:
    """Создать таблицы, если их ещё нет.

    Для MVP этого достаточно; миграции (alembic уже в зависимостях) подключим,
    когда схема начнёт меняться на работающей базе.
    """
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
