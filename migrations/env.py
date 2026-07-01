"""Окружение Alembic (async).

URL БД и метаданные берём из приложения, а не из alembic.ini: DSN — из
config.settings (тот же .env), target_metadata — db.models.Base. Движок
асинхронный (asyncpg), поэтому online-режим гоняем через asyncio.

До этой ревизии схему создавал только create_all (init_models). Миграции
уживаются с ним: первая ревизия идемпотентна (проверяет наличие через
inspector), поэтому порядок «create_all и alembic» не важен.
"""
from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from config import settings
from db.models import Base

config = context.config

# DSN приложения (asyncpg). Прокидываем в конфиг alembic для async-движка.
config.set_main_option("sqlalchemy.url", settings.postgres_dsn)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Offline: генерируем SQL без подключения к БД."""
    context.configure(
        url=settings.postgres_dsn,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Online: подключаемся асинхронным движком и накатываем ревизии."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(_do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
