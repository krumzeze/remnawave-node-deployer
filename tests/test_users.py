"""Тесты пользователей, подписки и лимитов (db.repo, ADR 0014)."""
from __future__ import annotations

import datetime as dt

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from db import repo
from db.models import Base


@pytest_asyncio.fixture
async def sm():
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest.mark.asyncio
async def test_upsert_creates_then_returns_same(sm):
    u1 = await repo.upsert_user(sm, 111)
    u2 = await repo.upsert_user(sm, 111)
    assert u1.tg_id == u2.tg_id == 111
    assert u1.premium_until is None


@pytest.mark.asyncio
async def test_upsert_promotes_to_admin_but_never_demotes(sm):
    await repo.upsert_user(sm, 1, is_admin=True)
    assert (await repo.get_user(sm, 1)).is_admin is True
    # Повторный вход без is_admin не сбрасывает админа.
    await repo.upsert_user(sm, 1, is_admin=False)
    assert (await repo.get_user(sm, 1)).is_admin is True


def test_is_premium_none_and_expired():
    assert repo.is_premium(None) is False
    now = dt.datetime(2026, 1, 1)
    past = type("U", (), {"premium_until": dt.datetime(2025, 1, 1)})()
    future = type("U", (), {"premium_until": dt.datetime(2027, 1, 1)})()
    assert repo.is_premium(past, now=now) is False
    assert repo.is_premium(future, now=now) is True


@pytest.mark.asyncio
async def test_extend_premium_from_now_then_stacks(sm):
    await repo.upsert_user(sm, 5)
    first = await repo.extend_premium(sm, 5, 30)
    # Второе продление прибавляется к активной подписке, а не от «сейчас».
    second = await repo.extend_premium(sm, 5, 30)
    assert (second - first).days == 30


@pytest.mark.asyncio
async def test_extend_premium_creates_user_if_missing(sm):
    until = await repo.extend_premium(sm, 42, 30)
    assert until > dt.datetime.utcnow()
    assert await repo.get_user(sm, 42) is not None


@pytest.mark.asyncio
async def test_count_owner_nodes(sm):
    p1 = await repo.get_or_create_panel(sm, owner_tg_id=1, url="https://a", token_vault_path="t")
    p2 = await repo.get_or_create_panel(sm, owner_tg_id=2, url="https://b", token_vault_path="t")
    await repo.create_node_record(sm, panel_id=p1, ip="1.1.1.1")
    await repo.create_node_record(sm, panel_id=p1, ip="1.1.1.2")
    await repo.create_node_record(sm, panel_id=p2, ip="2.2.2.2")

    assert await repo.count_owner_nodes(sm, 1) == 2
    assert await repo.count_owner_nodes(sm, 2) == 1
    assert await repo.count_owner_nodes(sm, 999) == 0
