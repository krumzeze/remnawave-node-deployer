"""Тесты db.repo на реальном SQL (sqlite в памяти через aiosqlite).

Боевой движок — postgres, но запросы те же: проверяем, что create_node_record
заводит ноду в queued, get_or_create_panel не плодит дубли, а record_status
меняет Node.state и добавляет строку Task. Postgres-специфики в репозитории нет.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from db import repo
from db.models import Base, Node
from db.models import Task as TaskRow


@pytest_asyncio.fixture
async def sm():
    """Чистая БД на каждый тест: sqlite в памяти + созданные таблицы."""
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest.mark.asyncio
async def test_create_node_record_starts_queued(sm):
    panel_id = await repo.get_or_create_panel(
        sm, owner_tg_id=1, url="https://p", token_vault_path="panels/1/token"
    )
    node_id = await repo.create_node_record(sm, panel_id=panel_id, ip="1.2.3.4")

    async with sm() as session:
        node = await session.get(Node, node_id)
        assert node.state == "queued"
        assert node.ip == "1.2.3.4"
        assert node.panel_id == panel_id


@pytest.mark.asyncio
async def test_get_or_create_panel_is_idempotent(sm):
    a = await repo.get_or_create_panel(
        sm, owner_tg_id=1, url="https://p", token_vault_path="t"
    )
    b = await repo.get_or_create_panel(
        sm, owner_tg_id=1, url="https://p", token_vault_path="t"
    )
    assert a == b


@pytest.mark.asyncio
async def test_get_saved_panel_returns_none_when_absent(sm):
    assert await repo.get_saved_panel(sm, owner_tg_id=42) is None


@pytest.mark.asyncio
async def test_get_saved_panel_returns_latest_for_owner(sm):
    await repo.get_or_create_panel(
        sm, owner_tg_id=1, url="https://old", token_vault_path="panels/1/token"
    )
    await repo.get_or_create_panel(
        sm, owner_tg_id=1, url="https://new", token_vault_path="panels/1/token"
    )
    # Чужая панель в выборку не попадает.
    await repo.get_or_create_panel(
        sm, owner_tg_id=2, url="https://other", token_vault_path="panels/2/token"
    )

    panel = await repo.get_saved_panel(sm, owner_tg_id=1)
    assert panel is not None
    assert panel.url == "https://new"


@pytest.mark.asyncio
async def test_record_status_updates_node_and_adds_task(sm):
    panel_id = await repo.get_or_create_panel(
        sm, owner_tg_id=1, url="https://p", token_vault_path="t"
    )
    node_id = await repo.create_node_record(sm, panel_id=panel_id, ip="1.2.3.4")

    await repo.record_status(sm, node_id, "bootstrapping", "Подключаюсь")
    await repo.record_status(sm, node_id, "online", "Готово")

    async with sm() as session:
        node = await session.get(Node, node_id)
        assert node.state == "online"
        tasks = (
            await session.scalars(
                select(TaskRow).where(TaskRow.node_id == node_id)
            )
        ).all()
        assert [t.state for t in tasks] == ["bootstrapping", "online"]


@pytest.mark.asyncio
async def test_record_status_missing_node_is_noop(sm):
    # Нет такой ноды — не бросаем и ничего не пишем.
    await repo.record_status(sm, 999, "online", "x")
    async with sm() as session:
        tasks = (await session.scalars(select(TaskRow))).all()
        assert tasks == []
