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
async def test_import_panel_node_creates_then_dedups(sm):
    panel_id = await repo.get_or_create_panel(
        sm, owner_tg_id=1, url="https://p", token_vault_path="t"
    )
    # Первый синк: ноды нет — создаём, без SSH-ключа, со статусом панели.
    created = await repo.import_panel_node(
        sm, panel_id=panel_id, remnawave_uuid="rw-1", ip="1.2.3.4", state="online"
    )
    assert created is True
    # Повторный синк той же ноды — дубль не создаём.
    again = await repo.import_panel_node(
        sm, panel_id=panel_id, remnawave_uuid="rw-1", ip="1.2.3.4", state="offline"
    )
    assert again is False

    nodes = await repo.list_nodes_for_owner(sm, owner_tg_id=1)
    assert len(nodes) == 1
    node = nodes[0]
    assert node.remnawave_uuid == "rw-1"
    assert node.state == "online"           # повторный синк не перетёр статус
    assert node.ssh_key_vault_path is None  # чужая нода — ключа нет


@pytest.mark.asyncio
async def test_set_node_state_by_uuid_updates_existing(sm):
    # Синк освежает статус уже импортированной ноды по (panel_id, uuid).
    panel_id = await repo.get_or_create_panel(
        sm, owner_tg_id=1, url="https://p", token_vault_path="t"
    )
    await repo.import_panel_node(
        sm, panel_id=panel_id, remnawave_uuid="rw-1", ip="1.2.3.4", state="online"
    )

    changed = await repo.set_node_state_by_uuid(
        sm, panel_id=panel_id, remnawave_uuid="rw-1", state="offline"
    )
    assert changed is True
    nodes = await repo.list_nodes_for_owner(sm, owner_tg_id=1)
    assert nodes[0].state == "offline"

    # Тот же статус — не пишем, возвращаем False.
    again = await repo.set_node_state_by_uuid(
        sm, panel_id=panel_id, remnawave_uuid="rw-1", state="offline"
    )
    assert again is False

    # Неизвестный uuid — тоже False, без ошибки.
    missing = await repo.set_node_state_by_uuid(
        sm, panel_id=panel_id, remnawave_uuid="nope", state="online"
    )
    assert missing is False


@pytest.mark.asyncio
async def test_import_panel_node_skips_bot_node_with_same_uuid(sm):
    # Ботовая нода с проставленным uuid не должна задваиваться при синке.
    panel_id = await repo.get_or_create_panel(
        sm, owner_tg_id=1, url="https://p", token_vault_path="t"
    )
    node_id = await repo.create_node_record(sm, panel_id=panel_id, ip="1.1.1.1")
    await repo.set_node_fields(sm, node_id, remnawave_uuid="rw-bot")

    created = await repo.import_panel_node(
        sm, panel_id=panel_id, remnawave_uuid="rw-bot", ip="1.1.1.1", state="online"
    )
    assert created is False
    nodes = await repo.list_nodes_for_owner(sm, owner_tg_id=1)
    assert len(nodes) == 1


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


@pytest.mark.asyncio
async def test_list_nodes_for_owner_only_owner_newest_first(sm):
    p1 = await repo.get_or_create_panel(sm, owner_tg_id=1, url="https://a", token_vault_path="t")
    p2 = await repo.get_or_create_panel(sm, owner_tg_id=2, url="https://b", token_vault_path="t")
    n1 = await repo.create_node_record(sm, panel_id=p1, ip="1.1.1.1")
    n2 = await repo.create_node_record(sm, panel_id=p1, ip="2.2.2.2")
    await repo.create_node_record(sm, panel_id=p2, ip="9.9.9.9")  # чужая
    nodes = await repo.list_nodes_for_owner(sm, owner_tg_id=1)
    ids = [n.id for n in nodes]
    assert set(ids) == {n1, n2}
    assert ids[0] == n2  # свежая сверху


@pytest.mark.asyncio
async def test_get_node_for_owner_checks_ownership(sm):
    p1 = await repo.get_or_create_panel(sm, owner_tg_id=1, url="https://a", token_vault_path="t")
    node_id = await repo.create_node_record(sm, panel_id=p1, ip="1.1.1.1")
    assert (await repo.get_node_for_owner(sm, node_id, 1)).ip == "1.1.1.1"
    assert await repo.get_node_for_owner(sm, node_id, 2) is None      # чужой
    assert await repo.get_node_for_owner(sm, 999, 1) is None          # нет такой


@pytest.mark.asyncio
async def test_delete_node_removes_node_and_history(sm):
    p1 = await repo.get_or_create_panel(sm, owner_tg_id=1, url="https://a", token_vault_path="t")
    node_id = await repo.create_node_record(sm, panel_id=p1, ip="1.1.1.1")
    await repo.record_status(sm, node_id, "online", "ok")
    assert await repo.delete_node(sm, node_id, 2) is False            # чужую нельзя
    assert await repo.delete_node(sm, node_id, 1) is True
    assert await repo.get_node_for_owner(sm, node_id, 1) is None
    async with sm() as session:
        tasks = (await session.scalars(select(TaskRow).where(TaskRow.node_id == node_id))).all()
        assert tasks == []
    assert await repo.delete_node(sm, node_id, 1) is False            # повторно — нечего
