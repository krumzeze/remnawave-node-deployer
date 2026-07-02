"""Тесты веб-эндпоинтов через httpx + ASGITransport.

Тестовая фабрика сессий — sqlite в памяти (то же, что test_repo.py).
Боевая зависимость _get_session_factory переопределяется через
app.dependency_overrides, чтобы не пытаться соединиться с postgres.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
import httpx
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from db import repo
from db.models import Base
from web.app import app, _get_session_factory


@pytest_asyncio.fixture
async def sm():
    """Чистая sqlite БД на каждый тест."""
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def client(sm):
    """AsyncClient с подменённой session_factory и ASGI-транспортом."""
    app.dependency_overrides[_get_session_factory] = lambda: sm
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# /nodes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_nodes_returns_owner_nodes(client, sm):
    panel_id = await repo.get_or_create_panel(
        sm, owner_tg_id=1, url="https://p", token_vault_path="t"
    )
    await repo.create_node_record(sm, panel_id=panel_id, ip="1.2.3.4")
    await repo.create_node_record(sm, panel_id=panel_id, ip="5.6.7.8")

    resp = await client.get("/nodes", params={"owner_tg_id": 1})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    ips = {n["ip"] for n in data}
    assert ips == {"1.2.3.4", "5.6.7.8"}


@pytest.mark.asyncio
async def test_nodes_does_not_return_foreign_nodes(client, sm):
    p1 = await repo.get_or_create_panel(
        sm, owner_tg_id=1, url="https://a", token_vault_path="t"
    )
    p2 = await repo.get_or_create_panel(
        sm, owner_tg_id=2, url="https://b", token_vault_path="t"
    )
    await repo.create_node_record(sm, panel_id=p1, ip="1.1.1.1")
    await repo.create_node_record(sm, panel_id=p2, ip="9.9.9.9")  # чужая

    resp = await client.get("/nodes", params={"owner_tg_id": 1})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["ip"] == "1.1.1.1"


@pytest.mark.asyncio
async def test_nodes_empty_for_unknown_owner(client, sm):
    resp = await client.get("/nodes", params={"owner_tg_id": 999})
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_nodes_response_contains_expected_fields(client, sm):
    panel_id = await repo.get_or_create_panel(
        sm, owner_tg_id=1, url="https://p", token_vault_path="t"
    )
    await repo.create_node_record(sm, panel_id=panel_id, ip="1.2.3.4")

    resp = await client.get("/nodes", params={"owner_tg_id": 1})
    node = resp.json()[0]
    for field in ("id", "ip", "state", "remnawave_uuid", "created_at"):
        assert field in node, f"поле {field!r} отсутствует в ответе"
    assert node["state"] == "queued"


# ---------------------------------------------------------------------------
# /nodes/{node_id}/audit
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_audit_returns_history_for_owner(client, sm):
    panel_id = await repo.get_or_create_panel(
        sm, owner_tg_id=1, url="https://p", token_vault_path="t"
    )
    node_id = await repo.create_node_record(sm, panel_id=panel_id, ip="1.2.3.4")
    await repo.record_status(sm, node_id, "bootstrapping", "Подключаюсь")
    await repo.record_status(sm, node_id, "online", "Готово")

    resp = await client.get(f"/nodes/{node_id}/audit", params={"owner_tg_id": 1})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    assert data[0]["state"] == "bootstrapping"
    assert data[1]["state"] == "online"


@pytest.mark.asyncio
async def test_audit_returns_empty_for_foreign_node(client, sm):
    p1 = await repo.get_or_create_panel(
        sm, owner_tg_id=1, url="https://a", token_vault_path="t"
    )
    node_id = await repo.create_node_record(sm, panel_id=p1, ip="1.1.1.1")
    await repo.record_status(sm, node_id, "online", "ok")

    # Запрос от другого владельца — пустой список, не ошибка.
    resp = await client.get(f"/nodes/{node_id}/audit", params={"owner_tg_id": 2})
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_audit_empty_for_nonexistent_node(client, sm):
    resp = await client.get("/nodes/9999/audit", params={"owner_tg_id": 1})
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_audit_response_contains_expected_fields(client, sm):
    panel_id = await repo.get_or_create_panel(
        sm, owner_tg_id=1, url="https://p", token_vault_path="t"
    )
    node_id = await repo.create_node_record(sm, panel_id=panel_id, ip="1.2.3.4")
    await repo.record_status(sm, node_id, "bootstrapping", "Шаг")

    resp = await client.get(f"/nodes/{node_id}/audit", params={"owner_tg_id": 1})
    entry = resp.json()[0]
    for field in ("id", "state", "detail", "updated_at"):
        assert field in entry, f"поле {field!r} отсутствует в ответе аудита"
