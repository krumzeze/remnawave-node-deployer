"""Тест удочерения импортированной ноды (handlers._adopt_node, ADR 0013).

Проверяем склейку: bootstrap по паролю ставит ключ, ключ уходит в Vault по
nodes/{id}/ssh, путь пишется в БД (ssh_key_vault_path). bootstrap и Vault
подменяем фейками, запись в БД — реальная (sqlite), как в test_repo. Так нода
из импортированной (без SSH) становится полноценной."""
from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import db
from bot import handlers
from db import repo
from db.models import Base, Node
from orchestrator import ssh_bootstrap
from secretstore import vault as vault_mod


@pytest_asyncio.fixture
async def sm():
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


class FakeVault:
    """Записывает put в общий словарь — проверяем путь и содержимое."""

    store: dict = {}

    def put(self, path: str, data: dict) -> str:
        FakeVault.store[path] = data
        return path


@pytest.mark.asyncio
async def test_adopt_installs_key_and_persists_path(sm, monkeypatch):
    FakeVault.store = {}
    # bootstrap по паролю «удался» и вернул приватный ключ.
    async def fake_bootstrap(ip, login, password, **kw):
        return ssh_bootstrap.BootstrapResult(ok=True, private_key="PRIV", detail="ok")

    monkeypatch.setattr(ssh_bootstrap, "bootstrap_password", fake_bootstrap)
    monkeypatch.setattr(vault_mod, "VaultStore", FakeVault)
    monkeypatch.setattr(db, "get_sessionmaker", lambda: sm)

    # Импортированная нода: есть uuid, ssh_key_vault_path = NULL.
    panel_id = await repo.get_or_create_panel(
        sm, owner_tg_id=1, url="https://p", token_vault_path="panels/1/token"
    )
    ok = await repo.import_panel_node(
        sm, panel_id=panel_id, remnawave_uuid="rw-1", ip="1.2.3.4", state="online"
    )
    assert ok
    node = (await repo.list_nodes_for_owner(sm, 1))[0]
    assert node.ssh_key_vault_path is None

    ok, detail = await handlers._adopt_node(node.id, "1.2.3.4", "root", "pw")
    assert ok, detail

    # Ключ и логин ушли в Vault по каноничному пути, путь записан в БД.
    assert FakeVault.store == {
        f"nodes/{node.id}/ssh": {"private_key": "PRIV", "login": "root"}
    }
    async with sm() as session:
        refreshed = await session.get(Node, node.id)
        assert refreshed.ssh_key_vault_path == f"nodes/{node.id}/ssh"


@pytest.mark.asyncio
async def test_adopt_reports_failure_and_keeps_node_untouched(sm, monkeypatch):
    FakeVault.store = {}
    async def fake_bootstrap(ip, login, password, **kw):
        return ssh_bootstrap.BootstrapResult(ok=False, detail="вход не удался")

    monkeypatch.setattr(ssh_bootstrap, "bootstrap_password", fake_bootstrap)
    monkeypatch.setattr(vault_mod, "VaultStore", FakeVault)
    monkeypatch.setattr(db, "get_sessionmaker", lambda: sm)

    panel_id = await repo.get_or_create_panel(
        sm, owner_tg_id=1, url="https://p", token_vault_path="panels/1/token"
    )
    await repo.import_panel_node(
        sm, panel_id=panel_id, remnawave_uuid="rw-1", ip="1.2.3.4", state="offline"
    )
    node = (await repo.list_nodes_for_owner(sm, 1))[0]

    ok, detail = await handlers._adopt_node(node.id, "1.2.3.4", "root", "pw")
    assert ok is False
    assert "вход не удался" in detail
    # Ничего не сохранили: ни в Vault, ни в БД.
    assert FakeVault.store == {}
    async with sm() as session:
        refreshed = await session.get(Node, node.id)
        assert refreshed.ssh_key_vault_path is None
