"""Веб-дашборд: статус нод и аудит (наряду с Telegram).

Авторизации нет: идентификация по owner_tg_id — MVP-заглушка, не замена
полноценной аутентификации. Достаточно для single-tenant (ADR 0003).
"""
from __future__ import annotations

from fastapi import Depends, FastAPI
from sqlalchemy.ext.asyncio import async_sessionmaker

from db import repo

app = FastAPI(title="remnawave-node-deployer")


def _get_session_factory() -> async_sessionmaker:
    """Боевая фабрика сессий. Переопределяется в тестах через dependency_overrides."""
    from db import get_sessionmaker
    return get_sessionmaker()


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/nodes")
async def list_nodes(
    owner_tg_id: int,
    sf: async_sessionmaker = Depends(_get_session_factory),
) -> list[dict]:
    """Список нод владельца со статусами.

    owner_tg_id — query-параметр. Фильтрация по нему достаточна для
    single-tenant MVP; не является заменой аутентификации.
    """
    nodes = await repo.list_nodes_for_owner(sf, owner_tg_id)
    return [
        {
            "id": n.id,
            "ip": n.ip,
            "state": n.state,
            "remnawave_uuid": n.remnawave_uuid,
            "created_at": n.created_at.isoformat() if n.created_at else None,
        }
        for n in nodes
    ]


@app.get("/nodes/{node_id}/audit")
async def node_audit(
    node_id: int,
    owner_tg_id: int,
    sf: async_sessionmaker = Depends(_get_session_factory),
) -> list[dict]:
    """История переходов состояний ноды.

    Если нода не принадлежит владельцу — возвращаем пустой список, не 404:
    не раскрываем факт существования чужой ноды.
    """
    return await repo.list_node_audit(sf, node_id, owner_tg_id)
