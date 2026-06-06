"""Операции с БД для бота и воркера.

Две вещи нужны вертикальному срезу:
  - `create_node_record` — при постановке задачи бот заводит Panel (если её ещё
    нет) и Node в состоянии queued, отдаёт node_id; дальше воркер обновляет эту
    же строку.
  - `record_status` — воркеров `report` пишет сюда: меняет Node.state и
    добавляет строку Task с деталью (история переходов задачи).

Секретов тут нет: токен панели и ключи лежат в Vault, в БД — только путь
(token_vault_path / ssh_key_vault_path). См. db/models.py.

Все функции принимают `session_factory` (async_sessionmaker) параметром, а не
берут глобальную: это шов для тестов (sqlite вместо postgres) и явная граница
владения соединением.
"""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from db.models import Node, Panel
from db.models import Task as TaskRow

log = logging.getLogger(__name__)

# Длина detail в модели Task — 1024. Режем заранее, чтобы длинная ошибка
# ansible/SDK не уронила вставку.
_DETAIL_MAX = 1024


async def get_or_create_panel(
    session_factory: async_sessionmaker,
    *,
    owner_tg_id: int,
    url: str,
    token_vault_path: str,
) -> int:
    """Вернуть id панели этого владельца по URL, создав её при отсутствии.

    Single-tenant (ADR 0003): один владелец, панель обычно одна. Переиспользуем
    запись по (owner_tg_id, url), чтобы не плодить дубли при добавлении нескольких
    нод к одной панели.
    """
    async with session_factory() as session:
        existing = await session.scalar(
            select(Panel).where(
                Panel.owner_tg_id == owner_tg_id, Panel.url == url
            )
        )
        if existing is not None:
            return existing.id
        panel = Panel(
            owner_tg_id=owner_tg_id, url=url, token_vault_path=token_vault_path
        )
        session.add(panel)
        await session.commit()
        await session.refresh(panel)
        return panel.id


async def get_saved_panel(
    session_factory: async_sessionmaker, owner_tg_id: int
) -> Panel | None:
    """Последняя сохранённая панель владельца, либо None.

    Нужна боту, чтобы не спрашивать URL/токен на каждом /add: single-tenant
    (ADR 0003), панель у владельца обычно одна. Берём самую свежую — на случай,
    если оператор сменил панель через /panel (добавится новая запись с тем же
    owner). Сам токен лежит в Vault по token_vault_path, тут только метаданные.
    """
    async with session_factory() as session:
        return await session.scalar(
            select(Panel)
            .where(Panel.owner_tg_id == owner_tg_id)
            .order_by(Panel.created_at.desc(), Panel.id.desc())
        )


async def create_node_record(
    session_factory: async_sessionmaker,
    *,
    panel_id: int,
    ip: str,
) -> int:
    """Завести Node в состоянии queued и вернуть её id."""
    async with session_factory() as session:
        node = Node(panel_id=panel_id, ip=ip, state="queued")
        session.add(node)
        await session.commit()
        await session.refresh(node)
        return node.id


async def record_status(
    session_factory: async_sessionmaker,
    node_id: int,
    state: str,
    detail: str,
) -> None:
    """Обновить Node.state и добавить строку Task с деталью перехода.

    Если ноды с таким id нет — просто логируем и выходим: история отдельной
    задачи не должна валить провижининг (FK на отсутствующую ноду не пишем).
    """
    async with session_factory() as session:
        node = await session.get(Node, node_id)
        if node is None:
            log.warning("record_status: нет ноды id=%s (state=%s)", node_id, state)
            return
        node.state = state
        session.add(TaskRow(node_id=node_id, state=state, detail=detail[:_DETAIL_MAX]))
        await session.commit()
